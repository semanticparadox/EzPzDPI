//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config is persisted in <dataDir>\config.json.
type Config struct {
	Strategy string    `json:"strategy,omitempty"`
	PickedAt time.Time `json:"picked_at,omitempty"`
	Result   string    `json:"result,omitempty"`
}

type App struct {
	dataDir    string
	cfg        Config
	payload    PayloadInfo
	strategies []Strategy
	lastEngine Engine

	mu        sync.Mutex
	trialCmd  *exec.Cmd
	trialDone <-chan error
	pending   *prevState // bypass to bring back if the user aborts
}

// prevState remembers how the bypass was running before an operation
// stopped it.
type prevState struct{ mode, key string }

func main() {
	initConsole(appName)
	auto := flag.Bool("auto", false, "подобрать стратегию и включить её службой")
	run := flag.Bool("run", false, "включить сохранённую стратегию службой")
	stop := flag.Bool("stop", false, "выключить обход")
	check := flag.Bool("check", false, "проверить, открываются ли YouTube и Discord")
	selftest := flag.Bool("selftest", false, "проверка сборки без прав администратора")
	dataDir := flag.String("datadir", "", "папка рабочих файлов")
	flag.Parse()

	if *selftest {
		os.Exit(runSelftest(*dataDir))
	}
	if *dataDir != "" {
		say("Параметр -datadir работает только вместе с -selftest.")
		os.Exit(2)
	}
	if !isAdmin() {
		if err := relaunchElevated(os.Args[1:]); err != nil {
			say(col(cRed, "Нужны права администратора: без них драйвер WinDivert не запустится."))
			say("Нажмите на %s.exe правой кнопкой и выберите «Запуск от имени администратора».", appName)
			pause()
			os.Exit(1)
		}
		return
	}

	a := &App{dataDir: defaultDataDir()}
	a.watchSignals()
	if err := a.init(); err != nil {
		say(col(cRed, "Ошибка запуска: %v"), err)
		pause()
		os.Exit(1)
	}
	switch {
	case *auto:
		a.autoPick(false, true)
	case *run:
		if s, ok := a.savedStrategy(); ok {
			a.enable(s, true)
		} else {
			say("Стратегия ещё не подобрана: запустите %s без параметров.", appName)
			os.Exit(1)
		}
	case *stop:
		a.stopAll()
		say("Обход выключен.")
	case *check:
		a.checkNow()
	default:
		a.menu()
	}
}

func (a *App) watchSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		a.killTrial()
		fmt.Println()
		a.mu.Lock()
		p := a.pending
		a.pending = nil
		a.mu.Unlock()
		if p != nil {
			a.restore(*p)
		}
		os.Exit(130)
	}()
}

func (a *App) zapretDir() string         { return filepath.Join(a.dataDir, "zapret") }
func (a *App) gdpiDir() string           { return filepath.Join(a.dataDir, "gdpi") }
func (a *App) logPath() string           { return filepath.Join(a.dataDir, "logs", "engine.log") }
func (a *App) gdpiBlacklistPath() string { return filepath.Join(a.gdpiDir(), "blacklist.txt") }

func (a *App) engineExe(e Engine) string {
	if e == EngineGDPI {
		return filepath.Join(a.gdpiDir(), "goodbyedpi.exe")
	}
	return filepath.Join(a.zapretDir(), "bin", "winws.exe")
}

// checkEngine explains the usual reason an engine file disappears.
func (a *App) checkEngine(e Engine) error {
	if fileExists(a.engineExe(e)) {
		return nil
	}
	return fmt.Errorf("нет файла %s: вероятно, его удалил антивирус. Добавьте папку %s в исключения антивируса и запустите %s снова",
		filepath.Base(a.engineExe(e)), a.dataDir, appName)
}

func (a *App) ownsPath(p string) bool {
	return p != "" && strings.HasPrefix(strings.ToLower(p), strings.ToLower(a.dataDir)+`\`)
}

func (a *App) init() error {
	enableDebugPrivilege() // lets killPID stop a winws that runs as LocalSystem
	if err := secureDataDir(a.dataDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.dataDir, "logs"), 0o755); err != nil {
		return err
	}
	a.loadConfig()
	a.handleConflicts() // before extraction: a foreign engine may hold our files
	prev := a.capture()
	extracted, err := a.ensurePayload(true)
	if err != nil {
		return err
	}
	hardenDir(a.dataDir)
	a.loadStrategies()
	if extracted {
		a.restore(prev)
	}
	return nil
}

func (a *App) capture() prevState { return prevState{mode: a.state(), key: a.cfg.Strategy} }

func (a *App) setPending(p *prevState) {
	a.mu.Lock()
	a.pending = p
	a.mu.Unlock()
}

// restore re-enables the bypass that ran before an operation stopped it
// without ending in a new choice.
func (a *App) restore(p prevState) {
	if p.mode == "" {
		return
	}
	var s Strategy
	found := false
	for _, x := range a.strategies {
		if x.Key() == p.key {
			s, found = x, true
		}
	}
	if !found {
		say(col(cYellow, "  Прежней стратегии больше нет, обход выключен. Запустите автоподбор."))
		return
	}
	say(col(cDim, "  Возвращаю прежнюю стратегию: %s"), s.Name)
	if p.mode == "service" {
		err := a.startService(s)
		if err == nil {
			return
		}
		say(col(cYellow, "  Служба не запустилась (%v), включаю до перезагрузки."), err)
	}
	if err := a.startSession(s); err != nil {
		say(col(cRed, "  Не удалось включить: %v"), err)
	}
}

// ensurePayload unpacks the embedded engines when they are missing, broken
// or older than the ones built into this exe. It reports whether it
// extracted anything (engines were stopped for that).
func (a *App) ensurePayload(manageEngines bool) (bool, error) {
	emb, err := readEmbeddedInfo()
	if err != nil {
		return false, fmt.Errorf("встроенный архив повреждён: %w", err)
	}
	cur, curErr := readInstalledInfo(a.dataDir)
	bats, _ := filepath.Glob(filepath.Join(a.zapretDir(), "strategies", "general*.bat"))
	needZapret := curErr != nil || !fileExists(a.engineExe(EngineZapret)) || len(bats) == 0 ||
		versionLess(cur.Flowseal, emb.Flowseal)
	needGdpi := curErr != nil || !fileExists(a.engineExe(EngineGDPI)) || cur.GoodbyeDPI != emb.GoodbyeDPI
	a.payload = cur
	if !needZapret && !needGdpi {
		return false, nil
	}
	if manageEngines {
		a.stopAll()
	}
	say(col(cDim, "Распаковка рабочих файлов в %s ..."), a.dataDir)
	zr, err := embeddedZip()
	if err != nil {
		return false, err
	}
	if needZapret {
		_ = os.RemoveAll(filepath.Join(a.zapretDir(), "strategies"))
	}
	err = extractZip(zr, a.dataDir, func(name string) (string, bool) {
		switch {
		case strings.HasPrefix(name, "zapret/"), strings.HasPrefix(name, "licenses/"):
			return name, needZapret
		case strings.HasPrefix(name, "gdpi/"):
			return name, needGdpi
		}
		return "", false
	})
	if err != nil {
		return false, err
	}
	if err := ensureUserLists(filepath.Join(a.zapretDir(), "lists")); err != nil {
		return false, err
	}
	if needZapret {
		cur.Flowseal, cur.Source = emb.Flowseal, emb.Source
	}
	if needGdpi {
		cur.GoodbyeDPI = emb.GoodbyeDPI
	}
	a.payload = cur
	return true, writeInstalledInfo(a.dataDir, cur)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (a *App) loadConfig() {
	data, err := os.ReadFile(filepath.Join(a.dataDir, "config.json"))
	if err == nil {
		_ = json.Unmarshal(data, &a.cfg)
	}
}

func (a *App) saveConfig() {
	data, _ := json.MarshalIndent(a.cfg, "", "  ")
	_ = os.WriteFile(filepath.Join(a.dataDir, "config.json"), data, 0o644)
}

func (a *App) loadStrategies() {
	z, errs := loadZapretStrategies(a.zapretDir())
	for _, e := range errs {
		say(col(cYellow, "Пропущена стратегия: %v"), e)
	}
	a.strategies = append(z, gdpiStrategies(a.gdpiBlacklistPath())...)
}

func (a *App) savedStrategy() (Strategy, bool) {
	for _, s := range a.strategies {
		if s.Key() == a.cfg.Strategy {
			return s, true
		}
	}
	return Strategy{}, false
}

func (a *App) writeGdpiBlacklist() error {
	var parts []string
	for _, n := range []string{"list-general.txt", "list-google.txt", "list-general-user.txt"} {
		if b, err := os.ReadFile(filepath.Join(a.zapretDir(), "lists", n)); err == nil {
			parts = append(parts, string(b))
		}
	}
	return os.WriteFile(a.gdpiBlacklistPath(), []byte(buildGdpiBlacklist(parts...)), 0o644)
}

var foreignServices = []string{"zapret", "GoodbyeDPI", "winws1", "winws2", "zapret2"}

// handleConflicts finds other DPI tools: two WinDivert programs at once
// break each other and make the strategy test meaningless.
func (a *App) handleConflicts() {
	var procs []procInfo
	for _, p := range listProcs("winws.exe", "winws2.exe", "goodbyedpi.exe") {
		if !a.ownsPath(p.Path) {
			procs = append(procs, p)
		}
	}
	var svcs []string
	for _, n := range foreignServices {
		if ok, _ := serviceStatus(n); ok {
			svcs = append(svcs, n)
		}
	}
	if len(procs) == 0 && len(svcs) == 0 {
		return
	}
	say(col(cYellow, "\nНайдены другие программы обхода. Они будут мешать:"))
	for _, p := range procs {
		say("  - процесс %s  %s", p.Name, col(cDim, p.Path))
	}
	for _, s := range svcs {
		say("  - служба Windows «%s»", s)
	}
	if !confirm("Остановить их и удалить их службы?", true) {
		say(col(cYellow, "Хорошо. Учтите: с ними подбор может показать неверный результат."))
		return
	}
	for _, s := range svcs {
		if err := stopAndDeleteService(s); err != nil {
			say(col(cRed, "  служба %s: %v"), s, err)
		}
	}
	for _, p := range procs {
		_ = killPID(p.PID)
	}
	_ = stopAndDeleteService("WinDivert")
	say(col(cGreen, "Готово."))
}

// state describes whether our bypass is running and how.
func (a *App) state() string {
	if _, running := serviceStatus(serviceName); running {
		return "service"
	}
	for _, p := range listProcs("winws.exe", "goodbyedpi.exe") {
		if a.ownsPath(p.Path) {
			return "session"
		}
	}
	return ""
}

func (a *App) stopAll() {
	a.killTrial()
	_ = stopAndDeleteService(serviceName)
	for _, p := range listProcs("winws.exe", "goodbyedpi.exe") {
		if a.ownsPath(p.Path) {
			_ = killPID(p.PID)
		}
	}
	_ = stopAndDeleteService("WinDivert")
	a.lastEngine = ""
}

func (a *App) killTrial() {
	a.mu.Lock()
	cmd, done := a.trialCmd, a.trialDone
	a.trialCmd, a.trialDone = nil, nil
	a.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// runTrial starts a strategy, lets WinDivert settle, runs the tester and
// stops the engine again.
func (a *App) runTrial(ctx context.Context, s Strategy, t *Tester) (Report, error) {
	if a.lastEngine != "" && a.lastEngine != s.Engine {
		_ = stopAndDeleteService("WinDivert") // the two engines ship different WinDivert builds
	}
	a.lastEngine = s.Engine
	if err := a.checkEngine(s.Engine); err != nil {
		return Report{}, err
	}
	if s.Engine == EngineGDPI {
		if err := a.writeGdpiBlacklist(); err != nil {
			return Report{}, err
		}
	}
	cmd, done, err := startEngine(a.engineExe(s.Engine), s.Args, a.logPath(), true)
	if err != nil {
		return Report{}, err
	}
	a.mu.Lock()
	a.trialCmd, a.trialDone = cmd, done
	a.mu.Unlock()
	defer a.killTrial()
	select {
	case <-done:
		return Report{}, fmt.Errorf("не запустилась: %s", lastLogLine(a.logPath()))
	case <-time.After(2 * time.Second):
	}
	r := t.Run(ctx)
	select {
	case <-done:
		return r, fmt.Errorf("завершилась во время проверки: %s", lastLogLine(a.logPath()))
	default:
	}
	return r, nil
}

func lastLogLine(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return "нет лога"
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n")), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 110 {
				l = l[:110] + "…"
			}
			return l
		}
	}
	return "лог пуст"
}

func (a *App) clearScreen() {
	if useColor {
		fmt.Print("\x1b[2J\x1b[H")
	}
}

func (a *App) menu() {
	for {
		a.clearScreen()
		say("")
		say("  %s %s  %s", col(cBold+cCyan, appName), version, col(cDim, "обход блокировок YouTube и Discord"))
		say(col(cDim, "  Стратегии: Flowseal %s (%d шт.) + GoodbyeDPI"), a.payload.Flowseal, len(a.strategies))
		switch a.state() {
		case "service":
			say("  Обход: %s %s", col(cGreen, "включён"), col(cDim, "(служба, стартует вместе с Windows)"))
		case "session":
			say("  Обход: %s %s", col(cGreen, "включён"), col(cDim, "(до перезагрузки)"))
		default:
			say("  Обход: %s", col(cRed, "выключен"))
		}
		if s, ok := a.savedStrategy(); ok {
			say("  Стратегия: %s %s", col(cCyan, s.Name), col(cDim, "подобрана "+a.cfg.PickedAt.Format("02.01.2006")))
		}
		say("")
		say("  1. Автоподбор и включение %s", col(cDim, "(рекомендуется)"))
		say("  2. Включить сохранённую стратегию")
		say("  3. Выбрать стратегию вручную")
		say("  4. Проверить, открываются ли YouTube и Discord")
		say("  5. Выключить обход")
		say("  6. Полный подбор (проверить все стратегии и выбрать самую быструю)")
		say("  7. Обновить стратегии с GitHub (Flowseal)")
		say("  8. Удалить всё (службу и рабочие файлы)")
		say("  0. Выход")
		choice := ask("\n  Пункт: ")
		say("")
		switch choice {
		case "1":
			a.autoPick(false, false)
		case "2":
			if s, ok := a.savedStrategy(); ok {
				a.offerEnable(s)
			} else {
				say("Стратегия ещё не подобрана. Выберите пункт 1.")
			}
		case "3":
			a.manualPick()
		case "4":
			a.checkNow()
		case "5":
			a.stopAll()
			say(col(cGreen, "Обход выключен."))
		case "6":
			a.autoPick(true, false)
		case "7":
			a.update()
		case "8":
			if a.uninstall() {
				pause()
				return
			}
		case "0", "q", "й":
			return
		default:
			continue
		}
		say("")
		pause()
	}
}

type trialResult struct {
	s Strategy
	r Report
}

// autoPick tests strategies one by one. Quick mode stops at the first one
// that passes every check twice; full mode tests all and keeps the fastest.
func (a *App) autoPick(full, unattended bool) {
	ctx := context.Background()
	prev := a.capture()
	a.setPending(&prev)
	defer a.setPending(nil)
	a.stopAll()

	say(col(cBold, "Шаг 1. Проверка без обхода"))
	ct := NewTester(ctx, []Target{controlTarget})
	ct.Timeout = 8 * time.Second
	if ctl := ct.Run(ctx); !ctl.AllOK() {
		say(col(cRed, "  Не открывается даже ya.ru: похоже, нет интернета (%s)."), shortFailure(ctl))
		say("  Проверьте подключение и запустите подбор снова.")
		a.restore(prev)
		return
	}
	t := NewTester(ctx, Targets)
	base := t.Run(ctx)
	if t.RecheckSpoofed(ctx, base) {
		base = t.Run(ctx)
	}
	for _, n := range t.Notes {
		say(col(cYellow, "  DNS: %s"), n)
	}
	printReport(base)
	if base.AllOK() {
		say(col(cGreen, "\n  YouTube и Discord уже открываются без обхода."))
		if unattended || !confirm("  Всё равно подобрать стратегию?", false) {
			a.restore(prev)
			return
		}
	}

	say(col(cBold, "\nШаг 2. Перебор стратегий (%d шт.)"), len(a.strategies))
	say(col(cDim, "  Одна проверка занимает около 10 секунд. Ctrl+C прерывает подбор."))
	var results []trialResult
	var winner *trialResult
	for i, s := range a.strategies {
		fmt.Printf("  [%2d/%d] %-30s ", i+1, len(a.strategies), s.Name)
		r, err := a.runTrial(ctx, s, t)
		if err != nil {
			say(col(cRed, "%v"), err)
			continue
		}
		say("%s", serviceLine(r))
		results = append(results, trialResult{s, r})
		if r.AllOK() && !full {
			fmt.Printf("  %s", col(cDim, "         перепроверка... "))
			r2, err := a.runTrial(ctx, s, t)
			if err == nil && r2.AllOK() {
				say(col(cGreen, "стабильно"))
				winner = &trialResult{s, r2}
				break
			}
			say(col(cYellow, "нестабильно, ищу дальше"))
		}
	}
	if winner == nil {
		winner = a.pickBest(ctx, t, results)
	}
	a.stopAll()

	say(col(cBold, "\nШаг 3. Результат"))
	helps := winner != nil && winner.r.Passed() > 0 &&
		(winner.r.AllOK() || winner.r.Passed() > base.Passed())
	if !helps {
		say(col(cRed, "  Ни одна стратегия не помогла."))
		say("  Что можно сделать:")
		say("  - пункт 7: обновить стратегии с GitHub и повторить подбор;")
		say("  - выключить VPN, прокси и «защиту сети» антивируса на время подбора;")
		say("  - если не помогает: провайдер блокирует по IP, тогда поможет только VPN.")
		if t.DNSTrouble() {
			a.dnsAdvice()
		}
		a.restore(prev)
		return
	}
	a.setPending(nil)
	say("  Лучшая стратегия: %s", col(cCyan, winner.s.Name))
	say("  %s", serviceLine(winner.r))
	if !winner.r.AllOK() {
		say(col(cYellow, "  Помогает частично: %s"), shortFailure(winner.r))
	}
	a.cfg = Config{Strategy: winner.s.Key(), PickedAt: time.Now(), Result: plainServiceLine(winner.r)}
	a.saveConfig()
	if t.DNSTrouble() {
		a.dnsAdvice()
	}
	if unattended {
		a.enable(winner.s, true)
		return
	}
	a.offerEnable(winner.s)
}

// pickBest ranks partial or full-mode results and re-checks the leaders so a
// lucky single run does not win.
func (a *App) pickBest(ctx context.Context, t *Tester, results []trialResult) *trialResult {
	sort.SliceStable(results, func(i, j int) bool { return results[i].r.Better(results[j].r) })
	for i := 0; i < len(results) && i < 3; i++ {
		c := results[i]
		if c.r.Passed() == 0 {
			break
		}
		fmt.Printf("  Перепроверка лидера: %-30s ", c.s.Name)
		r2, err := a.runTrial(ctx, c.s, t)
		if err == nil && r2.Passed() >= c.r.Passed() {
			say(col(cGreen, "подтверждено"))
			return &trialResult{c.s, r2}
		}
		say(col(cYellow, "не подтвердилось"))
	}
	if len(results) > 0 && results[0].r.Passed() > 0 {
		return &results[0]
	}
	return nil
}

func plainServiceLine(r Report) string {
	var parts []string
	for _, s := range r.Services() {
		st := "не работает"
		if r.ServiceOK(s) {
			st = "работает"
		}
		parts = append(parts, s+": "+st)
	}
	return strings.Join(parts, ", ")
}

func (a *App) dnsAdvice() {
	say(col(cYellow, "\n  Провайдер подменяет DNS для части сайтов."))
	say("  Включите «Безопасный DNS» в браузере: Chrome/Edge/Яндекс → Настройки → Конфиденциальность →")
	say("  Использовать безопасный DNS → Cloudflare (1.1.1.1) или Google. В Firefox: «DNS через HTTPS».")
}

func (a *App) offerEnable(s Strategy) {
	say("\n  Как включить «%s»?", s.Name)
	say("  1. Включить и запускать вместе с Windows %s", col(cDim, "(рекомендуется)"))
	say("  2. Включить до перезагрузки")
	say("  0. Не включать")
	switch ask("  Пункт [1]: ") {
	case "", "1":
		a.enable(s, true)
	case "2":
		a.enable(s, false)
	}
}

func (a *App) startService(s Strategy) error {
	if s.Engine == EngineGDPI {
		if err := a.writeGdpiBlacklist(); err != nil {
			return err
		}
	}
	err := installService(serviceName, appName, "Обход блокировок YouTube и Discord ("+s.Name+"). "+repoURL,
		a.engineExe(s.Engine), s.Args)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		switch serviceState(serviceName) {
		case svcRunning:
			time.Sleep(1500 * time.Millisecond) // let WinDivert settle before the check
			return nil
		case svcStopped:
			_ = stopAndDeleteService(serviceName)
			return errors.New("служба остановилась сразу после запуска (подробности: Просмотр событий → Журналы Windows → Система)")
		}
	}
	_ = stopAndDeleteService(serviceName)
	return errors.New("служба не перешла в состояние «работает»")
}

// startSession runs the engine detached until reboot.
func (a *App) startSession(s Strategy) error {
	if err := a.checkEngine(s.Engine); err != nil {
		return err
	}
	if s.Engine == EngineGDPI {
		if err := a.writeGdpiBlacklist(); err != nil {
			return err
		}
	}
	_, done, err := startEngine(a.engineExe(s.Engine), s.Args, a.logPath(), false)
	if err != nil {
		return err
	}
	select {
	case <-done:
		return fmt.Errorf("программа сразу завершилась: %s", lastLogLine(a.logPath()))
	case <-time.After(2 * time.Second):
		return nil
	}
}

func (a *App) enable(s Strategy, asService bool) {
	a.stopAll()
	if err := a.checkEngine(s.Engine); err != nil {
		say(col(cRed, "  %v"), err)
		return
	}
	if asService {
		if err := a.startService(s); err != nil {
			say(col(cYellow, "  Служба не запустилась (%v). Включаю до перезагрузки."), err)
			asService = false
		}
	}
	if !asService {
		if err := a.startSession(s); err != nil {
			say(col(cRed, "  Не удалось включить: %v"), err)
			return
		}
	}
	mode := "до перезагрузки, окно можно закрыть"
	if asService {
		mode = "служба Windows, включится сама после перезагрузки"
	}
	say(col(cGreen, "\n  Обход включён: %s"), s.Name)
	say(col(cDim, "  (%s)"), mode)
	fmt.Print("  Контрольная проверка... ")
	ctx := context.Background()
	r := NewTester(ctx, Targets).Run(ctx)
	say("%s", serviceLine(r))
	say(col(cDim, "  Если Discord был открыт, полностью закройте его (через значок в трее) и запустите снова."))
}

func (a *App) checkNow() {
	ctx := context.Background()
	t := NewTester(ctx, Targets)
	r := t.Run(ctx)
	if t.RecheckSpoofed(ctx, r) {
		r = t.Run(ctx)
	}
	for _, n := range t.Notes {
		say(col(cYellow, "  DNS: %s"), n)
	}
	printReport(r)
	if t.DNSTrouble() {
		a.dnsAdvice()
	}
}

func (a *App) manualPick() {
	for i, s := range a.strategies {
		say("  %2d. %s", i+1, s.Name)
	}
	n, err := strconv.Atoi(ask("\n  Номер стратегии (Enter: назад): "))
	if err != nil || n < 1 || n > len(a.strategies) {
		return
	}
	s := a.strategies[n-1]
	ctx := context.Background()
	prev := a.capture()
	a.setPending(&prev)
	defer a.setPending(nil)
	a.stopAll()
	t := NewTester(ctx, Targets)
	say("  Проверяю %s ...", s.Name)
	r, err := a.runTrial(ctx, s, t)
	a.stopAll()
	if err != nil {
		say(col(cRed, "  %v"), err)
		a.restore(prev)
		return
	}
	printReport(r)
	if !confirm("\n  Сохранить эту стратегию?", r.Passed() > 0) {
		a.restore(prev)
		return
	}
	a.setPending(nil)
	a.cfg = Config{Strategy: s.Key(), PickedAt: time.Now(), Result: plainServiceLine(r)}
	a.saveConfig()
	a.offerEnable(s)
}

func (a *App) update() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	say("  Проверяю последнюю версию Flowseal на GitHub...")
	tag, url, err := latestFlowseal(ctx)
	if err != nil {
		say(col(cRed, "  Не удалось: %v"), err)
		return
	}
	say("  Установлено: %s, на GitHub: %s", a.payload.Flowseal, tag)
	if !versionLess(a.payload.Flowseal, tag) {
		say(col(cGreen, "  Стратегии уже последней версии."))
		return
	}
	if !confirm("  Скачать и установить?", true) {
		return
	}
	data, err := downloadBytes(ctx, url, 64<<20)
	if err != nil {
		say(col(cRed, "  Загрузка не удалась: %v"), err)
		return
	}
	prev := a.capture()
	a.stopAll()
	n, err := installFlowsealZip(data, a.zapretDir())
	if err != nil {
		say(col(cRed, "  Установка не удалась, остались прежние стратегии: %v"), err)
		a.restore(prev)
		return
	}
	a.payload.Flowseal, a.payload.Source = tag, "github"
	_ = writeInstalledInfo(a.dataDir, a.payload)
	hardenDir(a.dataDir)
	a.loadStrategies()
	say(col(cGreen, "  Обновлено до %s: %d стратегий."), tag, n)
	a.restore(prev)
	say("  Рекомендуется заново запустить автоподбор (пункт 1).")
}

func (a *App) uninstall() bool {
	if !confirm("  Выключить обход и удалить службу и папку "+a.dataDir+"?", false) {
		return false
	}
	a.stopAll()
	if err := os.RemoveAll(a.dataDir); err != nil {
		say(col(cRed, "  Не всё удалось удалить: %v"), err)
		return false
	}
	say(col(cGreen, "  Удалено. Сам файл %s.exe можно просто удалить."), appName)
	return true
}

// runSelftest needs no admin rights: it unpacks the payload, validates every
// zapret strategy with `winws --dry-run` and runs the tester without bypass.
func runSelftest(dataDir string) int {
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), appName+"-selftest")
	}
	a := &App{dataDir: dataDir}
	if err := os.MkdirAll(filepath.Join(dataDir, "logs"), 0o755); err != nil {
		say("mkdir: %v", err)
		return 1
	}
	if _, err := a.ensurePayload(false); err != nil {
		say("payload: %v", err)
		return 1
	}
	a.loadStrategies()
	say("%s %s selftest, admin=%v, data=%s", appName, version, isAdmin(), dataDir)
	say("payload: Flowseal %s, GoodbyeDPI %s, strategies: %d", a.payload.Flowseal, a.payload.GoodbyeDPI, len(a.strategies))
	failed := 0
	for _, s := range a.strategies {
		if s.Engine != EngineZapret {
			continue
		}
		cmd := exec.Command(a.engineExe(s.Engine), append([]string{"--dry-run"}, s.Args...)...)
		cmd.Dir = filepath.Dir(a.engineExe(s.Engine))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		// winws.exe's manifest demands elevation; --dry-run only parses options.
		cmd.Env = append(os.Environ(), "__COMPAT_LAYER=RunAsInvoker")
		out, err := cmd.CombinedOutput()
		status := "OK"
		if err != nil {
			status = "FAIL " + err.Error()
			failed++
		}
		say("dry-run %-30s %s", s.Name, status)
		if err != nil {
			say("  %s", lastNonEmpty(string(out)))
		}
	}
	ctx := context.Background()
	t := NewTester(ctx, append([]Target{controlTarget}, Targets...))
	for _, n := range t.Notes {
		say("DNS: %s", n)
	}
	r := t.Run(ctx)
	printReport(r)
	say("tester: %d/%d passed; dry-run failures: %d", r.Passed(), len(r.Results), failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func lastNonEmpty(s string) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}
