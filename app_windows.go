//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config is persisted in <dataDir>\config.json.
type Config struct {
	Strategy string    `json:"strategy,omitempty"`
	PickedAt time.Time `json:"picked_at,omitempty"`
	// Autostart: run as an auto-start service (true) or until reboot.
	Autostart bool `json:"autostart"`
	// Heal: re-check at logon and re-pick a strategy if the old one broke.
	Heal  bool `json:"heal"`
	Games bool `json:"games,omitempty"`
	// Toggles override the catalog default (true = check, false = skip).
	Toggles map[string]bool `json:"toggles,omitempty"`
	// Fixed are services that worked only with the bypass at the last fix.
	Fixed []string `json:"fixed,omitempty"`
	// ForeignDisabled are other tools' Windows services EzPzDPI disabled,
	// with their original start type, so they can be restored.
	ForeignDisabled map[string]uint32 `json:"foreign_disabled,omitempty"`
	// ForeignTasks are other tools' scheduled tasks EzPzDPI disabled.
	ForeignTasks []string `json:"foreign_tasks,omitempty"`
	// ForeignShortcuts maps a moved autostart shortcut (backup path) to its
	// original path.
	ForeignShortcuts map[string]string `json:"foreign_shortcuts,omitempty"`
	DNSBackup        *DNSBackup        `json:"dns_backup,omitempty"`
	ProxyBackup      *ProxyBackup      `json:"proxy_backup,omitempty"`
	DefenderExcluded bool              `json:"defender_excluded,omitempty"`
	// Installed: Start menu shortcut and "Apps" uninstall entry exist.
	Installed bool `json:"installed,omitempty"`
	// Off: the user switched the bypass off; the logon check must not turn
	// it back on.
	Off           bool      `json:"off,omitempty"`
	LastHeal      string    `json:"last_heal,omitempty"`
	LastHealAt    time.Time `json:"last_heal_at,omitempty"`
	ConfigVersion int       `json:"config_version"`
}

// DNSBackup records an adapter's DNS settings before EzPzDPI switched it
// to encrypted DNS, so the change can be undone exactly.
type DNSBackup struct {
	IfIndex  uint32    `json:"if_index"`
	IfGUID   string    `json:"if_guid"`
	IfName   string    `json:"if_name"`
	WasDHCP  bool      `json:"was_dhcp"`
	Servers  []string  `json:"servers,omitempty"`
	Provider string    `json:"provider"`
	At       time.Time `json:"at"`
}

// ProxyBackup records the WinINET proxy settings before EzPzDPI turned a
// dead proxy off.
type ProxyBackup struct {
	Enable uint32    `json:"enable"`
	Server string    `json:"server"`
	PAC    string    `json:"pac"`
	At     time.Time `json:"at"`
	// UserKey is the Internet Settings path under HKEY_USERS of the user
	// whose proxy was changed ("" = the elevated account's HKCU).
	UserKey string `json:"user_key,omitempty"`
}

// journal appends one system change to logs\journal.log (JSON lines):
// what changed, the value before and after. Undo actions read the config
// backups; the journal is the human-readable audit trail.
func (a *App) journal(what, before, after string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	rec, _ := json.Marshal(map[string]string{
		"time": time.Now().Format(time.RFC3339), "what": what, "before": before, "after": after,
	})
	f, err := os.OpenFile(filepath.Join(a.logDir(), "journal.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(rec, '\r', '\n'))
}

func defaultConfig() Config { return Config{Autostart: true, Heal: true, ConfigVersion: 2} }

type App struct {
	dataDir    string
	cfg        Config
	payload    PayloadInfo
	strategies []Strategy
	lastEngine Engine

	mu        sync.Mutex
	trialCmd  *exec.Cmd
	trialDone <-chan error

	logMu sync.Mutex
	// keptBackups is where uninstall saved the backups, for the final message.
	keptBackups string
}

// prevState remembers how our bypass ran before an operation stopped it.
type prevState struct{ mode, key string }

func (a *App) zapretDir() string         { return filepath.Join(a.dataDir, "zapret") }
func (a *App) gdpiDir() string           { return filepath.Join(a.dataDir, "gdpi") }
func (a *App) logDir() string            { return filepath.Join(a.dataDir, "logs") }
func (a *App) logPath() string           { return filepath.Join(a.logDir(), "engine.log") }
func (a *App) gdpiBlacklistPath() string { return filepath.Join(a.gdpiDir(), "blacklist.txt") }
func (a *App) extraListPath() string {
	return filepath.Join(a.zapretDir(), "lists", "list-ezpzdpi.txt")
}
func (a *App) installedExe() string { return filepath.Join(a.dataDir, appName+".exe") }

// Engines run under their own image names, so other tools' "kill all
// winws.exe" helpers do not stop EzPzDPI, and our processes are easy to
// tell apart from foreign ones.
const (
	ourWinws = "ezpz-winws.exe"
	ourGdpi  = "ezpz-goodbyedpi.exe"
)

// ourEngineNames includes 0.1.x names so old engines are found and stopped.
var ourEngineNames = []string{ourWinws, ourGdpi, "winws.exe", "goodbyedpi.exe"}

func (a *App) engineExe(e Engine) string {
	if e == EngineGDPI {
		return filepath.Join(a.gdpiDir(), ourGdpi)
	}
	return filepath.Join(a.zapretDir(), "bin", ourWinws)
}

// ensureEngineCopies refreshes the renamed engine copies from the files the
// payload or a Flowseal update installed.
func (a *App) ensureEngineCopies() error {
	pairs := [][2]string{
		{filepath.Join(a.zapretDir(), "bin", "winws.exe"), a.engineExe(EngineZapret)},
		{filepath.Join(a.gdpiDir(), "goodbyedpi.exe"), a.engineExe(EngineGDPI)},
	}
	for _, p := range pairs {
		src, err := os.ReadFile(p[0])
		if err != nil {
			continue // the antivirus may have removed it; checkEngine explains
		}
		if cur, err := os.ReadFile(p[1]); err == nil && string(cur) == string(src) {
			continue
		}
		if err := os.WriteFile(p[1], src, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// logf appends a line to logs\app.log (rotated at 1 MB).
func (a *App) logf(format string, args ...any) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	p := filepath.Join(a.logDir(), "app.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 1<<20 {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\r\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// checkEngine explains the usual reason an engine file disappears.
func (a *App) checkEngine(e Engine) error {
	if fileExists(a.engineExe(e)) {
		return nil
	}
	return fmt.Errorf("нет файла %s: скорее всего, его удалил антивирус. Добавьте папку %s в исключения антивируса и откройте EzPzDPI снова",
		filepath.Base(a.engineExe(e)), a.dataDir)
}

func (a *App) ownsPath(p string) bool {
	return p != "" && strings.HasPrefix(strings.ToLower(p), strings.ToLower(a.dataDir)+`\`)
}

// init prepares the data folder and payload. It never touches other tools;
// conflicts are reported by detectEnv and resolved by the controller.
func (a *App) init() error {
	enableDebugPrivilege() // lets killPID stop a winws that runs as LocalSystem
	if err := secureDataDir(a.dataDir); err != nil {
		return err
	}
	if err := os.MkdirAll(a.logDir(), 0o755); err != nil {
		return err
	}
	a.loadConfig()
	prev := a.capture()
	extracted, err := a.ensurePayload(true)
	if err != nil {
		return err
	}
	hardenDir(a.dataDir)
	if err := a.ensureEngineCopies(); err != nil {
		a.logf("engine copies: %v", err)
	}
	_ = a.writeExtraList()
	a.loadStrategies()
	if extracted {
		a.logf("payload extracted: Flowseal %s, GoodbyeDPI %s", a.payload.Flowseal, a.payload.GoodbyeDPI)
		_ = a.restore(prev)
	}
	// A newer downloaded exe refreshes the installed copy that the logon
	// check and the Start menu entry run.
	if a.cfg.Installed {
		if err := a.installSelf(); err != nil {
			a.logf("update installed copy: %v", err)
		}
	}
	return nil
}

func (a *App) capture() prevState { return prevState{mode: a.state(), key: a.cfg.Strategy} }

// restore re-enables the bypass that ran before an operation stopped it.
func (a *App) restore(p prevState) error {
	if p.mode == "" {
		return nil
	}
	s, ok := a.strategyByKey(p.key)
	if !ok {
		return errors.New("прежней стратегии больше нет")
	}
	a.logf("restore %s (%s)", s.Name, p.mode)
	if p.mode == "service" {
		if err := a.startService(s); err == nil {
			return nil
		}
	}
	return a.startSession(s)
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
	needZapret := curErr != nil || !fileExists(filepath.Join(a.zapretDir(), "bin", "winws.exe")) || len(bats) == 0 ||
		versionLess(cur.Flowseal, emb.Flowseal)
	needGdpi := curErr != nil || !fileExists(filepath.Join(a.gdpiDir(), "goodbyedpi.exe")) || cur.GoodbyeDPI != emb.GoodbyeDPI
	a.payload = cur
	if !needZapret && !needGdpi {
		return false, nil
	}
	if manageEngines {
		a.stopAll()
	}
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
	a.cfg = defaultConfig()
	data, err := os.ReadFile(filepath.Join(a.dataDir, "config.json"))
	if err != nil {
		return
	}
	var c Config
	if json.Unmarshal(data, &c) != nil {
		return
	}
	if c.ConfigVersion < 2 { // 0.1.x configs had no settings
		keep, pick := c.Strategy, c.PickedAt
		c = defaultConfig()
		c.Strategy, c.PickedAt = keep, pick
	}
	a.cfg = c
}

func (a *App) saveConfig() {
	data, _ := json.MarshalIndent(a.cfg, "", "  ")
	_ = os.WriteFile(filepath.Join(a.dataDir, "config.json"), data, 0o644)
}

// enabledServices are the catalog ids the user wants checked: catalog
// defaults, overridden by the user's toggles.
func (a *App) enabledServices() map[string]bool {
	on := map[string]bool{}
	for _, s := range catalog {
		want := s.Default
		if v, ok := a.cfg.Toggles[s.ID]; ok {
			want = v
		}
		if want {
			on[s.ID] = true
		}
	}
	return on
}

// writeExtraList writes EzPzDPI's own domains (for enabled services) next to
// Flowseal's lists; strategies reference it through --hostlist.
func (a *App) writeExtraList() error {
	doms := extraDomains(a.enabledServices())
	if len(doms) == 0 {
		doms = []string{"domain.example.abc"} // winws refuses empty lists
	}
	return os.WriteFile(a.extraListPath(), []byte(strings.Join(doms, "\r\n")+"\r\n"), 0o644)
}

func (a *App) loadStrategies() {
	game := gameFilterOff
	if a.cfg.Games {
		game = gameFilterOn
	}
	z, errs := loadZapretStrategies(a.zapretDir(), game, a.extraListPath())
	for _, e := range errs {
		a.logf("strategy skipped: %v", e)
	}
	a.strategies = append(z, gdpiStrategies(a.gdpiBlacklistPath())...)
}

func (a *App) strategyByKey(key string) (Strategy, bool) {
	for _, s := range a.strategies {
		if s.Key() == key {
			return s, true
		}
	}
	return Strategy{}, false
}

func (a *App) savedStrategy() (Strategy, bool) { return a.strategyByKey(a.cfg.Strategy) }

func (a *App) writeGdpiBlacklist() error {
	var parts []string
	for _, n := range []string{"list-general.txt", "list-google.txt", "list-general-user.txt", "list-ezpzdpi.txt"} {
		if b, err := os.ReadFile(filepath.Join(a.zapretDir(), "lists", n)); err == nil {
			parts = append(parts, string(b))
		}
	}
	return os.WriteFile(a.gdpiBlacklistPath(), []byte(buildGdpiBlacklist(parts...)), 0o644)
}

// state describes whether our bypass runs: "service", "session" or "".
func (a *App) state() string {
	if serviceState(serviceName) == svcRunning {
		return "service"
	}
	for _, p := range listProcs(ourEngineNames...) {
		if a.ownsPath(p.Path) {
			return "session"
		}
	}
	return ""
}

// stopAll stops our bypass (service, detached engines, trial engine).
func (a *App) stopAll() {
	a.killTrial()
	_ = stopAndDeleteService(serviceName)
	for _, p := range listProcs(ourEngineNames...) {
		if a.ownsPath(p.Path) {
			if err := killPID(p.PID); err != nil {
				a.logf("kill %s (%d): %v", p.Path, p.PID, err)
			}
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

// runTrial starts a strategy, lets WinDivert settle, runs the tester (and
// extra checks such as the voice estimate) and stops the engine again.
func (a *App) runTrial(ctx context.Context, s Strategy, t *Tester, extra func(context.Context) []ProbeResult) (Report, error) {
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
		return Report{}, engineFailure(lastLogLine(a.logPath()))
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		return Report{}, ctx.Err()
	}
	r := t.Run(ctx)
	if extra != nil && ctx.Err() == nil {
		r.Results = append(r.Results, extra(ctx)...)
	}
	select {
	case <-done:
		return r, engineFailure(lastLogLine(a.logPath()))
	default:
	}
	return r, ctx.Err()
}

// EngineError carries an engine start failure with a plain explanation.
type EngineError struct {
	Line   string
	Advice string
}

func (e *EngineError) Error() string {
	if e.Advice != "" {
		return e.Advice
	}
	return "программа обхода не запустилась: " + e.Line
}

func engineFailure(line string) error {
	return &EngineError{Line: line, Advice: explainEngineLog(line)}
}

func lastLogLine(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return "нет лога"
	}
	return lastNonEmpty(string(data))
}

func lastNonEmpty(s string) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 160 {
				l = l[:160] + "…"
			}
			return l
		}
	}
	return ""
}

func (a *App) startService(s Strategy) error {
	if err := a.checkEngine(s.Engine); err != nil {
		return err
	}
	if s.Engine == EngineGDPI {
		if err := a.writeGdpiBlacklist(); err != nil {
			return err
		}
	}
	err := installService(serviceName, appName, "Обход блокировок ("+s.Name+"). "+repoURL, a.engineExe(s.Engine), s.Args)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		switch serviceState(serviceName) {
		case svcRunning:
			time.Sleep(1500 * time.Millisecond) // let WinDivert settle before any check
			return nil
		case svcStopped:
			_ = stopAndDeleteService(serviceName)
			return errors.New("служба остановилась сразу после запуска (подробности: Просмотр событий, журнал «Система»)")
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
		return engineFailure(lastLogLine(a.logPath()))
	case <-time.After(2 * time.Second):
		return nil
	}
}

// enable switches the bypass on with strategy s in the configured mode and
// returns the mode actually used.
func (a *App) enable(s Strategy) (string, error) {
	a.stopAll()
	if a.cfg.Autostart {
		err := a.startService(s)
		if err == nil {
			return "service", nil
		}
		a.logf("service start failed, falling back to session: %v", err)
	}
	if err := a.startSession(s); err != nil {
		return "", err
	}
	return "session", nil
}

// installSelf copies this exe into the data dir so the logon task can run
// it even if the user deletes or moves the downloaded file.
func (a *App) installSelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(a.installedExe())) {
		return nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(a.installedExe()); err == nil && string(cur) == string(data) {
		return nil
	}
	tmp := a.installedExe() + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, a.installedExe())
}

// syncHealTask makes the logon task match the settings.
func (a *App) syncHealTask() error {
	if !a.cfg.Heal || a.cfg.Strategy == "" || a.cfg.Off {
		return deleteTask(healTaskName)
	}
	if err := a.installSelf(); err != nil {
		return err
	}
	return createLogonTask(healTaskName, a.installedExe(), "-heal")
}

// update installs the newest Flowseal release from GitHub.
func (a *App) update(ctx context.Context) (tag string, n int, err error) {
	tag, url, err := latestFlowseal(ctx)
	if err != nil {
		return "", 0, err
	}
	if !versionLess(a.payload.Flowseal, tag) {
		return tag, 0, nil
	}
	data, err := downloadBytes(ctx, url, 64<<20)
	if err != nil {
		return tag, 0, err
	}
	prev := a.capture()
	a.stopAll()
	n, err = installFlowsealZip(data, a.zapretDir())
	if err != nil {
		_ = a.restore(prev)
		return tag, 0, err
	}
	a.payload.Flowseal, a.payload.Source = tag, "github"
	_ = writeInstalledInfo(a.dataDir, a.payload)
	hardenDir(a.dataDir)
	_ = a.ensureEngineCopies()
	_ = a.writeExtraList()
	a.loadStrategies()
	_ = a.restore(prev)
	return tag, n, nil
}

// uninstall reverts every change EzPzDPI made (U01) and removes its files.
// It returns the steps that failed, in plain Russian.
func (a *App) uninstall(restoreForeignTools bool) []string {
	var errs []string
	step := func(what string, err error) {
		if err != nil {
			a.logf("uninstall %s: %v", what, err)
			errs = append(errs, what+": "+err.Error())
		}
	}
	a.stopAll()
	step("задача автопроверки", deleteTask(healTaskName))
	if a.cfg.DNSBackup != nil {
		step("настройки DNS", revertSecureDNS(a))
	}
	if a.cfg.DefenderExcluded {
		step("исключение Защитника", removeDefenderExclusion(a))
	}
	if restoreForeignTools {
		step("прежний обход", restoreForeign(a))
		step("файл hosts", restoreHosts(a))
	}
	// After the old tool is back, so a proxy it serves is seen alive; a dead
	// proxy is left off instead of cutting the browser off.
	if a.cfg.ProxyBackup != nil {
		step("прокси", restoreProxy(a))
	}
	step("ярлык и запись в «Приложениях»", removeEntries(a))
	if len(errs) > 0 {
		a.saveConfig() // keep the backups so a second run can finish the job
		return errs
	}
	kept, err := a.preserveBackups()
	if err != nil {
		a.saveConfig()
		return []string{"резервные копии не удалось сохранить (" + err.Error() + "), поэтому папка " + a.dataDir + " оставлена"}
	}
	if kept != "" {
		a.logf("backups kept in %s", kept)
	}
	scheduleRemoval(a.dataDir)
	return nil
}

// preserveBackups copies the backup folder (hosts copies, moved autostart
// entries of other tools, service exports) out of the data folder before it
// is removed. The copy goes to a NEW admin-only folder under ProgramData
// with an unpredictable name: never into a user-writable place, where a
// pre-planted junction could redirect this elevated write.
func (a *App) preserveBackups() (string, error) {
	src := filepath.Join(a.dataDir, "backup")
	if entries, err := os.ReadDir(src); err != nil || len(entries) == 0 {
		return "", nil
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	dst := filepath.Join(filepath.Dir(a.dataDir),
		fmt.Sprintf("%s-backup-%s-%x", appName, time.Now().Format("20060102-150405"), rnd))
	if err := createAdminOnlyDir(dst); err != nil { // fails if it already exists
		return "", err
	}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil // never follow links, even in our own folder
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.Mkdir(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		a.logf("preserve backups: %v", err)
		return "", err
	}
	a.keptBackups = dst
	return dst, nil
}

// runSelftest needs no admin rights: it unpacks the payload, validates every
// zapret strategy with `winws --dry-run` and runs the diagnosis.
func runSelftest(dataDir string) int {
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), appName+"-selftest")
	}
	a := &App{dataDir: dataDir, cfg: defaultConfig()}
	if err := os.MkdirAll(a.logDir(), 0o755); err != nil {
		say("mkdir: %v", err)
		return 1
	}
	if _, err := a.ensurePayload(false); err != nil {
		say("payload: %v", err)
		return 1
	}
	if err := a.ensureEngineCopies(); err != nil {
		say("engine copies: %v", err)
		return 1
	}
	_ = a.writeExtraList()
	failed := 0
	for _, games := range []bool{false, true} {
		a.cfg.Games = games
		a.loadStrategies()
		say("%s %s selftest, admin=%v, games=%v, data=%s", appName, version, isAdmin(), games, dataDir)
		say("payload: Flowseal %s, GoodbyeDPI %s, strategies: %d", a.payload.Flowseal, a.payload.GoodbyeDPI, len(a.strategies))
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
	}
	ctx := context.Background()
	t := NewTester(ctx, allTargets(nil))
	t.Neutral = true
	for _, n := range t.Notes {
		say("DNS: %s", n)
	}
	r := t.Run(ctx)
	byID := catalogByID()
	for _, id := range r.Services() {
		d := Diagnose(byID[id], r)
		say("%-22s %-10s %s", byID[id].Name, d.State, d.Detail)
	}
	say("tester: %d/%d probes passed; dry-run failures: %d", r.Passed(), len(r.Results), failed)
	if failed > 0 {
		return 1
	}
	return 0
}
