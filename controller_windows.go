//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ViewState is everything the window (or console) shows. It is sent to the
// page as JSON after every change; see docs/dev/v02-contracts.md.
type ViewState struct {
	Phase            string            `json:"phase"`
	Verdict          Verdict           `json:"verdict"`
	Progress         *Progress         `json:"progress,omitempty"`
	Provenance       string            `json:"provenance,omitempty"`
	Bypass           Bypass            `json:"bypass"`
	Services         []ViewService     `json:"services"`
	Notices          []Finding         `json:"notices"`
	Settings         SettingsView      `json:"settings"`
	Catalog          []CatalogItem     `json:"catalog"`
	Versions         map[string]string `json:"versions"`
	Strategies       []StratRef        `json:"strategies"`
	ConfirmFix       string            `json:"confirm_fix,omitempty"`
	ConfirmReplace   string            `json:"confirm_replace,omitempty"` // before a manual pick stops another tool
	Busy             bool              `json:"busy"`                      // an operation is running: controls are disabled
	ForeignDisabled  []string          `json:"foreign_disabled,omitempty"`
	SecureDNS        SecureDNSView     `json:"secure_dns"`
	DefenderExcluded bool              `json:"defender_excluded"`
	Report           string            `json:"report,omitempty"`
	Uninstalled      bool              `json:"uninstalled,omitempty"`
}

type Verdict struct {
	Title       string `json:"title"`
	Text        string `json:"text"`
	Action      string `json:"action,omitempty"`
	Second      string `json:"second,omitempty"`
	Calm        bool   `json:"calm,omitempty"`
	Busy        bool   `json:"busy,omitempty"`
	CancelLabel string `json:"cancel_label,omitempty"`
}

type Progress struct {
	I      int `json:"i"`
	N      int `json:"n"`
	ETASec int `json:"eta_sec"`
}

type Bypass struct {
	On        bool   `json:"on"`
	Strategy  string `json:"strategy,omitempty"`
	Autostart bool   `json:"autostart"`
}

type ViewService struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	State    SvcState `json:"state"`
	Fixable  bool     `json:"fixable"`
	Detail   string   `json:"detail,omitempty"`
	Label    string   `json:"label,omitempty"`
}

type SettingsView struct {
	Autostart bool     `json:"autostart"`
	Heal      bool     `json:"heal"`
	Games     bool     `json:"games"`
	Enabled   []string `json:"enabled"`
}

type CatalogItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Default  bool   `json:"default"`
}

type StratRef struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type SecureDNSView struct {
	Supported bool   `json:"supported"`
	Active    bool   `json:"active"`
	Provider  string `json:"provider,omitempty"`
}

const cancelLabel = "Отменить — ничего не сломается"

// Provenance labels (D09): how the results on screen were measured.
const (
	provDirect  = "Напрямую через провайдера"
	provForeign = "Через ваш текущий обход"
	provVPN     = "Через VPN — это не ваш провайдер"
	provOurs    = "С обходом EzPzDPI"
)

// Controller runs every user-facing scenario and keeps ViewState current.
type Controller struct {
	a *App

	mu       sync.Mutex
	vs       ViewState
	env      Env
	diag     map[string]Diagnosis // last diagnosis shown
	baseline map[string]Diagnosis // last diagnosis without any bypass
	prov     string
	extra    []Finding // notices produced by checks (DNS, antivirus, interrupted fix)
	busy     bool
	cancel   context.CancelFunc
	done     chan struct{}
	pending  *fixMarker
	last     ViewState // last published view, re-sent when the page reloads

	onChange func(ViewState)
}

// setEnv replaces the environment scan under the lock: the page thread
// reads it through update/refreshStatic.
func (c *Controller) setEnv(e Env) {
	c.mu.Lock()
	c.env = e
	c.mu.Unlock()
}

func (c *Controller) getEnv() Env {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.env
}

// Republish re-sends the last view without touching any state; the page
// calls it once it has loaded.
func (c *Controller) Republish() {
	c.mu.Lock()
	vs := c.last
	c.mu.Unlock()
	if c.onChange != nil && vs.Verdict.Title != "" {
		c.onChange(vs)
	}
}

func newController(a *App) *Controller {
	c := &Controller{a: a, diag: map[string]Diagnosis{}}
	c.vs.Phase = "idle"
	return c
}

// update mutates the view under the lock and publishes a copy.
func (c *Controller) update(f func(vs *ViewState)) {
	vs := c.apply(f)
	if c.onChange != nil {
		c.onChange(vs)
	}
}

// apply runs f under the lock; the deferred unlock keeps the controller
// usable even if f panics.
func (c *Controller) apply(f func(vs *ViewState)) ViewState {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(&c.vs)
	c.vs.Report = c.reportLocked()
	vs := c.vs
	vs.Services = append([]ViewService(nil), c.vs.Services...)
	vs.Notices = append([]Finding(nil), c.vs.Notices...)
	c.last = vs
	return vs
}

func (c *Controller) push() { c.update(func(vs *ViewState) { c.refreshStatic(vs) }) }

// Snapshot returns a copy of the current view.
func (c *Controller) Snapshot() ViewState {
	c.mu.Lock()
	defer c.mu.Unlock()
	vs := c.vs
	vs.Services = append([]ViewService(nil), c.vs.Services...)
	return vs
}

// refreshStatic recomputes everything that does not come from a test run.
// It runs inside update (under c.mu); c.diag, c.env and c.extra are written
// only by the operation goroutine.
func (c *Controller) refreshStatic(vs *ViewState) {
	a := c.a
	mode := a.state()
	vs.Bypass = Bypass{On: mode != "", Autostart: mode == "service"}
	if s, ok := a.savedStrategy(); ok && mode != "" {
		vs.Bypass.Strategy = s.Name
	}
	enabled := a.enabledServices()
	vs.Settings = SettingsView{Autostart: a.cfg.Autostart, Heal: a.cfg.Heal, Games: a.cfg.Games, Enabled: []string{}}
	vs.Catalog = make([]CatalogItem, 0, len(catalog))
	for _, s := range catalog {
		vs.Catalog = append(vs.Catalog, CatalogItem{ID: s.ID, Name: s.Name, Category: s.Category, Default: s.Default})
		if enabled[s.ID] {
			vs.Settings.Enabled = append(vs.Settings.Enabled, s.ID)
		}
	}
	vs.Versions = map[string]string{"app": version, "flowseal": a.payload.Flowseal, "goodbyedpi": a.payload.GoodbyeDPI}
	vs.Strategies = make([]StratRef, 0, len(a.strategies))
	for _, s := range a.strategies {
		vs.Strategies = append(vs.Strategies, StratRef{Key: s.Key(), Name: s.Name})
	}
	vs.ForeignDisabled = []string{}
	for name := range a.cfg.ForeignDisabled {
		vs.ForeignDisabled = append(vs.ForeignDisabled, name)
	}
	vs.ForeignDisabled = append(vs.ForeignDisabled, a.cfg.ForeignTasks...)
	vs.ForeignDisabled = append(vs.ForeignDisabled, foreignShortcutNames(a)...)
	sort.Strings(vs.ForeignDisabled)
	vs.SecureDNS = SecureDNSView{Supported: secureDNSSupported(), Active: secureDNSActive(a)}
	if a.cfg.DNSBackup != nil {
		vs.SecureDNS.Provider = a.cfg.DNSBackup.Provider
	}
	vs.DefenderExcluded = a.cfg.DefenderExcluded
	vs.Provenance = c.prov

	// Memory Integrity is on for most Windows 11 PCs: mention it only when
	// the driver actually failed to load (errors 577/1275).
	engineFailed := false
	for _, f := range c.extra {
		if f.ID == "engine-error" {
			engineFailed = true
		}
	}
	vs.Notices = make([]Finding, 0, len(c.env.Findings)+len(c.extra))
	for _, f := range c.env.Findings {
		if f.ID == "hvci" && !engineFailed {
			continue
		}
		vs.Notices = append(vs.Notices, f)
	}
	vs.Notices = append(vs.Notices, c.extra...)
	if a.cfg.LastHeal != "" && time.Since(a.cfg.LastHealAt) < 7*24*time.Hour {
		vs.Notices = append(vs.Notices, Finding{ID: "heal", Kind: "own", Level: "info",
			Title: "Автопроверка " + a.cfg.LastHealAt.Format("02.01 15:04"), Text: a.cfg.LastHeal})
	}
	vs.Services = make([]ViewService, 0, len(catalog))
	byID := catalogByID()
	for _, s := range catalog {
		if !enabled[s.ID] {
			continue
		}
		v := ViewService{ID: s.ID, Name: s.Name, Category: s.Category, State: StUnknown}
		if d, ok := c.diag[s.ID]; ok {
			v.State, v.Detail = d.State, d.Detail
			v.Fixable = d.State.Fixable() && !byID[s.ID].ProviderGeo && !byID[s.ID].NoBypass
			if s.Special == "voice" && d.State != StUnknown && d.State != StTesting {
				v.Label = upperFirst(stateText(d.State)) + " (оценка)"
			}
		}
		vs.Services = append(vs.Services, v)
	}
	// Ask before a fix only when it will actually stop another tool.
	vs.ConfirmFix = ""
	fixable := false
	for _, v := range vs.Services {
		fixable = fixable || v.Fixable
	}
	vs.ConfirmReplace = c.foreignConfirm(false)
	if fixable {
		vs.ConfirmFix = c.foreignConfirm(true)
	}
}

// foreignConfirm is the question asked before EzPzDPI stops another bypass
// tool, for a fix (search first) or a manual pick. "" when none runs.
func (c *Controller) foreignConfirm(search bool) string {
	fs := c.env.ForeignActive()
	if len(fs) == 0 || c.env.Has("vpn") {
		return ""
	}
	var names []string
	for _, f := range fs {
		names = append(names, strings.TrimPrefix(f.Title, "Найден другой обход: "))
	}
	who := strings.Join(names, " и ")
	if search {
		return "Чтобы подобрать обход, EzPzDPI остановит " + who + " на время подбора. Если вы сейчас в голосовом канале, звонок прервётся на пару секунд. " +
			"Если вариант найдётся, " + who + " будет отключён (вернуть можно в настройках). Если нет, " + who + " запустится обратно. Продолжить?"
	}
	return "EzPzDPI остановит " + who + " и включит выбранный вариант. Если вариант включится, " + who +
		" будет отключён (вернуть можно в настройках). Если нет, " + who + " запустится обратно. Продолжить?"
}

// Start scans the PC and shows the first screen. It runs as an operation so
// the crash-recovery rollback never overlaps another one.
func (c *Controller) Start() { c.run("start", func(ctx context.Context) { c.start() }) }

func (c *Controller) start() {
	c.recoverInterruptedFix()
	c.setEnv(detectEnv(c.a))
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "idle"
		n := len(vs.Services)
		privacy := " Программа подключается к проверяемым сайтам напрямую, как браузер, и ничего не отправляет авторам."
		switch {
		case vs.Bypass.On:
			vs.Verdict = Verdict{Title: "Обход включён", Text: fmt.Sprintf("Вариант %s. Нажмите «Проверить», чтобы увидеть, что сейчас открывается.", vs.Bypass.Strategy), Action: "Проверить"}
		case len(c.env.ForeignActive()) > 0:
			vs.Verdict = Verdict{Title: "Проверим, как работает ваш обход", Text: fmt.Sprintf("EzPzDPI проверит %d %s с ним. Пока вы не нажмёте «Починить», в системе ничего не меняется.", n, plural(n, "сервис", "сервиса", "сервисов")) + privacy, Action: "Проверить"}
		default:
			vs.Verdict = Verdict{Title: "Проверим, что у вас открывается", Text: fmt.Sprintf("EzPzDPI проверит %d %s, это займёт меньше минуты. Пока вы не нажмёте «Починить», в системе ничего не меняется.", n, plural(n, "сервис", "сервиса", "сервисов")) + privacy, Action: "Проверить"}
		}
	})
}

// run starts an operation in the background unless one is running.
func (c *Controller) run(name string, f func(ctx context.Context)) {
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		// Re-send the current view so controls the page changed snap back.
		go c.Republish()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.busy, c.cancel, c.done = true, cancel, make(chan struct{})
	done := c.done
	c.mu.Unlock()
	c.update(func(vs *ViewState) { vs.Busy = true })
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.a.logf("panic in %s: %v", name, r)
				c.update(func(vs *ViewState) {
					vs.Phase = "idle"
					vs.Progress = nil
					vs.Verdict = Verdict{Title: "Что-то пошло не так", Text: fmt.Sprintf("%v. Подробности в журнале.", r), Action: "Проверить снова"}
				})
			}
			c.mu.Lock()
			c.busy, c.cancel = false, nil
			c.mu.Unlock()
			c.update(func(vs *ViewState) { vs.Busy = false })
			cancel()
			close(done)
		}()
		c.a.logf("op %s start", name)
		f(ctx)
		c.a.logf("op %s end", name)
	}()
}

// Busy reports whether an operation is running.
func (c *Controller) Busy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.busy
}

// Wait blocks until the current operation finishes (console mode).
func (c *Controller) Wait() {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Main is the big button. It does what its label says: a fix only when the
// verdict offers one, otherwise a fresh check.
func (c *Controller) Main() {
	c.mu.Lock()
	busy, phase, action := c.busy, c.vs.Phase, c.vs.Verdict.Action
	c.mu.Unlock()
	wantsFix := phase == "diagnosed" && (action == "Починить" || action == "Подобрать заново")
	switch {
	case busy:
		c.Cancel()
	case wantsFix:
		c.run("pre-fix", func(ctx context.Context) {
			c.update(func(vs *ViewState) {
				vs.Verdict = Verdict{Title: "Готовлюсь к подбору", Text: "Проверяю, что работает на компьютере.", Busy: true, Calm: true, CancelLabel: cancelLabel}
			})
			c.setEnv(detectEnv(c.a))
			if c.env.Has("vpn") {
				c.update(func(vs *ViewState) {
					c.refreshStatic(vs)
					vs.Phase = "idle"
					vs.Verdict = Verdict{Title: "Сначала выключите VPN", Text: "Пока VPN включён, EzPzDPI не видит вашего провайдера и не сможет подобрать обход. Выключите VPN и нажмите «Проверить снова».", Action: "Проверить снова", Calm: true}
				})
				return
			}
			c.fix(ctx)
		})
	default:
		c.Check(false)
	}
}

// Second is the link under the big button.
func (c *Controller) Second() { c.Check(false) }

func (c *Controller) Cancel() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Shutdown is called when the window closes: abort and roll back.
func (c *Controller) Shutdown() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
}

func (c *Controller) setTesting(ids map[string]bool) {
	c.update(func(vs *ViewState) {
		for i := range vs.Services {
			if ids == nil || ids[vs.Services[i].ID] {
				vs.Services[i].State = StTesting
				vs.Services[i].Detail = ""
				vs.Services[i].Label = ""
			}
		}
	})
}

// controlTargets are Russian sites that must keep working (F05, N08). Each
// is its own pseudo-service, so one site that was already down does not
// veto every strategy.
var controlTargets = []Target{
	{Service: "_c:ya.ru", Host: "ya.ru", Path: "/"},
	{Service: "_c:vk.com", Host: "vk.com", Path: "/"},
	{Service: "_c:gosuslugi", Host: "www.gosuslugi.ru", Path: "/"},
}

func isControl(svc string) bool { return strings.HasPrefix(svc, "_c:") }

// controlsOK lists the control pseudo-services that answered.
func controlsOK(r Report) []string {
	var ok []string
	for _, p := range r.Results {
		if isControl(p.Service) && p.OK && !contains(ok, p.Service) {
			ok = append(ok, p.Service)
		}
	}
	return ok
}

// netState checks the connection itself: no internet, a Wi-Fi login page,
// a wrong clock, or mobile "whitelist" mode where only approved Russian
// sites open.
func (c *Controller) netState(ctx context.Context) (string, Report) {
	intl := []Target{
		{Service: "_intl", Host: "www.google.com", Path: "/generate_204"},
		{Service: "_intl", Host: "telegram.org", Path: "/"},
		{Service: "_intl", Host: "www.wikipedia.org", Path: "/"},
		{Service: "_intl", Host: "fsn1-speed.hetzner.com", Path: "/", UA: "Wget/1.21"},
	}
	// Same timeout as the trials, so a control site is judged the same way
	// in the baseline and in every strategy test.
	t := NewTester(ctx, append(append([]Target{}, controlTargets...), intl...))
	r := t.Run(ctx)
	ruOK, intlOK, expired := 0, 0, 0
	for _, p := range r.Results {
		if p.OK && isControl(p.Service) {
			ruOK++
		}
		if p.OK && p.Service == "_intl" {
			intlOK++
		}
		if p.CertExpired {
			expired++
		}
	}
	switch {
	case ctx.Err() != nil:
		return "cancelled", r
	case ruOK == 0 && intlOK == 0:
		switch {
		case captivePortal(ctx):
			return "portal", r
		case expired >= 3:
			return "clock", r
		case secureDNSActive(c.a) && rawIPReachable(ctx) && !systemDNSWorks(ctx):
			return "dnsbroken", r
		}
		return "offline", r
	case expired >= 3:
		return "clock", r
	case intlOK == 0:
		return "whitelist", r
	}
	return "ok", r
}

func (c *Controller) showNet(state string) {
	if state == "dnsbroken" { // kept in extra so later refreshes keep the button
		c.mu.Lock()
		c.extra = append(removeFinding(c.extra, "dns-broken"), Finding{ID: "dns-broken", Kind: "dns", Level: "error", Active: true, Title: "DNS не работает",
			Text: "Вернуть настройки DNS, которые были до EzPzDPI?", Acts: []Action{{ID: "dns-revert", Label: "Вернуть прежний DNS"}}})
		c.mu.Unlock()
	}
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "idle"
		vs.Progress = nil
		for i := range vs.Services {
			vs.Services[i].State = StOffline
			vs.Services[i].Detail = ""
		}
		switch state {
		case "dnsbroken":
			vs.Verdict = Verdict{Title: "Защищённый DNS не отвечает", Text: "EzPzDPI включал защищённый DNS, но в этой сети он не работает, поэтому сайты не открываются. Верните прежние настройки DNS кнопкой в сообщении выше.", Action: "Проверить снова"}
		case "portal":
			vs.Verdict = Verdict{Title: "Нужно войти в сеть Wi-Fi", Text: "Эта сеть просит войти через страницу в браузере (как в кафе или гостинице). Откройте любой сайт в браузере, войдите и нажмите «Проверить снова».", Action: "Проверить снова"}
		case "clock":
			vs.Verdict = Verdict{Title: "На компьютере неверное время", Text: "Из-за этого не открываются защищённые сайты. Включите «Установить время автоматически» в настройках Windows и нажмите «Проверить снова».", Action: "Проверить снова"}
		case "whitelist":
			vs.Verdict = Verdict{Title: "Похоже, включены белые списки", Text: "Открываются только разрешённые российские сайты, все зарубежные адреса недоступны. Так бывает на мобильном интернете во время ограничений. Обход здесь не поможет: на домашнем интернете или Wi-Fi всё должно работать как раньше.", Action: "Проверить снова"}
		default:
			vs.Verdict = Verdict{Title: "Нет интернета", Text: "Не открываются даже ya.ru и vk.com: дело не в блокировках. Проверьте Wi-Fi или кабель и нажмите «Проверить снова».", Action: "Проверить снова"}
		}
	})
}

// diagnoseAll runs the full diagnosis for the enabled services. The voice
// estimate runs at the same time as the web checks.
func (c *Controller) diagnoseAll(ctx context.Context, soak time.Duration) (map[string]Diagnosis, *Tester, Report) {
	enabled := c.a.enabledServices()
	var voice *VoiceResult
	var wg sync.WaitGroup
	if enabled["voice"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := voiceBurst(ctx, 15)
			// A soak only makes sense when calls connect at all.
			if soak > 0 && ctx.Err() == nil && v.State != StBlocked && v.State != StUnknown {
				v.Soak = voiceSoak(ctx, soak)
				v.State, v.Detail = classifyVoice(v)
			}
			voice = &v
		}()
	}
	t := NewTester(ctx, append(allTargets(enabled), speedTarget))
	t.Neutral = true
	r := t.Run(ctx)
	if ctx.Err() == nil && t.RecheckSpoofed(ctx, r) {
		r = t.Run(ctx)
	}
	wg.Wait()
	out := map[string]Diagnosis{}
	for i := range catalog {
		s := &catalog[i]
		if enabled[s.ID] && len(s.Targets) > 0 {
			out[s.ID] = Diagnose(s, r)
		}
	}
	if voice != nil {
		d := Diagnosis{ID: "voice", State: voice.State, Detail: voice.Detail}
		if f, ok := c.env.Find("av"); ok && f.Data["adguard"] == "1" {
			d.Detail = joinSentences(d.Detail, "Оценка неточна, пока работает AdGuard: он фильтрует трафик звонков.")
		}
		if s := catalogByID()["voice"]; s != nil && s.Note != "" {
			d.Detail = joinSentences(d.Detail, s.Note)
		}
		out["voice"] = d
	}
	c.noteProbeFindings(r)
	return out, t, r
}

// noteProbeFindings turns things the probes noticed into notices.
func (c *Controller) noteProbeFindings(r Report) {
	var extra []Finding
	dns, av := false, ""
	for _, p := range r.Results {
		if p.DNSSpoofed {
			dns = true
		}
		if p.AVIntercept && av == "" {
			av = p.Issuer
		}
	}
	if dns {
		f := Finding{ID: "dns", Kind: "dns", Level: "warn", Active: true, Title: "Провайдер не отдаёт адреса части сайтов"}
		if secureDNSActive(c.a) {
			f.Level = "info"
			f.Text = "Защищённый DNS в Windows включён, но браузер может использовать свой. В Chrome, Edge и Яндекс Браузере: Настройки → Конфиденциальность → Использовать безопасный DNS."
		} else if secureDNSSupported() {
			f.Text = "Такие сайты не откроются, даже если обход работает. Защищённый DNS получает настоящие адреса в обход провайдера. EzPzDPI может включить его в Windows и вернуть как было одной кнопкой."
			f.Acts = []Action{{ID: "dns-secure", Label: "Включить защищённый DNS", Confirm: "EzPzDPI переключит DNS этого подключения на защищённый (зашифрованный) сервер. Если в вашей сети есть внутренние сайты (работа, учёба) или детский фильтр DNS, они перестанут работать. Вернуть можно в настройках. Продолжить?"}}
		} else {
			f.Text = "Включите защищённый DNS в браузере: Chrome, Edge или Яндекс Браузер → Настройки → Конфиденциальность → Использовать безопасный DNS → Cloudflare или Google. В Firefox: «DNS через HTTPS»."
		}
		for _, ff := range c.env.Foreign() {
			if ff.Data["dns_redirect"] == "1" {
				f.Text += " GoodbyeDPI на этом компьютере перенаправляет DNS, поэтому этот вывод может быть неточным."
			}
		}
		extra = append(extra, f)
	}
	if av != "" {
		extra = append(extra, Finding{ID: "av-https", Kind: "av", Level: "info", Title: "Антивирус проверяет защищённые соединения",
			Text: "Сертификаты сайтов выдаёт антивирус (" + av + "). Проверка учла это, но обход может не работать для сайтов, которые антивирус пропускает через себя. Если сайты не откроются, отключите в антивирусе проверку защищённых соединений или добавьте discord.com и youtube.com в доверенные адреса."})
	}
	c.mu.Lock()
	keep := make([]Finding, 0, len(c.extra))
	for _, f := range c.extra {
		if f.ID != "dns" && f.ID != "av-https" {
			keep = append(keep, f)
		}
	}
	c.extra = append(keep, extra...)
	c.mu.Unlock()
}

func (c *Controller) provenance(withoutForeign bool) string {
	switch {
	case c.env.Has("vpn"):
		return provVPN
	case len(c.env.ForeignActive()) > 0 && !withoutForeign:
		return provForeign
	case c.a.state() != "":
		return provOurs
	}
	return provDirect
}

// Check shows what works right now (with whatever bypass is running), or,
// with withoutForeign, pauses other bypass tools to show the raw state.
func (c *Controller) Check(withoutForeign bool) {
	c.run("check", func(ctx context.Context) {
		c.setEnv(detectEnv(c.a))
		c.prov = c.provenance(withoutForeign)
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "checking"
			vs.Progress = nil
			vs.Verdict = Verdict{Title: "Проверяю", Text: "Это займёт меньше минуты.", Action: "Остановить", Calm: true, Busy: true, CancelLabel: cancelLabel}
		})
		c.setTesting(nil)
		if withoutForeign {
			resume := pauseForeign(c.a, c.env.ForeignActive())
			defer func() {
				resume()
				c.setEnv(detectEnv(c.a))
				c.push()
			}()
		}
		switch st, _ := c.netState(ctx); st {
		case "ok":
		case "cancelled":
			c.cancelled("Проверка остановлена.")
			return
		default:
			c.showNet(st)
			return
		}
		diag, t, _ := c.diagnoseAll(ctx, 12*time.Second)
		if ctx.Err() != nil {
			c.cancelled("Проверка остановлена.")
			return
		}
		ourOn := c.a.state() != ""
		if ourOn {
			for _, id := range c.a.cfg.Fixed {
				if d, ok := diag[id]; ok && d.State == StWorks {
					d.State = StFixed
					diag[id] = d
				}
			}
		}
		foreign := len(c.env.ForeignActive()) > 0 && !withoutForeign
		if !ourOn && !foreign && !c.env.Has("vpn") {
			c.baseline = diag
		}
		c.mu.Lock()
		c.diag = diag
		c.mu.Unlock()
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "diagnosed"
			vs.Verdict = summarize(vs.Services, ourOn, foreign, c.env.Has("vpn"), t.DNSTrouble())
		})
	})
}

func (c *Controller) cancelled(text string) {
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "idle"
		vs.Progress = nil
		vs.Verdict = Verdict{Title: "Остановлено", Text: text, Action: "Проверить"}
	})
}

// summarize writes the verdict for a finished diagnosis.
func summarize(svcs []ViewService, ourOn, foreign, vpn, dns bool) Verdict {
	var fix, ip, geo, dnsList, part, broken []string
	for _, s := range svcs {
		switch {
		case s.Fixable:
			fix = append(fix, s.Name)
		case s.State == StIPBlock:
			ip = append(ip, s.Name)
		case s.State == StGeo:
			geo = append(geo, s.Name)
		case s.State == StDNS:
			dnsList = append(dnsList, s.Name)
		case s.State == StPartial:
			part = append(part, s.Name)
		}
		if s.State.Broken() && s.State != StGeo {
			broken = append(broken, s.Name)
		}
	}
	n := len(svcs)
	if len(broken) == 0 {
		v := Verdict{Title: "Всё открывается", Action: "Проверить снова", Calm: true}
		switch {
		case vpn:
			v.Text = "Через включённый VPN всё работает. Чтобы увидеть, что блокирует провайдер, выключите VPN и проверьте снова."
		case ourOn:
			v.Text = "Обход включён и работает."
		case foreign:
			v.Text = "Ваш текущий обход справляется. Если голос или видео обрываются, нажмите «Проверить без него» в сообщении выше: EzPzDPI покажет, что можно улучшить."
		default:
			v.Text = "Обход не нужен. Если что-то перестанет открываться, нажмите «Проверить снова»."
		}
		if len(part) > 0 {
			v.Text += " Частично работают: " + joinNames(part) + "."
		}
		if len(geo) > 0 {
			v.Text += " " + joinNames(geo) + pluralVerb(len(geo), " сам не работает", " сами не работают") + " с Россией, это не блокировка."
		}
		return v
	}
	v := Verdict{Title: fmt.Sprintf("Не работают %d из %d", len(broken), n)}
	switch {
	case vpn:
		v.Title = fmt.Sprintf("Через VPN не работают %d из %d", len(broken), n)
	case foreign:
		v.Title = fmt.Sprintf("С вашим обходом не работают %d из %d", len(broken), n)
	case ourOn:
		v.Title = fmt.Sprintf("С обходом не работают %d из %d", len(broken), n)
	}
	var parts []string
	if len(fix) > 0 {
		parts = append(parts, "Обход должен починить "+joinNames(fix)+".")
	}
	if len(ip) > 0 {
		parts = append(parts, joinNames(ip)+": провайдер блокирует адрес целиком, тут скорее нужен VPN.")
	}
	if len(dnsList) > 0 || dns {
		parts = append(parts, "Провайдер не отдаёт адреса части сайтов: включите защищённый DNS (кнопка в сообщении выше).")
	}
	if len(geo) > 0 {
		parts = append(parts, joinNames(geo)+pluralVerb(len(geo), " сам не работает", " сами не работают")+" с Россией.")
	}
	v.Text = strings.Join(parts, " ")
	if len(fix) > 0 {
		v.Action, v.Second = "Починить", "Проверить снова"
		if ourOn {
			v.Action = "Подобрать заново"
		}
	} else {
		v.Action, v.Calm = "Проверить снова", true
	}
	return v
}

// fixMarker is written while a fix runs, so an interrupted fix (crash,
// power loss) can be rolled back at the next start (F08).
type fixMarker struct {
	Mode   string        `json:"mode"`
	Key    string        `json:"key"`
	Paused PausedForeign `json:"paused"` // other tools stopped for the search
	At     time.Time     `json:"at"`
}

func (c *Controller) markerPath() string { return filepath.Join(c.a.dataDir, "fix.marker") }

func (c *Controller) writeMarker(m fixMarker) {
	data, _ := json.Marshal(m)
	_ = os.WriteFile(c.markerPath(), data, 0o644)
	c.mu.Lock()
	c.pending = &m
	c.mu.Unlock()
}

func (c *Controller) clearMarker() {
	_ = os.Remove(c.markerPath())
	c.mu.Lock()
	c.pending = nil
	c.mu.Unlock()
}

func (c *Controller) recoverInterruptedFix() {
	data, err := os.ReadFile(c.markerPath())
	if err != nil {
		return
	}
	var m fixMarker
	if json.Unmarshal(data, &m) == nil {
		c.a.logf("interrupted fix from %s: rolling back", m.At.Format(time.RFC3339))
		if err := c.rollback(m); err != nil {
			c.a.logf("recovery: %v", err)
		}
		c.extra = append(c.extra, Finding{ID: "fix-interrupted", Kind: "own", Level: "info", Title: "Прошлый подбор прервался",
			Text: "Всё вернули как было до него. Нажмите «Проверить», а затем «Починить», чтобы подобрать обход заново."})
	}
	c.clearMarker()
}

// Fix stops every bypass, measures the raw state, tests strategies and
// enables the best one. Any abort restores what ran before.
func (c *Controller) Fix() {
	c.run("fix", func(ctx context.Context) { c.fix(ctx) })
}

func (c *Controller) fix(ctx context.Context) {
	a := c.a
	prev := a.capture()
	c.setEnv(detectEnv(a))
	foreign := c.env.ForeignActive()
	marker := fixMarker{Mode: prev.mode, Key: prev.key, At: time.Now()}
	c.writeMarker(marker) // written before anything stops, updated below
	ok, rolled := false, false
	defer func() {
		if !ok && !rolled {
			if err := c.rollback(marker); err != nil {
				c.note("Прежний обход вернуть не удалось", err.Error()+". Запустите его вручную или откройте настройки EzPzDPI.")
			}
			c.setEnv(detectEnv(a))
			c.push()
		}
		c.clearMarker()
	}()

	c.prov = provDirect
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "fixing"
		vs.Progress = nil
		vs.Verdict = Verdict{Title: "Проверяю без обхода", Text: "Сначала нужно увидеть, что блокирует провайдер.", Action: "Остановить", Calm: true, Busy: true, CancelLabel: cancelLabel}
	})
	if ctx.Err() != nil {
		c.cancelled("Подбор отменён.")
		return
	}
	// Other tools are only paused for the search (their exact command lines
	// are kept in the marker); they are disabled for good only after the
	// winner passes the final check.
	if len(foreign) > 0 {
		marker.Paused = pauseForeignState(a, foreign)
		c.writeMarker(marker)
	}
	a.stopAll()
	c.setTesting(nil)
	st, netR := c.netState(ctx)
	switch st {
	case "ok":
	case "cancelled":
		c.cancelled("Подбор отменён, всё вернули как было.")
		return
	default:
		c.showNet(st)
		return
	}
	baseControls := controlsOK(netR)
	base, t, _ := c.diagnoseAll(ctx, 0)
	if ctx.Err() != nil {
		c.cancelled("Подбор отменён, всё вернули как было.")
		return
	}
	c.mu.Lock()
	c.baseline, c.diag = base, base
	c.mu.Unlock()

	var want, must, keep []string
	for _, s := range catalog {
		d, okd := base[s.ID]
		if !okd {
			continue
		}
		if s.ProviderGeo || s.NoBypass || d.State == StDNS {
			// Not ours to fix, but a strategy must not make them worse.
			if d.Reachable {
				keep = append(keep, s.ID)
			}
			continue
		}
		switch d.State {
		case StBlocked, StThrottled:
			want, must = append(want, s.ID), append(must, s.ID)
		case StIPBlock:
			want = append(want, s.ID) // rarely fixable, but a strategy that fixes it wins
		case StPartial:
			if s.ID == "voice" {
				want, must = append(want, s.ID), append(must, s.ID)
			} else {
				keep = append(keep, s.ID)
			}
		case StWorks:
			keep = append(keep, s.ID)
		}
	}
	keep = append(keep, baseControls...)
	if len(must) == 0 {
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "idle"
			vs.Verdict = summarize(vs.Services, false, false, false, t.DNSTrouble())
			if vs.Verdict.Action == "Починить" {
				vs.Verdict.Action, vs.Verdict.Second = "Проверить снова", ""
			}
			vs.Verdict.Text = strings.TrimSpace("Обход здесь ничего не исправит. " + vs.Verdict.Text)
		})
		return
	}

	inTest := map[string]bool{speedTarget.Service: true}
	for _, id := range append(append([]string{}, want...), keep...) {
		inTest[id] = true
	}
	tt := t.Subset(func(tg Target) bool { return inTest[tg.Service] })
	for _, ct := range controlTargets {
		if inTest[ct.Service] {
			tt.Targets = append(tt.Targets, ct)
		}
	}
	tt.Merge(NewTester(ctx, controlTargets)) // resolve the control hosts too
	tt.Neutral = false
	voiceWanted := contains(want, "voice") || contains(keep, "voice")

	winner, _, err := c.search(ctx, tt, want, must, keep, voiceWanted)
	if ctx.Err() != nil {
		c.cancelled("Подбор отменён, всё вернули как было.")
		return
	}
	if winner == nil {
		msg := "Ни один из вариантов не открыл " + joinNames(namesOf(must)) + ". Обновите варианты обхода в настройках и попробуйте снова. Если не поможет, провайдер блокирует по адресу и нужен VPN."
		if err != nil {
			msg = err.Error()
			c.noteEngineError(err)
		}
		rolled = true
		rbErr := c.rollback(marker)
		c.setEnv(detectEnv(a))
		if len(marker.Paused.Services)+len(marker.Paused.Procs) > 0 {
			if rbErr == nil {
				msg += " Ваш прежний обход запущен обратно."
			} else {
				msg += " Прежний обход вернуть не удалось: " + rbErr.Error() + "."
			}
		}
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "idle"
			vs.Progress = nil
			vs.Verdict = Verdict{Title: "Обход не помог", Text: msg, Action: "Проверить снова", Calm: true}
		})
		return
	}

	c.update(func(vs *ViewState) {
		vs.Progress = nil
		vs.Verdict = Verdict{Title: "Включаю обход", Text: "Вариант " + winner.Name + ".", Busy: true, Calm: true}
	})
	mode, err := a.enable(*winner)
	if err != nil {
		c.noteEngineError(err)
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "diagnosed"
			vs.Phase = "idle"
			vs.Verdict = Verdict{Title: "Не удалось включить обход", Text: err.Error(), Action: "Проверить снова", Calm: true}
		})
		return
	}

	// Final check with the bypass on (F06): ordinary Russian sites must still
	// work, otherwise switch it off again.
	c.setTesting(nil)
	after, _, _ := c.diagnoseAll(ctx, 20*time.Second)
	ctlR := NewTester(ctx, controlTargets).Run(ctx)
	if ctx.Err() != nil {
		c.cancelled("Подбор отменён, всё вернули как было.")
		return
	}
	if lost := missing(baseControls, controlsOK(ctlR)); len(lost) > 0 {
		a.logf("winner %s broke control sites %v: %s", winner.Name, lost, shortFailure(ctlR))
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "idle"
			vs.Verdict = Verdict{Title: "Вариант сломал обычные сайты", Text: "С ним перестали открываться российские сайты (" + shortFailure(ctlR) + "), поэтому EzPzDPI всё вернул как было. Обновите варианты обхода в настройках и попробуйте снова.", Action: "Проверить снова", Calm: true}
		})
		return
	}
	ok = true
	var fixed []string
	for id, d := range after {
		b, okb := base[id]
		if !okb {
			continue
		}
		if (b.State.Broken() || (id == "voice" && b.State == StPartial)) && d.State == StWorks {
			d.State = StFixed
			after[id] = d
			fixed = append(fixed, id)
		}
	}
	// The winner holds: now retire the tools that were only paused.
	for _, f := range foreign {
		if err := disableForeign(a, f); err != nil {
			a.logf("disable foreign %s: %v", f.ID, err)
		}
	}
	a.cfg.Strategy, a.cfg.PickedAt, a.cfg.Fixed, a.cfg.Off = winner.Key(), time.Now(), fixed, false
	a.saveConfig()
	c.install()
	c.mu.Lock()
	c.diag = after
	c.mu.Unlock()
	c.setEnv(detectEnv(a))
	c.prov = provOurs
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "fixed"
		vs.Progress = nil
		vs.Verdict = fixedVerdict(vs.Services, must, mode)
	})
}

// noteEngineError attaches the button that fixes a known engine failure
// (X01): BFE stopped, antivirus removed files, a foreign driver in memory.
func (c *Controller) noteEngineError(err error) {
	var ee *EngineError
	if !errors.As(err, &ee) {
		return
	}
	code, ok := engineLogCode(ee.Line)
	if !ok {
		return
	}
	f := Finding{ID: "engine-error", Kind: "system", Level: "error", Active: true,
		Title: "Программа обхода не запускается", Text: ee.Error()}
	switch code {
	case 1753:
		f.Acts = []Action{{ID: "bfe-on", Label: "Включить службу базовой фильтрации"}}
	case 2, 5, 225:
		f.Acts = []Action{{ID: "defender-exclude", Label: "Добавить EzPzDPI в исключения Защитника"}}
	case 654:
		f.Acts = []Action{{ID: "recheck", Label: "Проверить снова"}}
	}
	c.mu.Lock()
	c.extra = append(removeFinding(c.extra, "engine-error"), f)
	c.mu.Unlock()
}

// install copies the app into the data folder and registers the Start menu
// entry, the uninstall entry and the logon check (P09).
func (c *Controller) install() {
	a := c.a
	if err := a.installSelf(); err != nil {
		a.logf("install self: %v", err)
		return
	}
	if !a.cfg.Installed {
		if err := installEntries(a); err != nil {
			a.logf("install entries: %v", err)
		} else {
			a.cfg.Installed = true
			a.saveConfig()
		}
	}
	if err := a.syncHealTask(); err != nil {
		a.logf("heal task: %v", err)
	}
}

// search tests strategies in order. It stops at the first one that fixes
// every must-fix service without breaking working ones, confirmed by a
// second run; otherwise it re-checks the best few and returns the leader.
func (c *Controller) search(ctx context.Context, t *Tester, want, must, keep []string, voice bool) (*Strategy, TrialScore, error) {
	a := c.a
	type cand struct {
		s  Strategy
		sc TrialScore
	}
	var cands []cand
	var lastErr error
	strats := c.orderedStrategies()
	n := len(strats)
	fixedSoFar := map[string]bool{}
	started := time.Now()
	var extra func(context.Context) []ProbeResult
	if voice { // measured while the strategy's engine is still running
		extra = func(ctx context.Context) []ProbeResult {
			v := voiceBurst(ctx, 10)
			return []ProbeResult{{Target: Target{Service: "voice"}, OK: voiceOK(v)}}
		}
	}
	trial := func(s Strategy) (TrialScore, error) {
		r, err := a.runTrial(ctx, s, t, extra)
		if err != nil {
			return TrialScore{}, err
		}
		return ScoreTrial(r, want, keep), nil
	}
	for i, s := range strats {
		if ctx.Err() != nil {
			return nil, TrialScore{}, ctx.Err()
		}
		eta := 0
		if i > 0 {
			eta = int(time.Since(started).Seconds() / float64(i) * float64(n-i))
		}
		c.update(func(vs *ViewState) {
			vs.Progress = &Progress{I: i, N: n, ETASec: eta}
			vs.Verdict = Verdict{Title: "Подбираю обход", Text: fmt.Sprintf("Пробую вариант %d из %d. %s Окно можно свернуть.", i+1, n, etaText(eta)), Action: "Остановить", Calm: true, Busy: true, CancelLabel: cancelLabel}
			for j := range vs.Services {
				id := vs.Services[j].ID
				if contains(want, id) && !fixedSoFar[id] {
					vs.Services[j].State = StTesting
				}
			}
		})
		sc, err := trial(s)
		if err != nil {
			if ctx.Err() != nil {
				return nil, TrialScore{}, ctx.Err()
			}
			var ee *EngineError
			if errors.As(err, &ee) && ee.Advice != "" {
				lastErr = err
			}
			a.logf("trial %s: %v", s.Name, err)
			continue
		}
		a.logf("trial %s: fixed %d/%d broke %d latency %v", s.Name, sc.Fixed, len(want), sc.Broke, sc.Latency)
		cands = append(cands, cand{s, sc})
		c.update(func(vs *ViewState) {
			for j := range vs.Services {
				id := vs.Services[j].ID
				if sc.Services[id] && contains(want, id) {
					fixedSoFar[id] = true
					vs.Services[j].State = StFixed
				}
			}
		})
		if coversAll(sc, must) && sc.Broke == 0 {
			if sc2, err := trial(s); err == nil && coversAll(sc2, must) && sc2.Broke == 0 {
				return &s, sc2, nil
			}
		}
	}
	if len(cands) == 0 {
		return nil, TrialScore{}, lastErr
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].sc.Better(cands[j].sc) })
	for i := 0; i < len(cands) && i < 3; i++ {
		cd := cands[i]
		if cd.sc.Fixed == 0 || cd.sc.Broke > 0 {
			continue
		}
		c.update(func(vs *ViewState) {
			vs.Verdict = Verdict{Title: "Перепроверяю лучший вариант", Text: cd.s.Name, Action: "Остановить", Calm: true, Busy: true, CancelLabel: cancelLabel}
		})
		if sc2, err := trial(cd.s); err == nil && sc2.Fixed >= cd.sc.Fixed && sc2.Broke == 0 {
			return &cd.s, sc2, nil
		}
	}
	return nil, TrialScore{}, lastErr
}

// orderedStrategies puts the strategy a foreign Flowseal install used first:
// it is the user's known baseline and often a good fit for their ISP.
func (c *Controller) orderedStrategies() []Strategy {
	var first string
	for _, f := range c.env.Foreign() {
		if s := f.Data["strategy"]; s != "" {
			first = s
		}
	}
	out := make([]Strategy, 0, len(c.a.strategies))
	for _, s := range c.a.strategies {
		if s.Engine == EngineZapret && s.Name == first {
			out = append([]Strategy{s}, out...)
		} else {
			out = append(out, s)
		}
	}
	return out
}

func etaText(sec int) string {
	switch {
	case sec <= 0:
		return "Обычно хватает 1–4 минут."
	case sec < 60:
		return "Осталось меньше минуты."
	}
	m := (sec + 30) / 60
	return fmt.Sprintf("Осталось примерно %d %s.", m, plural(m, "минута", "минуты", "минут"))
}

func coversAll(sc TrialScore, ids []string) bool {
	for _, id := range ids {
		if !sc.Services[id] {
			return false
		}
	}
	return true
}

// rollback brings back what ran before a failed or aborted fix: the other
// tools paused for the search (with their original command lines) and our
// own previous bypass.
func (c *Controller) rollback(m fixMarker) error {
	a := c.a
	a.killTrial()
	a.stopAll()
	var errs []error
	if len(m.Paused.Services)+len(m.Paused.Procs) > 0 {
		if err := resumeForeignState(a, m.Paused); err != nil {
			a.logf("rollback foreign: %v", err)
			errs = append(errs, err)
		}
	}
	if m.Mode != "" {
		if err := a.restore(prevState{mode: m.Mode, key: m.Key}); err != nil {
			a.logf("rollback restore: %v", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func fixedVerdict(svcs []ViewService, must []string, mode string) Verdict {
	var fixed, failed, ip []string
	view := map[string]ViewService{}
	for _, s := range svcs {
		view[s.ID] = s
		if s.State == StIPBlock {
			ip = append(ip, s.Name)
		}
	}
	for _, id := range must {
		if s, ok := view[id]; ok {
			if s.State == StFixed || s.State == StWorks {
				fixed = append(fixed, s.Name)
			} else {
				failed = append(failed, s.Name)
			}
		}
	}
	v := Verdict{Title: fmt.Sprintf("Починено %d из %d", len(fixed), len(must)), Action: "Проверить снова", Calm: true}
	if mode == "service" {
		v.Text = "Обход включён и будет запускаться вместе с Windows."
	} else {
		v.Text = "Обход включён до перезагрузки."
	}
	v.Text += " Полностью закройте браузер и Discord (в трее «Выйти») и откройте снова, чтобы изменения применились."
	if len(failed) > 0 {
		v.Text += " Не удалось починить: " + joinNames(failed) + "."
	}
	if len(ip) > 0 {
		v.Text += " Для " + joinNames(ip) + " нужен VPN."
	}
	return v
}

// Stop switches our bypass off.
func (c *Controller) Stop() {
	c.run("stop", func(ctx context.Context) {
		c.a.stopAll()
		c.a.cfg.Off = true // the logon check must not switch it back on
		c.a.saveConfig()
		if err := c.a.syncHealTask(); err != nil {
			c.a.logf("heal task: %v", err)
		}
		c.mu.Lock()
		c.diag = map[string]Diagnosis{}
		c.mu.Unlock()
		c.prov = ""
		c.setEnv(detectEnv(c.a))
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "idle"
			vs.Progress = nil
			vs.Verdict = Verdict{Title: "Обход выключен", Text: "Нажмите «Проверить», чтобы увидеть, что открывается без него.", Action: "Проверить"}
		})
	})
}

// Action handles notice buttons.
func (c *Controller) Action(notice, action string) {
	a := c.a
	simple := func(name string, f func() error, okTitle, okText string) {
		c.run(name, func(ctx context.Context) {
			err := f()
			c.setEnv(detectEnv(a))
			if err != nil {
				c.note("Не получилось", err.Error())
				return
			}
			c.note(okTitle, okText)
		})
	}
	switch action {
	case "check-without":
		c.Check(true)
	case "recheck":
		c.Check(false)
	case "disable-foreign":
		f, ok := c.getEnv().Find(notice)
		if !ok {
			return
		}
		simple("disable-foreign", func() error { return disableForeign(a, f) },
			"Прежний обход отключён", "Он не удалён: вернуть его можно в настройках («Вернуть прежний обход»). Нажмите «Проверить», а затем «Починить».")
	case "restart-own":
		simple("restart-own", func() error {
			s, ok := a.savedStrategy()
			if !ok {
				return errors.New("сохранённого варианта нет, нажмите «Проверить» и «Починить»")
			}
			if _, err := a.enable(s); err != nil {
				return err
			}
			a.cfg.Off = false
			a.saveConfig()
			return a.syncHealTask()
		}, "Обход снова включён", "Нажмите «Проверить», чтобы убедиться, что всё работает.")
	case "clean-hosts":
		c.run("clean-hosts", func(ctx context.Context) {
			backup, err := cleanHosts(a)
			c.setEnv(detectEnv(a))
			if err != nil {
				c.note("Не удалось изменить hosts", err.Error())
				return
			}
			c.note("Записи отключены", "Они закомментированы, а копия прежнего файла сохранена: "+backup+". Нажмите «Проверить снова».")
		})
	case "remove-leftovers":
		f, ok := c.getEnv().Find(notice)
		if !ok {
			return
		}
		simple("remove-leftovers", func() error { return removeLeftovers(a, f) }, "Остатки убраны", "Нажмите «Проверить снова».")
	case "proxy-off":
		simple("proxy-off", func() error { return proxyOff(a) }, "Прокси выключен", "Браузер снова ходит напрямую. Вернуть прокси можно при удалении EzPzDPI.")
	case "bfe-on":
		simple("bfe-on", func() error { return startBFE(a) }, "Служба базовой фильтрации включена", "Нажмите «Проверить», а затем «Починить».")
	case "defender-exclude":
		c.Defender(true)
	case "dns-secure":
		c.SecureDNS(true)
	case "dns-revert":
		c.SecureDNS(false)
	case "restore-foreign":
		c.RestoreForeign()
	}
}

// note shows a one-off message in the verdict area.
func (c *Controller) note(title, text string) {
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Verdict = Verdict{Title: title, Text: text, Action: "Проверить", Calm: true}
		vs.Phase = "idle"
		vs.Progress = nil
	})
}

// Settings applies the settings sheet.
func (c *Controller) Settings(s SettingsView) {
	c.run("settings", func(ctx context.Context) {
		a := c.a
		before := a.enabledServices()
		modeChanged := s.Autostart != a.cfg.Autostart
		gamesChanged := s.Games != a.cfg.Games
		a.cfg.Autostart, a.cfg.Heal, a.cfg.Games = s.Autostart, s.Heal, s.Games
		on := map[string]bool{}
		for _, id := range s.Enabled {
			on[id] = true
		}
		a.cfg.Toggles = map[string]bool{}
		for _, svc := range catalog {
			if on[svc.ID] != svc.Default {
				a.cfg.Toggles[svc.ID] = on[svc.ID]
			}
		}
		a.saveConfig()
		listsChanged := !sameKeys(before, a.enabledServices())
		if gamesChanged || listsChanged {
			_ = a.writeExtraList()
			a.loadStrategies()
		}
		if a.state() != "" && (modeChanged || gamesChanged || listsChanged) {
			if st, ok := a.savedStrategy(); ok {
				if _, err := a.enable(st); err != nil {
					c.note("Не удалось применить настройки", err.Error())
					return
				}
			}
		}
		if err := a.syncHealTask(); err != nil {
			a.logf("heal task: %v", err)
		}
		c.push()
	})
}

// Manual enables a strategy the user picked and checks the result. Other
// tools are paused first and come back if the variant does not start.
func (c *Controller) Manual(key string) {
	if key == "" {
		return
	}
	c.run("manual", func(ctx context.Context) {
		a := c.a
		s, ok := a.strategyByKey(key)
		if !ok {
			return
		}
		c.update(func(vs *ViewState) {
			vs.Verdict = Verdict{Title: "Включаю " + s.Name, Busy: true, Calm: true, CancelLabel: "Отменить и вернуть как было"}
		})
		prev := a.capture()
		c.setEnv(detectEnv(a))
		foreign := c.env.ForeignActive()
		var paused PausedForeign
		if len(foreign) > 0 {
			paused = pauseForeignState(a, foreign)
		}
		mode, err := a.enable(s)
		if err == nil && ctx.Err() != nil {
			err = errors.New("отменено")
		}
		if err != nil {
			_ = c.rollback(fixMarker{Mode: prev.mode, Key: prev.key, Paused: paused})
			c.noteEngineError(err)
			c.setEnv(detectEnv(a))
			c.note("Не удалось включить", err.Error()+" Прежнее состояние восстановлено.")
			return
		}
		for _, f := range foreign {
			_ = disableForeign(a, f)
		}
		a.cfg.Strategy, a.cfg.PickedAt, a.cfg.Off = s.Key(), time.Now(), false
		a.saveConfig()
		c.install()
		c.setTesting(nil)
		c.prov = provOurs
		diag, _, _ := c.diagnoseAll(ctx, 12*time.Second)
		if ctx.Err() != nil {
			c.cancelled("Вариант " + s.Name + " включён, проверка остановлена.")
			return
		}
		var fixed []string
		for id, d := range diag {
			if b, okb := c.baseline[id]; okb && b.State.Broken() && d.State == StWorks {
				d.State = StFixed
				diag[id] = d
				fixed = append(fixed, id)
			}
		}
		if len(c.baseline) > 0 {
			a.cfg.Fixed = fixed
			a.saveConfig()
		}
		c.mu.Lock()
		c.diag = diag
		c.mu.Unlock()
		c.setEnv(detectEnv(a))
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "diagnosed"
			v := summarize(vs.Services, true, false, false, false)
			if mode == "session" {
				v.Text += " Обход включён до перезагрузки."
			}
			vs.Verdict = v
		})
	})
}

// Update fetches the newest Flowseal strategies.
func (c *Controller) Update() {
	c.run("update", func(ctx context.Context) {
		c.update(func(vs *ViewState) {
			vs.Verdict = Verdict{Title: "Обновляю варианты обхода", Text: "Скачиваю последний набор Flowseal с GitHub.", Busy: true, Calm: true}
		})
		uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		tag, n, err := c.a.update(uctx)
		switch {
		case err != nil:
			c.note("Обновить не удалось", err.Error())
		case n == 0:
			c.note("Обновлять нечего", "У вас последняя версия набора Flowseal: "+tag+".")
		default:
			c.note("Варианты обновлены", fmt.Sprintf("Набор Flowseal %s, %d вариантов. Нажмите «Проверить», а затем «Починить», чтобы подобрать вариант заново.", tag, n))
		}
	})
}

// SecureDNS turns Windows encrypted DNS on or reverts it (N05).
func (c *Controller) SecureDNS(enable bool) {
	c.run("secure-dns", func(ctx context.Context) {
		a := c.a
		if !enable {
			if err := revertSecureDNS(a); err != nil {
				c.note("Не удалось вернуть DNS", err.Error())
				return
			}
			c.mu.Lock()
			c.extra = removeFinding(c.extra, "dns-broken")
			c.mu.Unlock()
			c.note("DNS вернули как было", "Нажмите «Проверить снова».")
			return
		}
		c.update(func(vs *ViewState) {
			vs.Verdict = Verdict{Title: "Включаю защищённый DNS", Text: "Проверяю, какой сервер работает в вашей сети.", Busy: true, Calm: true}
		})
		dctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		provider, err := enableSecureDNS(dctx, a)
		if err != nil {
			c.note("Защищённый DNS не включился", err.Error())
			return
		}
		c.mu.Lock()
		c.extra = removeFinding(c.extra, "dns")
		c.mu.Unlock()
		c.note("Защищённый DNS включён", "Сервер: "+provider+". Закройте браузер полностью и откройте снова. Вернуть как было можно в настройках.")
	})
}

// Defender adds or removes the antivirus exclusion for the data folder.
func (c *Controller) Defender(enable bool) {
	c.run("defender", func(ctx context.Context) {
		a := c.a
		if !enable {
			if err := removeDefenderExclusion(a); err != nil {
				c.note("Не удалось убрать исключение", err.Error())
				return
			}
			c.note("Исключение убрано", "Защитник Windows снова проверяет папку EzPzDPI.")
			return
		}
		if err := addDefenderExclusion(a); err != nil {
			c.note("Не удалось добавить исключение", err.Error())
			return
		}
		prev := a.capture()
		extracted, err := a.ensurePayload(true)
		if err != nil {
			a.logf("re-extract: %v", err)
		}
		_ = a.ensureEngineCopies()
		if extracted {
			if err := a.restore(prev); err != nil {
				a.logf("restore after re-extract: %v", err)
			}
		}
		c.setEnv(detectEnv(a))
		c.mu.Lock()
		c.extra = removeFinding(c.extra, "engine-error")
		c.mu.Unlock()
		c.note("Папка EzPzDPI добавлена в исключения", "Файлы обхода восстановлены. Нажмите «Проверить», а затем «Починить».")
	})
}

// RestoreForeign brings back the bypass tool that ran before EzPzDPI.
func (c *Controller) RestoreForeign() {
	c.run("restore-foreign", func(ctx context.Context) {
		a := c.a
		a.stopAll()
		a.cfg.Off = true
		a.saveConfig()
		_ = a.syncHealTask()
		err := restoreForeign(a)
		c.setEnv(detectEnv(a))
		if err != nil {
			c.note("Вернуть не получилось", err.Error())
			return
		}
		c.note("Прежний обход возвращён", "EzPzDPI выключен, работает ваш прежний обход.")
	})
}

// Uninstall removes EzPzDPI from the PC.
func (c *Controller) Uninstall(restoreForeignTools bool) {
	c.run("uninstall", func(ctx context.Context) {
		errs := c.a.uninstall(restoreForeignTools)
		c.update(func(vs *ViewState) {
			vs.Phase = "uninstalled"
			vs.Uninstalled = true
			vs.Progress = nil
			vs.Bypass = Bypass{}
			vs.Notices = nil
			if len(errs) > 0 {
				vs.Verdict = Verdict{Title: "Удалено не всё", Text: strings.Join(errs, "; ") + ". Перезагрузите компьютер и откройте EzPzDPI снова, чтобы закончить удаление."}
				return
			}
			vs.Verdict = Verdict{Title: "EzPzDPI удалён", Text: "Обход выключен, служба и рабочие файлы удалены. Сетевой драйвер выгрузится после перезагрузки, интернет работает и без неё. Закройте окно и удалите файл EzPzDPI.exe, если он остался в Загрузках."}
		})
	})
}

func (c *Controller) OpenLog() { _ = exec.Command("explorer.exe", c.a.logDir()).Start() }

// OpenURL opens an https link through Explorer, so the browser starts with
// the user's normal rights rather than this elevated process's.
func (c *Controller) OpenURL(url string) {
	if !strings.HasPrefix(url, "https://") || strings.ContainsAny(url, " \"'<>|&^") {
		return
	}
	_ = exec.Command("explorer.exe", url).Start()
}

// reportLocked builds a plain-text diagnosis report for forums and chats.
// It contains no IP addresses or account data. Caller holds c.mu.
func (c *Controller) reportLocked() string {
	vs := &c.vs
	if len(vs.Services) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "EzPzDPI %s, %s\r\n", version, time.Now().Format("02.01.2006 15:04"))
	if vs.Provenance != "" {
		fmt.Fprintf(&b, "Как проверяли: %s\r\n", vs.Provenance)
	}
	if vs.Bypass.On {
		fmt.Fprintf(&b, "Обход: %s\r\n", vs.Bypass.Strategy)
	}
	fmt.Fprintf(&b, "Итог: %s. %s\r\n\r\n", vs.Verdict.Title, vs.Verdict.Text)
	for _, s := range vs.Services {
		fmt.Fprintf(&b, "%s: %s", s.Name, stateText(s.State))
		if s.Detail != "" {
			fmt.Fprintf(&b, " (%s)", s.Detail)
		}
		b.WriteString("\r\n")
	}
	if len(vs.Notices) > 0 {
		b.WriteString("\r\nНа компьютере:\r\n")
		for _, n := range vs.Notices {
			fmt.Fprintf(&b, "- %s\r\n", n.Title)
		}
	}
	fmt.Fprintf(&b, "\r\nFlowseal %s, Windows %s\r\n", c.a.payload.Flowseal, windowsVersion())
	return b.String()
}

func stateText(s SvcState) string {
	switch s {
	case StWorks:
		return "работает"
	case StFixed:
		return "работает через обход"
	case StBlocked:
		return "заблокирован"
	case StThrottled:
		return "замедлен"
	case StIPBlock:
		return "блокировка по адресу"
	case StGeo:
		return "сервис сам не работает с Россией"
	case StDNS:
		return "подмена DNS"
	case StPartial:
		return "частично"
	case StOffline:
		return "нет соединения"
	case StTesting:
		return "проверяется"
	}
	return "не проверено"
}

// --- small helpers ---

func plural(n int, one, few, many string) string {
	n = n % 100
	if n >= 11 && n <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	}
	return many
}

func pluralVerb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " и " + names[len(names)-1]
}

func namesOf(ids []string) []string {
	byID := catalogByID()
	var out []string
	for _, id := range ids {
		if s, ok := byID[id]; ok {
			out = append(out, s.Name)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// missing lists the items of want that are absent from have.
func missing(want, have []string) []string {
	var out []string
	for _, w := range want {
		if !contains(have, w) {
			out = append(out, w)
		}
	}
	return out
}

func removeFinding(fs []Finding, id string) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.ID != id {
			out = append(out, f)
		}
	}
	return out
}
