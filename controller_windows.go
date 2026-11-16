//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ViewState is everything the window (or console) shows. It is sent to the
// page as JSON after every change.
type ViewState struct {
	Phase           string            `json:"phase"`
	Verdict         Verdict           `json:"verdict"`
	Progress        *Progress         `json:"progress,omitempty"`
	Bypass          Bypass            `json:"bypass"`
	Services        []ViewService     `json:"services"`
	Notices         []Finding         `json:"notices"`
	Settings        SettingsView      `json:"settings"`
	Versions        map[string]string `json:"versions"`
	Strategies      []StratRef        `json:"strategies"`
	ConfirmFix      string            `json:"confirm_fix,omitempty"`
	ForeignDisabled []string          `json:"foreign_disabled,omitempty"`
	Uninstalled     bool              `json:"uninstalled,omitempty"`
}

type Verdict struct {
	Title  string `json:"title"`
	Text   string `json:"text"`
	Action string `json:"action,omitempty"`
	Second string `json:"second,omitempty"`
	Calm   bool   `json:"calm,omitempty"`
	Busy   bool   `json:"busy,omitempty"`
}

type Progress struct {
	I int `json:"i"`
	N int `json:"n"`
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
	Disabled  []string `json:"disabled"`
}

type StratRef struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Controller runs every user-facing scenario and keeps ViewState current.
type Controller struct {
	a *App

	mu       sync.Mutex
	vs       ViewState
	env      Env
	diag     map[string]Diagnosis // last diagnosis shown
	baseline map[string]Diagnosis // last diagnosis without any bypass
	busy     bool
	cancel   context.CancelFunc
	done     chan struct{}
	pending  *prevState
	// foreign services disabled during the current fix, with start types
	runDisabled map[string]uint32

	onChange func(ViewState)
}

func newController(a *App) *Controller {
	c := &Controller{a: a, diag: map[string]Diagnosis{}}
	c.vs.Phase = "idle"
	return c
}

// update mutates the view under the lock and publishes a copy.
func (c *Controller) update(f func(vs *ViewState)) {
	c.mu.Lock()
	f(&c.vs)
	vs := c.snapshotLocked()
	c.mu.Unlock()
	if c.onChange != nil {
		c.onChange(vs)
	}
}

func (c *Controller) push() { c.update(func(*ViewState) {}) }

func (c *Controller) snapshotLocked() ViewState {
	vs := c.vs
	vs.Services = append([]ViewService(nil), c.vs.Services...)
	vs.Notices = append([]Finding(nil), c.vs.Notices...)
	return vs
}

// refreshStatic recomputes everything that does not come from a test run.
func (c *Controller) refreshStatic(vs *ViewState) {
	a := c.a
	mode := a.state()
	vs.Bypass = Bypass{On: mode != "", Autostart: mode == "service"}
	if s, ok := a.savedStrategy(); ok && mode != "" {
		vs.Bypass.Strategy = s.Name
	}
	vs.Settings = SettingsView{Autostart: a.cfg.Autostart, Heal: a.cfg.Heal, Games: a.cfg.Games, Disabled: append([]string{}, a.cfg.Disabled...)}
	vs.Versions = map[string]string{"app": version, "flowseal": a.payload.Flowseal, "goodbyedpi": a.payload.GoodbyeDPI}
	vs.Strategies = vs.Strategies[:0]
	for _, s := range a.strategies {
		vs.Strategies = append(vs.Strategies, StratRef{Key: s.Key(), Name: s.Name})
	}
	vs.ForeignDisabled = vs.ForeignDisabled[:0]
	for name := range a.cfg.ForeignDisabled {
		vs.ForeignDisabled = append(vs.ForeignDisabled, name)
	}
	sort.Strings(vs.ForeignDisabled)
	vs.Notices = append([]Finding(nil), c.env.Findings...)
	if a.cfg.LastHeal != "" && time.Since(a.cfg.LastHealAt) < 7*24*time.Hour {
		vs.Notices = append(vs.Notices, Finding{ID: "heal", Kind: "own", Level: "info",
			Title: "Автопроверка " + a.cfg.LastHealAt.Format("02.01 15:04"), Text: a.cfg.LastHeal})
	}
	vs.ConfirmFix = ""
	if fs := c.env.ForeignActive(); len(fs) > 0 {
		var names []string
		for _, f := range fs {
			names = append(names, strings.TrimPrefix(f.Title, "Найден другой обход: "))
		}
		vs.ConfirmFix = "Чтобы подобрать обход, EzPzDPI отключит " + strings.Join(names, " и ") +
			". Если ничего не поможет, EzPzDPI включит его обратно. Продолжить?"
	}
	enabled := a.enabledServices()
	vs.Services = vs.Services[:0]
	for _, s := range catalog {
		if !enabled[s.ID] {
			continue
		}
		v := ViewService{ID: s.ID, Name: s.Name, Category: s.Category, State: StUnknown}
		if d, ok := c.diag[s.ID]; ok {
			v.State, v.Detail = d.State, d.Detail
			v.Fixable = d.State.Fixable()
		}
		vs.Services = append(vs.Services, v)
	}
}

// Start scans the PC and shows the first screen.
func (c *Controller) Start() {
	c.env = detectEnv(c.a)
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Phase = "idle"
		n := len(vs.Services)
		switch {
		case vs.Bypass.On:
			vs.Verdict = Verdict{Title: "Обход включён", Text: fmt.Sprintf("Вариант %s. Нажмите «Проверить», чтобы увидеть, что сейчас открывается.", vs.Bypass.Strategy), Action: "Проверить"}
		case len(c.env.ForeignActive()) > 0:
			vs.Verdict = Verdict{Title: "Проверим, как работает ваш обход", Text: fmt.Sprintf("EzPzDPI проверит %d %s с ним. Пока вы не нажмёте «Починить», в системе ничего не меняется.", n, plural(n, "сервис", "сервиса", "сервисов")), Action: "Проверить"}
		default:
			vs.Verdict = Verdict{Title: "Проверим, что у вас открывается", Text: fmt.Sprintf("EzPzDPI проверит %d %s, это займёт около минуты. Пока вы не нажмёте «Починить», в системе ничего не меняется.", n, plural(n, "сервис", "сервиса", "сервисов")), Action: "Проверить"}
		}
	})
}

// run starts an operation in the background unless one is running.
func (c *Controller) run(name string, f func(ctx context.Context)) {
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.busy, c.cancel, c.done = true, cancel, make(chan struct{})
	done := c.done
	c.mu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.a.logf("panic in %s: %v", name, r)
				c.update(func(vs *ViewState) {
					vs.Phase = "idle"
					vs.Progress = nil
					vs.Verdict = Verdict{Title: "Что-то пошло не так", Text: fmt.Sprint(r), Action: "Проверить снова"}
				})
			}
			c.mu.Lock()
			c.busy, c.cancel = false, nil
			c.mu.Unlock()
			cancel()
			close(done)
		}()
		c.a.logf("op %s start", name)
		f(ctx)
		c.a.logf("op %s end", name)
	}()
}

// Main is the big button; its meaning follows the phase.
func (c *Controller) Main() {
	c.mu.Lock()
	phase, busy := c.vs.Phase, c.busy
	fixable := false
	for _, s := range c.vs.Services {
		if s.State.Fixable() {
			fixable = true
		}
	}
	c.mu.Unlock()
	switch {
	case busy:
		c.Cancel()
	case phase == "diagnosed" && fixable:
		c.Fix()
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
			}
		}
	})
}

// netState checks the connection itself: no internet, or mobile
// "whitelist" mode where only approved Russian sites open.
func (c *Controller) netState(ctx context.Context) string {
	ru := []Target{{Service: "_ru", Host: "ya.ru", Path: "/"}, {Service: "_ru", Host: "vk.com", Path: "/"}}
	intl := []Target{{Service: "_intl", Host: "www.google.com", Path: "/generate_204"}, {Service: "_intl", Host: "www.wikipedia.org", Path: "/"}, {Service: "_intl", Host: "one.one.one.one", Path: "/"}}
	t := NewTester(ctx, append(ru, intl...))
	t.Timeout = 8 * time.Second
	r := t.Run(ctx)
	ruOK, intlOK := 0, 0
	for _, p := range r.Results {
		if p.OK && p.Service == "_ru" {
			ruOK++
		}
		if p.OK && p.Service == "_intl" {
			intlOK++
		}
	}
	switch {
	case ruOK == 0 && intlOK == 0:
		return "offline"
	case intlOK == 0:
		return "whitelist"
	}
	return "ok"
}

func (c *Controller) showNet(state string) {
	c.update(func(vs *ViewState) {
		vs.Phase = "idle"
		vs.Progress = nil
		for i := range vs.Services {
			vs.Services[i].State = StOffline
			vs.Services[i].Detail = ""
		}
		if state == "offline" {
			vs.Verdict = Verdict{Title: "Нет интернета", Text: "Не открываются даже ya.ru и vk.com. Проверьте подключение и нажмите «Проверить снова».", Action: "Проверить снова"}
		} else {
			vs.Verdict = Verdict{Title: "Похоже, включены белые списки", Text: "Открываются только разрешённые российские сайты, все зарубежные адреса недоступны. Так бывает на мобильном интернете во время ограничений. Обход здесь не поможет: попробуйте домашний интернет или Wi-Fi.", Action: "Проверить снова"}
		}
	})
}

// diagnoseAll runs the full diagnosis for the enabled services.
func (c *Controller) diagnoseAll(ctx context.Context) (map[string]Diagnosis, *Tester) {
	enabled := c.a.enabledServices()
	t := NewTester(ctx, allTargets(enabled))
	t.Neutral = true
	r := t.Run(ctx)
	if ctx.Err() == nil && t.RecheckSpoofed(ctx, r) {
		r = t.Run(ctx)
	}
	out := map[string]Diagnosis{}
	for i := range catalog {
		s := &catalog[i]
		if enabled[s.ID] && len(s.Targets) > 0 {
			out[s.ID] = Diagnose(s, r)
		}
	}
	if enabled["voice"] {
		out["voice"] = c.voiceDiag(ctx)
	}
	return out, t
}

// Check shows what works right now (with whatever bypass is running), or,
// with withoutForeign, pauses other bypass tools to show the raw state.
func (c *Controller) Check(withoutForeign bool) {
	c.run("check", func(ctx context.Context) {
		c.env = detectEnv(c.a)
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "checking"
			vs.Progress = nil
			vs.Verdict = Verdict{Title: "Проверяю", Text: "Это займёт около минуты.", Action: "Остановить", Calm: true, Busy: true}
		})
		c.setTesting(nil)
		if withoutForeign {
			resume := pauseForeign(c.a, c.env.ForeignActive())
			defer func() {
				resume()
				c.env = detectEnv(c.a)
				c.push()
			}()
		}
		if st := c.netState(ctx); st != "ok" && ctx.Err() == nil {
			c.showNet(st)
			return
		}
		diag, t := c.diagnoseAll(ctx)
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
		if !ourOn && !foreign {
			c.baseline = diag
		}
		c.mu.Lock()
		c.diag = diag
		c.mu.Unlock()
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "diagnosed"
			vs.Verdict = summarize(c.a, vs.Services, ourOn, foreign, withoutForeign, t.DNSTrouble())
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
func summarize(a *App, svcs []ViewService, ourOn, foreign, withoutForeign, dns bool) Verdict {
	var fix, ip, geo, dnsList, part, broken []string
	for _, s := range svcs {
		switch s.State {
		case StBlocked, StThrottled:
			fix = append(fix, s.Name)
		case StIPBlock:
			ip = append(ip, s.Name)
		case StGeo:
			geo = append(geo, s.Name)
		case StDNS:
			dnsList = append(dnsList, s.Name)
		case StPartial:
			part = append(part, s.Name)
		}
		if s.State.Broken() {
			broken = append(broken, s.Name)
		}
	}
	n := len(svcs)
	if len(broken) == 0 {
		v := Verdict{Title: "Всё открывается", Action: "Проверить снова", Calm: true}
		switch {
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
		return v
	}
	v := Verdict{Title: fmt.Sprintf("Не работают %d из %d", len(broken), n)}
	if foreign {
		v.Title = fmt.Sprintf("С вашим обходом не работают %d из %d", len(broken), n)
	} else if ourOn {
		v.Title = fmt.Sprintf("С обходом не работают %d из %d", len(broken), n)
	}
	var parts []string
	if len(fix) > 0 {
		parts = append(parts, "Обход починит "+joinNames(fix)+".")
	}
	if len(ip) > 0 {
		parts = append(parts, joinNames(ip)+pluralVerb(len(ip), " блокирует", " блокируют")+" по адресу, тут нужен VPN.")
	}
	if len(geo) > 0 {
		parts = append(parts, joinNames(geo)+pluralVerb(len(geo), " сам не работает", " сами не работают")+" с Россией.")
	}
	if len(dnsList) > 0 || dns {
		parts = append(parts, "Провайдер подменяет адреса сайтов: включите безопасный DNS в браузере.")
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

// Fix stops every bypass, measures the raw state, tests strategies and
// enables the best one. Any abort restores what ran before.
func (c *Controller) Fix() {
	c.run("fix", func(ctx context.Context) {
		a := c.a
		prev := a.capture()
		c.mu.Lock()
		c.pending = &prev
		c.runDisabled = map[string]uint32{}
		c.mu.Unlock()
		ok := false
		defer func() {
			c.mu.Lock()
			c.pending = nil
			c.mu.Unlock()
			if !ok {
				c.rollback(prev)
			}
		}()

		c.update(func(vs *ViewState) {
			vs.Phase = "fixing"
			vs.Progress = nil
			vs.Verdict = Verdict{Title: "Проверяю без обхода", Text: "Сначала нужно увидеть, что блокирует провайдер.", Action: "Остановить", Calm: true, Busy: true}
		})
		c.env = detectEnv(a)
		for _, f := range c.env.ForeignActive() {
			for _, name := range f.Services {
				if si := queryService(name); si.Exists {
					if _, had := a.cfg.ForeignDisabled[name]; !had {
						c.runDisabled[name] = si.StartType
					}
				}
			}
			if err := disableForeign(a, f); err != nil {
				a.logf("disable foreign: %v", err)
			}
		}
		a.stopAll()
		c.setTesting(nil)
		if st := c.netState(ctx); st != "ok" {
			if ctx.Err() == nil {
				c.showNet(st)
			}
			return
		}
		base, t := c.diagnoseAll(ctx)
		if ctx.Err() != nil {
			c.cancelled("Подбор остановлен, прежние настройки возвращены.")
			return
		}
		c.mu.Lock()
		c.baseline, c.diag = base, base
		c.mu.Unlock()

		var want, must, keep []string
		for _, s := range catalog {
			d, okd := base[s.ID]
			if !okd || len(s.Targets) == 0 {
				continue
			}
			switch d.State {
			case StBlocked, StThrottled:
				want, must = append(want, s.ID), append(must, s.ID)
			case StIPBlock:
				want = append(want, s.ID) // rarely fixable, but a strategy that fixes it wins
			case StWorks, StPartial:
				keep = append(keep, s.ID)
			}
		}
		if len(must) == 0 {
			c.update(func(vs *ViewState) {
				c.refreshStatic(vs)
				vs.Phase = "diagnosed"
				vs.Verdict = summarize(a, vs.Services, false, false, false, t.DNSTrouble())
				if vs.Verdict.Action == "Починить" {
					vs.Verdict.Action = "Проверить снова"
				}
				vs.Verdict.Text = strings.TrimSpace("Обход здесь ничего не исправит. " + vs.Verdict.Text)
			})
			return
		}

		inTest := map[string]bool{}
		for _, id := range append(append([]string{}, want...), keep...) {
			inTest[id] = true
		}
		tt := t.Subset(func(tg Target) bool { return inTest[tg.Service] })
		tt.Neutral = false
		winner, sc, err := c.search(ctx, tt, want, must, keep)
		if ctx.Err() != nil {
			c.cancelled("Подбор остановлен, прежние настройки возвращены.")
			return
		}
		if winner == nil {
			msg := "Ни один из вариантов не открыл " + joinNames(namesOf(must)) + ". Обновите варианты обхода в настройках и попробуйте снова. Если не поможет, провайдер блокирует по адресу и нужен VPN."
			if err != nil {
				msg = err.Error()
			}
			c.update(func(vs *ViewState) {
				c.refreshStatic(vs)
				vs.Phase = "diagnosed"
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
			c.update(func(vs *ViewState) {
				c.refreshStatic(vs)
				vs.Phase = "diagnosed"
				vs.Verdict = Verdict{Title: "Не удалось включить обход", Text: err.Error(), Action: "Проверить снова", Calm: true}
			})
			return
		}
		ok = true
		var fixed []string
		for _, id := range want {
			if sc.Services[id] {
				fixed = append(fixed, id)
			}
		}
		a.cfg.Strategy, a.cfg.PickedAt, a.cfg.Fixed = winner.Key(), time.Now(), fixed
		a.saveConfig()
		if err := a.syncHealTask(); err != nil {
			a.logf("heal task: %v", err)
		}

		// Final check with the bypass on, so the screen shows the real result.
		c.setTesting(nil)
		after, _ := c.diagnoseAll(ctx)
		for id, d := range after {
			if b, okb := base[id]; okb && b.State.Broken() && d.State == StWorks {
				d.State = StFixed
				after[id] = d
			}
		}
		c.mu.Lock()
		c.diag = after
		c.mu.Unlock()
		c.env = detectEnv(a)
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "fixed"
			vs.Progress = nil
			vs.Verdict = fixedVerdict(vs.Services, must, mode)
		})
	})
}

// search tests strategies in order. It stops at the first one that fixes
// every name-blocked service without breaking working ones, confirmed by a
// second run; otherwise it re-checks the best few and returns the leader.
func (c *Controller) search(ctx context.Context, t *Tester, want, must, keep []string) (*Strategy, TrialScore, error) {
	a := c.a
	type cand struct {
		s  Strategy
		sc TrialScore
	}
	var cands []cand
	var lastErr error
	n := len(a.strategies)
	fixedSoFar := map[string]bool{}
	for i, s := range a.strategies {
		if ctx.Err() != nil {
			return nil, TrialScore{}, ctx.Err()
		}
		c.update(func(vs *ViewState) {
			vs.Progress = &Progress{I: i, N: n}
			vs.Verdict = Verdict{Title: "Подбираю обход", Text: fmt.Sprintf("Проверено %d из %d вариантов, сейчас %s. Обычно хватает 1–4 минут.", i, n, s.Name), Action: "Остановить", Calm: true, Busy: true}
			for j := range vs.Services {
				id := vs.Services[j].ID
				if contains(want, id) && !fixedSoFar[id] {
					vs.Services[j].State = StTesting
				}
			}
		})
		r, err := a.runTrial(ctx, s, t)
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
		sc := ScoreTrial(r, want, keep)
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
			r2, err := a.runTrial(ctx, s, t)
			if err == nil {
				sc2 := ScoreTrial(r2, want, keep)
				if coversAll(sc2, must) && sc2.Broke == 0 {
					return &s, sc2, nil
				}
			}
		}
	}
	if len(cands) == 0 {
		return nil, TrialScore{}, lastErr
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].sc.Better(cands[j].sc) })
	for i := 0; i < len(cands) && i < 3; i++ {
		cd := cands[i]
		if cd.sc.Fixed == 0 {
			break
		}
		c.update(func(vs *ViewState) {
			vs.Verdict = Verdict{Title: "Перепроверяю лучший вариант", Text: cd.s.Name, Action: "Остановить", Calm: true, Busy: true}
		})
		r2, err := a.runTrial(ctx, cd.s, t)
		if err == nil {
			if sc2 := ScoreTrial(r2, want, keep); sc2.Fixed >= cd.sc.Fixed {
				return &cd.s, sc2, nil
			}
		}
	}
	if cands[0].sc.Fixed > 0 {
		return &cands[0].s, cands[0].sc, nil
	}
	return nil, TrialScore{}, lastErr
}

func coversAll(sc TrialScore, ids []string) bool {
	for _, id := range ids {
		if !sc.Services[id] {
			return false
		}
	}
	return true
}

// rollback brings back what ran before a failed or aborted fix, including
// other tools EzPzDPI disabled during it.
func (c *Controller) rollback(prev prevState) {
	a := c.a
	a.killTrial()
	c.mu.Lock()
	rd := c.runDisabled
	c.runDisabled = nil
	c.mu.Unlock()
	if prev.mode != "" {
		if err := a.restore(prev); err != nil {
			a.logf("rollback restore: %v", err)
		}
	} else {
		a.stopAll()
	}
	for name, start := range rd {
		if err := setServiceStart(name, start, true); err != nil {
			a.logf("rollback foreign %s: %v", name, err)
		}
		delete(a.cfg.ForeignDisabled, name)
	}
	if len(rd) > 0 {
		a.saveConfig()
	}
	c.env = detectEnv(a)
	c.push()
}

func fixedVerdict(svcs []ViewService, must []string, mode string) Verdict {
	var fixed, failed, ip []string
	byID := map[string]ViewService{}
	for _, s := range svcs {
		byID[s.ID] = s
		if s.State == StIPBlock {
			ip = append(ip, s.Name)
		}
	}
	for _, id := range must {
		if s, ok := byID[id]; ok {
			if s.State == StFixed || s.State == StWorks || s.State == StPartial {
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
	if containsName(fixed, "Discord") {
		v.Text += " Если Discord был открыт, закройте его через значок в трее и откройте снова."
	}
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
		c.mu.Lock()
		c.diag = map[string]Diagnosis{}
		c.mu.Unlock()
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
	switch action {
	case "check-without":
		c.Check(true)
	case "recheck":
		c.Check(false)
	case "disable-foreign":
		c.run("disable-foreign", func(ctx context.Context) {
			if f, ok := c.env.Find(notice); ok {
				if err := disableForeign(c.a, f); err != nil {
					c.note("Не всё удалось отключить", err.Error())
				}
			}
			c.env = detectEnv(c.a)
			c.update(func(vs *ViewState) { c.refreshStatic(vs) })
		})
	case "restart-own":
		c.run("restart-own", func(ctx context.Context) {
			if s, ok := c.a.savedStrategy(); ok {
				if _, err := c.a.enable(s); err != nil {
					c.note("Не удалось запустить", err.Error())
				}
			}
			c.env = detectEnv(c.a)
			c.update(func(vs *ViewState) { c.refreshStatic(vs) })
		})
	case "clean-hosts":
		c.run("clean-hosts", func(ctx context.Context) {
			backup, err := cleanHosts()
			c.env = detectEnv(c.a)
			if err != nil {
				c.note("Не удалось изменить hosts", err.Error())
				return
			}
			c.note("Записи убраны", "Копия прежнего файла: "+backup)
		})
	}
}

// note shows a one-off message in the verdict area.
func (c *Controller) note(title, text string) {
	c.update(func(vs *ViewState) {
		c.refreshStatic(vs)
		vs.Verdict = Verdict{Title: title, Text: text, Action: "Проверить", Calm: true}
		vs.Phase = "idle"
	})
}

// Settings applies the settings sheet.
func (c *Controller) Settings(s SettingsView) {
	c.run("settings", func(ctx context.Context) {
		a := c.a
		modeChanged := s.Autostart != a.cfg.Autostart
		argsChanged := s.Games != a.cfg.Games || !sameSet(s.Disabled, a.cfg.Disabled)
		a.cfg.Autostart, a.cfg.Heal, a.cfg.Games = s.Autostart, s.Heal, s.Games
		a.cfg.Disabled = cleanIDs(s.Disabled)
		a.saveConfig()
		if argsChanged {
			_ = a.writeExtraList()
			a.loadStrategies()
		}
		if a.state() != "" && (modeChanged || argsChanged) {
			if st, ok := a.savedStrategy(); ok {
				if _, err := a.enable(st); err != nil {
					c.note("Не удалось применить настройки", err.Error())
				}
			}
		}
		if err := a.syncHealTask(); err != nil {
			a.logf("heal task: %v", err)
		}
		c.update(func(vs *ViewState) { c.refreshStatic(vs) })
	})
}

// Manual enables a strategy the user picked and checks the result.
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
			vs.Verdict = Verdict{Title: "Включаю " + s.Name, Busy: true, Calm: true}
		})
		mode, err := a.enable(s)
		if err != nil {
			c.note("Не удалось включить", err.Error())
			return
		}
		a.cfg.Strategy, a.cfg.PickedAt = s.Key(), time.Now()
		c.setTesting(nil)
		diag, _ := c.diagnoseAll(ctx)
		var fixed []string
		for id, d := range diag {
			if b, okb := c.baseline[id]; okb && b.State.Broken() && d.State == StWorks {
				d.State = StFixed
				diag[id] = d
				fixed = append(fixed, id)
			}
		}
		a.cfg.Fixed = fixed
		a.saveConfig()
		_ = a.syncHealTask()
		c.mu.Lock()
		c.diag = diag
		c.mu.Unlock()
		c.update(func(vs *ViewState) {
			c.refreshStatic(vs)
			vs.Phase = "diagnosed"
			v := summarize(a, vs.Services, true, false, false, false)
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

// Uninstall removes EzPzDPI from the PC.
func (c *Controller) Uninstall(restoreForeign bool) {
	c.run("uninstall", func(ctx context.Context) {
		err := c.a.uninstall(restoreForeign)
		c.update(func(vs *ViewState) {
			vs.Phase = "uninstalled"
			vs.Uninstalled = true
			vs.Progress = nil
			vs.Bypass = Bypass{}
			vs.Notices = nil
			if err != nil {
				vs.Verdict = Verdict{Title: "Удалено не всё", Text: err.Error() + ". Перезагрузите компьютер и удалите папку " + c.a.dataDir + " вручную."}
				return
			}
			vs.Verdict = Verdict{Title: "EzPzDPI удалён", Text: "Обход выключен, служба и рабочие файлы удалены. Закройте окно и удалите файл EzPzDPI.exe."}
		})
	})
}

func (c *Controller) OpenLog() {
	_ = exec.Command("explorer.exe", c.a.logDir()).Start()
}

// voiceDiag measures UDP the way calls use it (STUN binding requests).
func (c *Controller) voiceDiag(ctx context.Context) Diagnosis {
	d := Diagnosis{ID: "voice"}
	servers := []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}
	var res []StunResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, s := range servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			r := stunProbe(ctx, addr, 25, 120*time.Millisecond)
			mu.Lock()
			res = append(res, r)
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	best := StunResult{Sent: 1}
	for _, r := range res {
		if r.Loss() < best.Loss() {
			best = r
		}
	}
	switch {
	case best.Got == 0:
		d.State = StBlocked
		d.Detail = "UDP-запросы, как у звонков, не получают ответа ни от одного сервера. Голос и звонки в браузере и мессенджерах скорее всего не соединятся."
	case best.Loss() > 0.2 || best.MaxGap >= 5:
		d.State = StPartial
		d.Detail = fmt.Sprintf("Теряется %.0f%% UDP-пакетов, самый длинный обрыв %d подряд. Голос может прерываться.", 100*best.Loss(), best.MaxGap)
	default:
		d.State = StWorks
		d.Detail = fmt.Sprintf("UDP проходит: потери %.0f%%, задержка %d мс.", 100*best.Loss(), best.Median.Milliseconds())
	}
	return d
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

func containsName(list []string, s string) bool { return contains(list, s) }

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

func cleanIDs(ids []string) []string {
	known := catalogByID()
	var out []string
	for _, id := range ids {
		if _, ok := known[id]; ok && !contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
