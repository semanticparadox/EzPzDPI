//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// consoleReporter prints controller updates as plain lines.
type consoleReporter struct {
	mu        sync.Mutex
	lastTitle string
	lastProg  int
	lastPhase string
}

func (r *consoleReporter) show(vs ViewState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vs.Verdict.Title != r.lastTitle {
		r.lastTitle = vs.Verdict.Title
		say("\n%s", col(cBold, vs.Verdict.Title))
		if vs.Verdict.Text != "" {
			say("  %s", vs.Verdict.Text)
		}
	}
	if vs.Progress != nil && vs.Progress.I != r.lastProg {
		r.lastProg = vs.Progress.I
		say(col(cDim, "  вариант %d из %d"), vs.Progress.I+1, vs.Progress.N)
	}
	settled := vs.Phase == "diagnosed" || vs.Phase == "fixed"
	if settled && vs.Phase != r.lastPhase {
		for _, s := range vs.Services {
			mark := col(cGreen, "+")
			if s.State.Broken() || s.State == StPartial {
				mark = col(cRed, "-")
			}
			say("  %s %-26s %s", mark, s.Name, stateText(s.State))
		}
		for _, n := range vs.Notices {
			say(col(cYellow, "  ! %s"), n.Title)
		}
	}
	r.lastPhase = vs.Phase
}

// runConsole runs one command-line action, or the fallback menu when the
// window cannot open.
func runConsole(a *App, cmd string) int {
	c := newController(a)
	rep := &consoleReporter{}
	c.onChange = rep.show
	// Ctrl+C or closing the console window: cancel and let the rollback
	// finish (Windows allows about 5 s after a close).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		c.Cancel()
		// Ctrl+C: wait for the whole rollback. A closed console window
		// (SIGTERM) gives Windows' ~5 s, so leave a little before that;
		// fix.marker finishes the rollback at the next start if needed.
		limit := 60 * time.Second
		if s == syscall.SIGTERM {
			limit = 4500 * time.Millisecond
		}
		done := make(chan struct{})
		go func() { c.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(limit):
		}
		restoreConsole()
		os.Exit(130)
	}()
	c.Start()
	c.Wait()
	switch cmd {
	case "check":
		c.Check(false)
		c.Wait()
	case "fix":
		if q := c.foreignConfirm(true); q != "" && !confirm(q, true) {
			return 1
		}
		c.Check(false)
		c.Wait()
		c.Fix()
		c.Wait()
	case "stop":
		c.Stop()
		c.Wait()
	case "run":
		s, ok := a.savedStrategy()
		if !ok {
			say("Вариант ещё не подобран: запустите %s -fix.", appName)
			return 1
		}
		if _, err := a.enable(s); err != nil {
			say("Не удалось включить: %v", err)
			return 1
		}
		a.cfg.Off = false
		a.saveConfig()
		_ = a.syncHealTask()
		say("Обход включён: %s", s.Name)
	case "menu":
		return consoleMenu(c)
	}
	return 0
}

func consoleMenu(c *Controller) int {
	for {
		say("\n  1. Проверить\n  2. Починить\n  3. Выключить обход\n  4. Обновить варианты обхода\n  0. Выход")
		switch strings.TrimSpace(ask("  Пункт: ")) {
		case "1":
			c.Check(false)
		case "2":
			if q := c.foreignConfirm(true); q != "" && !confirm(q, true) {
				continue
			}
			c.Fix()
		case "3":
			c.Stop()
		case "4":
			c.Update()
		case "0", "":
			return 0
		default:
			continue
		}
		c.Wait()
	}
}

// waitRawIP waits up to d for the network to answer by IP.
func waitRawIP(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if rawIPReachable(ctx) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Second)
	}
}

// runHeal is the logon task (-heal): it checks the services the bypass
// fixed and, if they broke (the ISP changed its DPI), picks a new variant.
func runHeal(a *App) int {
	a.logf("heal: start")
	c := newController(a)
	c.recoverInterruptedFix() // a fix cut off by a reboot is rolled back first
	ctx := context.Background()
	// Secure DNS that stopped working (another network, a captive portal)
	// must never leave the user offline.
	// Only when the network itself is up: right after logon Wi-Fi may still
	// be connecting, and that is not a DNS problem.
	if a.cfg.DNSBackup != nil && waitRawIP(ctx, 2*time.Minute) && !systemDNSWorks(ctx) {
		if err := revertSecureDNS(a); err != nil {
			a.logf("heal: dns revert: %v", err)
		} else {
			a.cfg.LastHeal, a.cfg.LastHealAt = "Защищённый DNS не работал в этой сети, прежние настройки DNS возвращены.", time.Now()
			a.saveConfig()
		}
	}
	// The user switched the bypass off, or chose "until reboot": leave it.
	if a.cfg.Strategy == "" || a.cfg.Off || !a.cfg.Autostart {
		return 0
	}
	online := false
	for i := 0; i < 12; i++ {
		if st, _ := c.netState(ctx); st == "ok" {
			online = true
			break
		}
		time.Sleep(15 * time.Second)
	}
	if !online {
		a.logf("heal: no internet, skipped")
		return 0
	}
	c.setEnv(detectEnv(a))
	if len(c.env.ForeignActive()) > 0 {
		a.cfg.LastHeal, a.cfg.LastHealAt = "Работает другая программа обхода, автопроверка пропущена.", time.Now()
		a.saveConfig()
		return 0
	}
	if a.state() == "" {
		if s, ok := a.savedStrategy(); ok {
			if _, err := a.enable(s); err != nil {
				a.logf("heal: restart failed: %v", err)
			}
		}
	}
	if len(a.cfg.Fixed) == 0 {
		return 0
	}
	ids := map[string]bool{}
	for _, id := range a.cfg.Fixed {
		ids[id] = true
	}
	r := NewTester(ctx, allTargets(ids)).Run(ctx)
	var broken []string
	for id := range ids {
		if catalogByID()[id] != nil && len(catalogByID()[id].Targets) > 0 && !r.ServiceOK(id) {
			broken = append(broken, id)
		}
	}
	if len(broken) == 0 {
		a.logf("heal: all fixed services work")
		return 0
	}
	a.logf("heal: broken %v, re-picking", broken)
	c.fix(ctx)
	vs := c.Snapshot()
	a.loadConfig()
	a.cfg.LastHeal = fmt.Sprintf("Перестали работать %s. %s. %s", joinNames(namesOf(broken)), vs.Verdict.Title, vs.Verdict.Text)
	a.cfg.LastHealAt = time.Now()
	a.saveConfig()
	return 0
}
