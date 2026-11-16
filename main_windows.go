//go:build windows

package main

import (
	"context"
	"flag"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

// The window must be created and pumped on one OS thread.
func init() { runtime.LockOSThread() }

func main() {
	hardenDLLSearch() // before anything can load a DLL from the download folder (R04)

	check := flag.Bool("check", false, "проверить, что открывается")
	fix := flag.Bool("fix", false, "подобрать вариант обхода и включить его")
	auto := flag.Bool("auto", false, "то же, что -fix")
	stop := flag.Bool("stop", false, "выключить обход")
	run := flag.Bool("run", false, "включить сохранённый вариант")
	heal := flag.Bool("heal", false, "автопроверка при входе в Windows")
	uninstall := flag.Bool("uninstall", false, "удалить EzPzDPI")
	console := flag.Bool("console", false, "текстовый режим без окна")
	selftest := flag.Bool("selftest", false, "проверка сборки без прав администратора")
	uitest := flag.String("uitest", "", "проверка окна без прав администратора; значение: путь для PNG-снимка")
	dataDir := flag.String("datadir", "", "папка рабочих файлов (только с -selftest)")
	flag.Parse()

	cli := ""
	switch {
	case *check:
		cli = "check"
	case *fix || *auto:
		cli = "fix"
	case *stop:
		cli = "stop"
	case *run:
		cli = "run"
	case *console:
		cli = "menu"
	}

	if *selftest {
		setupConsole(appName)
		os.Exit(runSelftest(*dataDir))
	}
	if *uitest != "" {
		setupConsole(appName)
		os.Exit(runUITest(*dataDir, *uitest))
	}
	if *dataDir != "" {
		setupConsole(appName)
		say("Параметр -datadir работает только вместе с -selftest.")
		os.Exit(2)
	}
	if !isAdmin() { // the manifest requests elevation; this is a safety net
		if err := relaunchElevated(os.Args[1:]); err != nil {
			messageBox("Нужны права администратора: без них сетевой драйвер не запустится.", windows.MB_ICONWARNING)
			os.Exit(1)
		}
		return
	}

	// One instance at a time: two copies would fight over the engine. The
	// logon check holds a second mutex so a user who opens the app during
	// it gets a clear message.
	mutexName, _ := windows.UTF16PtrFromString(`Global\EzPzDPI`)
	h, err := windows.CreateMutex(nil, false, mutexName)
	if err == windows.ERROR_ALREADY_EXISTS {
		if !*heal && cli == "" {
			if mutexExists(`Global\EzPzDPI-Heal`) {
				messageBox("Сейчас идёт автоматическая проверка после входа в Windows. Откройте EzPzDPI через пару минут.", windows.MB_ICONINFORMATION)
			} else {
				messageBox("EzPzDPI уже открыт.", windows.MB_ICONINFORMATION)
			}
		}
		os.Exit(0)
	}
	defer windows.CloseHandle(h)
	if *heal {
		hn, _ := windows.UTF16PtrFromString(`Global\EzPzDPI-Heal`)
		if hh, err := windows.CreateMutex(nil, false, hn); err == nil {
			defer windows.CloseHandle(hh)
		}
	}

	if cli != "" {
		attachConsole(appName, cli == "menu")
	}
	a := &App{dataDir: defaultDataDir()}
	if err := a.init(); err != nil {
		fail(cli, "EzPzDPI не смог подготовить рабочие файлы: "+err.Error())
	}

	switch {
	case *heal:
		os.Exit(runHeal(a))
	case *uninstall:
		os.Exit(uninstallFromApps(a))
	case cli != "":
		code := runConsole(a, cli)
		if cli == "menu" {
			pause()
		}
		restoreConsole()
		os.Exit(code)
	}

	err = runGUI(a)
	if err == errNoWebView {
		if offerWebView2() {
			err = runGUI(a)
		}
		if err == errNoWebView {
			attachConsole(appName, true)
			say("Окно не открылось: нет компонента Microsoft WebView2. Работаю в текстовом режиме.")
			runConsole(a, "menu")
			return
		}
	}
	if err != nil {
		fail("", err.Error())
	}
}

func fail(cli, text string) {
	if cli != "" {
		say(col(cRed, "%s"), text)
	} else {
		messageBox(text, windows.MB_ICONERROR)
	}
	os.Exit(1)
}

// offerWebView2 installs the Microsoft WebView2 runtime after asking (X07).
func offerWebView2() bool {
	if webView2Installed() {
		return true
	}
	ans := messageBox("Для окна программы нужен компонент Microsoft WebView2 (около 2 МБ, официальный установщик Microsoft). Установить сейчас?\n\nЕсли нажать «Нет», EzPzDPI откроется в текстовом режиме.", windows.MB_YESNO|windows.MB_ICONQUESTION)
	if ans != 6 { // IDYES
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := installWebView2(ctx); err != nil {
		messageBox("Установить WebView2 не удалось: "+err.Error(), windows.MB_ICONWARNING)
		return false
	}
	return true
}

// uninstallFromApps runs when EzPzDPI is removed from Windows "Apps".
func uninstallFromApps(a *App) int {
	if messageBox("Выключить обход и удалить EzPzDPI с компьютера?", windows.MB_YESNO|windows.MB_ICONQUESTION) != 6 {
		return 1
	}
	restore := false
	if len(a.cfg.ForeignDisabled) > 0 || len(a.cfg.ForeignTasks) > 0 || len(a.cfg.ForeignShortcuts) > 0 {
		restore = messageBox("Раньше на компьютере был другой обход, EzPzDPI его отключил. Вернуть его как было?", windows.MB_YESNO|windows.MB_ICONQUESTION) == 6
	}
	if errs := a.uninstall(restore); len(errs) > 0 {
		messageBox("Удалено не всё:\n"+joinLines(errs), windows.MB_ICONWARNING)
		return 1
	}
	msg := "EzPzDPI удалён. Сетевой драйвер выгрузится после перезагрузки, интернет работает и без неё."
	if a.keptBackups != "" {
		msg += "\n\nРезервные копии сохранены в папке " + a.keptBackups + "."
	}
	messageBox(msg, windows.MB_ICONINFORMATION)
	return 0
}

func mutexExists(name string) bool {
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, n)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}

func joinLines(s []string) string {
	out := ""
	for _, x := range s {
		out += "- " + x + "\n"
	}
	return out
}
