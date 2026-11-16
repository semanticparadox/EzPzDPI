//go:build windows

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// dpiTool describes another circumvention program we can recognise.
type dpiTool struct {
	Name     string
	Procs    []string
	Services []string
	TaskHint []string // lowercase fragments of scheduled task names
}

var dpiTools = []dpiTool{
	{Name: "zapret", Procs: []string{"winws.exe"}, Services: []string{"zapret", "winws1", "winws2", "winws3"}, TaskHint: []string{"winws", "zapret"}},
	{Name: "zapret2", Procs: []string{"winws2.exe"}, Services: []string{"zapret2"}},
	{Name: "GoodbyeDPI", Procs: []string{"goodbyedpi.exe"}, Services: []string{"GoodbyeDPI"}, TaskHint: []string{"goodbyedpi"}},
	{Name: "ByeDPI", Procs: []string{"ciadpi.exe", "byedpi.exe"}, Services: []string{"ByeDPI", "byedpi"}, TaskHint: []string{"byedpi", "ciadpi"}},
	{Name: "SpoofDPI", Procs: []string{"spoofdpi.exe"}, Services: []string{"SpoofDPI", "spoofdpi"}, TaskHint: []string{"spoofdpi"}},
}

// avProducts that intercept traffic and are known to fight WinDivert tools.
var avProducts = []struct{ Name, Proc string }{
	{"Kaspersky", "avp.exe"},
	{"ESET", "ekrn.exe"},
	{"Dr.Web", "dwservice.exe"},
	{"AdGuard", "adguardsvc.exe"},
	{"Avast", "avastsvc.exe"},
	{"AVG", "avgsvc.exe"},
	{"Bitdefender", "bdservicehost.exe"},
}

// vpnHints are lowercase fragments of tunnel adapter names/descriptions.
var vpnHints = []string{"wintun", "wireguard", "tap-windows", "tap adapter", "openvpn", "amnezia", "outline", "hiddify",
	"sing-box", "singbox", "clash", "mihomo", "v2ray", "xray", "nekoray", "throne", "cloudflare warp", "warp", "proton",
	"kaspersky", "windscribe", "nordlynx", "tunnel", "vpn", "tun"}

func detectEnv(a *App) Env {
	var env Env
	env.Findings = append(env.Findings, detectDPITools(a)...)
	if f, ok := detectOwnService(a); ok {
		env.Findings = append(env.Findings, f)
	}
	if f, ok := detectVPN(); ok {
		env.Findings = append(env.Findings, f)
	}
	if f, ok := detectProxy(); ok {
		env.Findings = append(env.Findings, f)
	}
	if f, ok := detectHosts(); ok {
		env.Findings = append(env.Findings, f)
	}
	if f, ok := detectAV(); ok {
		env.Findings = append(env.Findings, f)
	}
	if f, ok := detectARM(); ok {
		env.Findings = append(env.Findings, f)
	}
	return env
}

func detectDPITools(a *App) []Finding {
	tasks := listTaskNames()
	var out []Finding
	for _, t := range dpiTools {
		var procs []procInfo
		for _, p := range listProcs(t.Procs...) {
			if !a.ownsPath(p.Path) {
				procs = append(procs, p)
			}
		}
		var svcs []svcInfo
		for _, n := range t.Services {
			if si := queryService(n); si.Exists && !strings.Contains(strings.ToLower(si.BinPath), strings.ToLower(a.dataDir)) {
				svcs = append(svcs, si)
			}
		}
		var tk []string
		for _, name := range tasks {
			ln := strings.ToLower(name)
			if strings.Contains(ln, "ezpzdpi") {
				continue
			}
			for _, h := range t.TaskHint {
				if strings.Contains(ln, h) {
					tk = append(tk, name)
					break
				}
			}
		}
		if len(procs) == 0 && len(svcs) == 0 && len(tk) == 0 {
			continue
		}
		f := Finding{ID: "dpi:" + strings.ToLower(t.Name), Kind: "dpi", Level: "warn"}
		for _, p := range procs {
			f.Procs = append(f.Procs, ProcRef{PID: p.PID, Name: p.Name, Path: p.Path})
		}
		label := t.Name
		var where []string
		running := len(procs) > 0
		for _, s := range svcs {
			f.Services = append(f.Services, s.Name)
			if s.Running {
				running = true
			}
			if strings.Contains(strings.ToLower(s.BinPath), "zapret-discord-youtube") || flowsealStrategy(s.Name) != "" {
				label = "zapret (Flowseal)"
			}
			state := "остановлена"
			if s.Running {
				state = "работает"
			}
			where = append(where, fmt.Sprintf("служба «%s» (%s)", s.Name, state))
			if st := flowsealStrategy(s.Name); st != "" {
				where = append(where, "вариант "+st)
			}
		}
		for _, p := range procs {
			if strings.Contains(strings.ToLower(p.Path), "zapret-discord-youtube") {
				label = "zapret (Flowseal)"
			}
			where = append(where, "запущен из "+filepath.Dir(p.Path))
		}
		for _, n := range tk {
			where = append(where, "задача «"+n+"»")
		}
		f.Active = running
		f.Title = "Найден другой обход: " + label
		if running {
			f.Text = "Он сейчас работает, поэтому проверка показывает результат с ним. " + strings.Join(where, ", ") + "."
			f.Acts = []Action{{ID: "check-without", Label: "Проверить без него"}, {ID: "disable-foreign", Label: "Отключить его"}}
		} else {
			f.Level = "info"
			f.Text = "Сейчас он не запущен. " + strings.Join(where, ", ") + "."
			f.Acts = []Action{{ID: "disable-foreign", Label: "Убрать из автозапуска"}}
		}
		out = append(out, f)
	}
	return out
}

// flowsealStrategy reads the strategy name Flowseal's service.bat stores
// next to its service, if any.
func flowsealStrategy(service string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+service, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	for _, n := range names {
		if v, _, err := k.GetStringValue(n); err == nil && strings.HasPrefix(strings.ToLower(v), "general") {
			return v
		}
	}
	return ""
}

func listTaskNames() []string {
	out, err := runHiddenOutput("schtasks.exe", "/Query", "/FO", "CSV", "/NH")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			continue
		}
		n := strings.TrimPrefix(line[1:end+1], `\`)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func detectOwnService(a *App) (Finding, bool) {
	si := queryService(serviceName)
	if !si.Exists || si.Running {
		return Finding{}, false
	}
	return Finding{ID: "own:stopped", Kind: "own", Level: "warn", Title: "Служба EzPzDPI остановлена",
		Text: "Обход установлен, но сейчас не работает. Возможно, его остановил антивирус или служба упала.",
		Acts: []Action{{ID: "restart-own", Label: "Запустить снова"}}}, true
}

// detectVPN checks whether traffic to the internet leaves through a tunnel.
func detectVPN() (Finding, bool) {
	name, desc, ok := bestRouteAdapter()
	if !ok {
		return Finding{}, false
	}
	l := strings.ToLower(name + " " + desc)
	for _, h := range vpnHints {
		if strings.Contains(l, h) {
			return Finding{ID: "vpn", Kind: "vpn", Level: "warn", Active: true,
				Title: "Похоже, включён VPN",
				Text:  fmt.Sprintf("Интернет идёт через «%s». Пока VPN включён, проверка показывает работу через него, а не через провайдера. Для честного диагноза выключите VPN и проверьте снова.", name),
				Acts:  []Action{{ID: "recheck", Label: "Проверить снова"}}}, true
		}
	}
	return Finding{}, false
}

// bestRouteAdapter returns the adapter Windows uses to reach the internet.
func bestRouteAdapter() (name, desc string, ok bool) {
	var idx uint32
	sa := &windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return "", "", false
	}
	size := uint32(16 << 10)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return "", "", false
		}
		for p := aa; p != nil; p = p.Next {
			if p.IfIndex == idx {
				return windows.UTF16PtrToString(p.FriendlyName), windows.UTF16PtrToString(p.Description), true
			}
		}
		return "", "", false
	}
	return "", "", false
}

func detectProxy() (Finding, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return Finding{}, false
	}
	defer k.Close()
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	pac, _, _ := k.GetStringValue("AutoConfigURL")
	if (en == 0 || server == "") && pac == "" {
		return Finding{}, false
	}
	what := server
	if pac != "" {
		what = "автонастройка " + pac
	}
	return Finding{ID: "proxy", Kind: "proxy", Level: "info", Active: true,
		Title: "В Windows включён прокси",
		Text:  "Браузер ходит через " + what + ". Так работают ByeDPI, v2rayN и похожие программы. EzPzDPI проверяет прямое соединение, поэтому в браузере результат может отличаться."}, true
}

func hostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// hostsWatch are names old guides redirect in hosts; any override of them
// breaks the bypass or the check.
func hostsWatch() []string {
	names := []string{"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "discord.com", "discord.gg", "discordapp.com",
		"discordapp.net", "discord.media", "instagram.com", "cdninstagram.com", "facebook.com", "twitter.com", "x.com", "twimg.com"}
	for _, s := range catalog {
		names = append(names, s.Domains...)
		for _, t := range s.Targets {
			names = append(names, t.Host)
		}
	}
	return names
}

func hostsOverrides() []string {
	data, err := os.ReadFile(hostsPath())
	if err != nil {
		return nil
	}
	watch := hostsWatch()
	var hits []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		for _, h := range fields[1:] {
			if strings.HasPrefix(h, "#") {
				break
			}
			if matchesAny(strings.ToLower(h), watch) {
				hits = append(hits, t)
				break
			}
		}
	}
	return hits
}

func matchesAny(host string, domains []string) bool {
	for _, d := range domains {
		d = strings.ToLower(d)
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func detectHosts() (Finding, bool) {
	hits := hostsOverrides()
	if len(hits) == 0 {
		return Finding{}, false
	}
	sample := hits[0]
	if len(hits) > 1 {
		sample += fmt.Sprintf(" и ещё %d", len(hits)-1)
	}
	return Finding{ID: "hosts", Kind: "hosts", Level: "warn", Active: true, Hosts: hits,
		Title: "В файле hosts есть старые записи",
		Text:  "Записи вида «" + sample + "» остались от старых инструкций. Они направляют сайты на чужие адреса и мешают обходу. EzPzDPI может убрать их, сохранив копию файла.",
		Acts:  []Action{{ID: "clean-hosts", Label: "Убрать записи"}}}, true
}

// cleanHosts removes override lines for watched names and keeps a backup.
func cleanHosts() (string, error) {
	p := hostsPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	backup := p + ".ezpzdpi-" + time.Now().Format("20060102-150405") + ".bak"
	if err := os.WriteFile(backup, data, 0o644); err != nil {
		return "", err
	}
	watch := hostsWatch()
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		fields := strings.Fields(t)
		drop := false
		if len(fields) >= 2 && !strings.HasPrefix(t, "#") && net.ParseIP(fields[0]) != nil {
			for _, h := range fields[1:] {
				if strings.HasPrefix(h, "#") {
					break
				}
				if matchesAny(strings.ToLower(h), watch) {
					drop = true
					break
				}
			}
		}
		if !drop {
			keep = append(keep, line)
		}
	}
	out := strings.TrimRight(strings.Join(keep, "\r\n"), "\r\n") + "\r\n"
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		return backup, err
	}
	_ = runHidden("ipconfig.exe", "/flushdns")
	return backup, nil
}

func detectAV() (Finding, bool) {
	var names []string
	for _, av := range avProducts {
		if len(listProcs(av.Proc)) > 0 {
			names = append(names, av.Name)
		}
	}
	if len(names) == 0 {
		return Finding{}, false
	}
	return Finding{ID: "av", Kind: "av", Level: "info",
		Title: "Антивирус может мешать обходу: " + strings.Join(names, ", "),
		Text:  "Если обход не включится или пропадёт через время, добавьте папку C:\\ProgramData\\EzPzDPI в исключения антивируса. Если сайты всё равно не открываются, отключите в нём проверку защищённых (HTTPS) соединений."}, true
}

func detectARM() (Finding, bool) {
	var procMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &procMachine, &nativeMachine); err != nil {
		return Finding{}, false
	}
	const imageFileMachineARM64 = 0xAA64
	if nativeMachine != imageFileMachineARM64 {
		return Finding{}, false
	}
	return Finding{ID: "arm64", Kind: "platform", Level: "error",
		Title: "Компьютер на процессоре ARM",
		Text:  "Драйвер WinDivert, на котором работает обход, не подписан для ARM. На этом компьютере обход не запустится, поможет только VPN."}, true
}

// disableForeign stops other tools and keeps their services from starting
// again, remembering the original start types so they can be restored.
func disableForeign(a *App, f Finding) error {
	if a.cfg.ForeignDisabled == nil {
		a.cfg.ForeignDisabled = map[string]uint32{}
	}
	var errs []string
	for _, name := range f.Services {
		si := queryService(name)
		if !si.Exists {
			continue
		}
		if _, seen := a.cfg.ForeignDisabled[name]; !seen && si.StartType != windows.SERVICE_DISABLED {
			a.cfg.ForeignDisabled[name] = si.StartType
		}
		if err := stopService(name); err != nil {
			errs = append(errs, err.Error())
		}
		if err := setServiceStart(name, windows.SERVICE_DISABLED, false); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, p := range f.Procs {
		if err := killPID(p.PID); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(p.Path), err))
		}
	}
	_ = stopAndDeleteService("WinDivert")
	a.saveConfig()
	a.logf("disabled foreign %s: services %v, procs %d, errors %v", f.ID, f.Services, len(f.Procs), errs)
	if len(errs) > 0 {
		return fmt.Errorf("не всё удалось остановить: %s", strings.Join(errs, "; "))
	}
	return nil
}

// pauseForeign stops other tools for a check and returns a function that
// starts their services again. Processes cannot be restarted.
func pauseForeign(a *App, fs []Finding) func() {
	var started []string
	for _, f := range fs {
		for _, name := range f.Services {
			if queryService(name).Running {
				if stopService(name) == nil {
					started = append(started, name)
				}
			}
		}
		for _, p := range f.Procs {
			_ = killPID(p.PID)
		}
	}
	return func() {
		for _, name := range started {
			if err := setServiceStart(name, queryService(name).StartType, true); err != nil {
				a.logf("restart %s: %v", name, err)
			}
		}
	}
}
