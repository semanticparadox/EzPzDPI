//go:build windows

package main

// Environment detection (module A): what else on this PC affects the bypass
// or the check, plus the reversible actions the notices offer. Detection
// only reads; every change happens in an action the user pressed, is
// recorded in a.cfg for undo and written to the journal.
//
// Everything is read through APIs, the registry, files, and CSV/XML with a
// fixed layout, so it works the same on Russian and English Windows. The
// pure parsers live in detect_parse.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// DLL entry points used only here. The names are prefixed so they do not
// clash with other files that load the same DLLs.
var (
	detKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	detGlobalFree        = detKernel32.NewProc("GlobalFree")
	detWinhttp           = windows.NewLazySystemDLL("winhttp.dll")
	detWinHTTPProxy      = detWinhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	detWininet           = windows.NewLazySystemDLL("wininet.dll")
	detInternetSetOption = detWininet.NewProc("InternetSetOptionW")
	detDnsapi            = windows.NewLazySystemDLL("dnsapi.dll")
	detDNSFlush          = detDnsapi.NewProc("DnsFlushResolverCache")
)

// errForeignGone means the other tool's files or registration no longer
// exist, so there is nothing to bring back.
var errForeignGone = errors.New("программа удалена")

const servicesKey = `SYSTEM\CurrentControlSet\Services\`

// ---------------------------------------------------------------------------
// Raw inventory
// ---------------------------------------------------------------------------

type scanProc struct {
	PID, PPID  uint32
	Name, Path string // Path only for processes detection cares about
}

type scanService struct {
	Name, Display string
	ImagePath     string // environment-expanded
	Exe           string // program or .sys file from ImagePath
	Type          uint32
	Start         uint32
	State         uint32
	Strategy      string // Flowseal's "zapret-discord-youtube" value
}

func (s scanService) driver() bool { return s.Type&windows.SERVICE_DRIVER != 0 }

func (s scanService) running() bool {
	return s.State == windows.SERVICE_RUNNING || s.State == windows.SERVICE_START_PENDING
}

// bypassTool tells which bypass tool a (non-driver) service belongs to.
func (s scanService) bypassTool() string {
	if t, ok := knownBypassServices[strings.ToLower(s.Name)]; ok {
		return t
	}
	return bypassToolOf(s.ImagePath)
}

// dead reports a service whose program file no longer exists (E09).
func (s scanService) dead() bool {
	return filepath.IsAbs(s.Exe) && !fileExists(s.Exe)
}

// scanAutorun is a Startup-folder file or a Run/RunOnce value.
type scanAutorun struct {
	Ref   string // file path, or runEntryRef(...) for a registry value
	Tool  string
	User  string // profile name when it belongs to another user (E15)
	Label string // how it is shown
}

type scanRoute struct {
	OK         bool
	Name, Desc string
	IfType     uint32
	Split      bool // 0.0.0.0/1 + 128.0.0.0/1 style routes on this adapter
}

type scanProxy struct {
	Enable      uint32
	Server, PAC string
	Dead        bool // every local endpoint refused the connection
	WinHTTP     string
}

type userProfile struct{ SID, Dir, Name string }

// envScan holds everything collected for one detectEnv call.
type envScan struct {
	sysRoot  string
	profiles []userProfile
	procs    []scanProc
	byPID    map[uint32]scanProc
	services []scanService
	tasks    []schedTask
	events   []scmEvent
	autoruns []scanAutorun
	route    scanRoute
	proxy    scanProxy
	hosts    []string
	drover   []string
	hvci     bool
}

// detectEnv scans the PC. Independent probes run concurrently and the
// event log is queried once, so the whole scan stays within a few seconds.
func detectEnv(a *App) Env {
	start := time.Now()
	s := collectScan(a)
	fs := s.foreignFindings(a)
	for _, build := range []func() (Finding, bool){
		func() (Finding, bool) { return s.enginesFinding(a) },
		func() (Finding, bool) { return s.leftoversFinding(a) },
		s.ownFinding,
		s.vpnFinding,
		s.proxyFinding,
		s.hostsFinding,
		func() (Finding, bool) { return s.avFinding(a) },
		s.anticheatFinding,
		s.droverFinding,
		s.bfeFinding,
		s.hvciFinding,
		detectARM,
	} {
		if f, ok := build(); ok {
			fs = append(fs, f)
		}
	}
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.ID
	}
	a.logf("detect: %v in %v", ids, time.Since(start).Round(time.Millisecond))
	return Env{Findings: fs}
}

func collectScan(a *App) *envScan {
	s := &envScan{sysRoot: detSystemRoot(), profiles: userProfiles()}
	var wg sync.WaitGroup
	run := func(name string, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					a.logf("detect %s: panic: %v", name, r)
				}
			}()
			f()
		}()
	}
	run("procs", func() { s.procs = snapshotProcs() })
	run("services", func() { s.services = enumAllServices(s.sysRoot) })
	run("tasks", func() { s.tasks = bypassTasks(a, s.sysRoot) })
	run("events", func() { s.events = scmEventsLastWeek() })
	run("autoruns", func() { s.autoruns = bypassAutoruns(a, s.profiles) })
	run("route", func() { s.route = defaultRouteInfo() })
	run("proxy", func() { s.proxy = readProxy() })
	run("files", func() {
		s.hosts = hostsOverrideLines(readHostsFile(), hostsWatchList())
		s.drover = droverFiles(s.profiles)
		s.hvci = hvciEnabled()
	})
	wg.Wait()
	s.byPID = make(map[uint32]scanProc, len(s.procs))
	for _, p := range s.procs {
		s.byPID[p.PID] = p
	}
	return s
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

func detSystemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

func detSys32(exe string) string { return filepath.Join(detSystemRoot(), "System32", exe) }

// detectRun runs a system tool hidden with a deadline and returns stdout.
func detectRun(timeout time.Duration, exe string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Output()
}

// consoleText decodes tool output. Piped console tools write in the OEM
// code page (866 on Russian Windows) or, without a console, sometimes in
// the ANSI one (1251); the decoding that yields real Russian letters wins.
// It matters for task names, which are passed back to schtasks.
func consoleText(b []byte) string {
	if len(b) == 0 || utf8.Valid(b) {
		return string(b)
	}
	const cpACP, cpOEM = 0, 1
	best, bestScore := string(b), -1<<31
	for _, cp := range []uint32{cpOEM, cpACP} {
		if s, ok := decodeCodePage(cp, b); ok && cyrillicScore(s) > bestScore {
			best, bestScore = s, cyrillicScore(s)
		}
	}
	return best
}

func decodeCodePage(cp uint32, b []byte) (string, bool) {
	n, err := windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n <= 0 {
		return "", false
	}
	w := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), &w[0], n); err != nil {
		return "", false
	}
	return string(utf16.Decode(w)), true
}

func detExpand(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if v, err := registry.ExpandString(s); err == nil {
		return v
	}
	return s
}

// detReadFile reads up to limit bytes of a file; "" when it cannot.
func detReadFile(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	return string(b)
}

// watchedProcs are the image names whose full path detection needs.
func watchedProc(lowName string) bool {
	if _, ok := foreignProcTools[lowName]; ok {
		return true
	}
	if _, ok := avProcNames[lowName]; ok {
		return true
	}
	return packetEngines[lowName] || lowName == "adguardsvc.exe" || lowName == "warp-svc.exe" ||
		reVPNClientProc.MatchString(lowName)
}

func snapshotProcs() []scanProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []scanProc
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := scanProc{PID: pe.ProcessID, PPID: pe.ParentProcessID, Name: windows.UTF16ToString(pe.ExeFile[:])}
		if watchedProc(strings.ToLower(p.Name)) {
			p.Path = procPath(p.PID)
		}
		out = append(out, p)
	}
	return out
}

// enumAllServices lists every service and driver with its state from one
// EnumServicesStatusEx call, then reads ImagePath/Start from the registry
// (cheaper than opening each service through SCM).
func enumAllServices(sysRoot string) []scanService {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(h)
	var buf []byte
	var needed, count uint32
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err = windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32|windows.SERVICE_DRIVER,
			windows.SERVICE_STATE_ALL, p, uint32(len(buf)), &needed, &count, nil, nil)
		if err == nil {
			break
		}
		if err != windows.ERROR_MORE_DATA || needed <= uint32(len(buf)) {
			return nil
		}
		buf = make([]byte, needed)
	}
	if count == 0 {
		return nil
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(count))
	out := make([]scanService, 0, len(entries))
	for _, e := range entries {
		sv := scanService{
			Name:    windows.UTF16PtrToString(e.ServiceName),
			Display: windows.UTF16PtrToString(e.DisplayName),
			Type:    e.ServiceStatusProcess.ServiceType,
			State:   e.ServiceStatusProcess.CurrentState,
			Start:   windows.SERVICE_DEMAND_START, // until the registry says otherwise
		}
		readServiceKey(&sv, sysRoot)
		out = append(out, sv)
	}
	return out
}

func readServiceKey(sv *scanService, sysRoot string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey+sv.Name, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	ip, _, _ := k.GetStringValue("ImagePath")
	sv.ImagePath = detExpand(ip)
	sv.Exe = imageExePath(sv.ImagePath, sysRoot)
	if st, _, err := k.GetIntegerValue("Start"); err == nil {
		sv.Start = uint32(st)
	}
	if !sv.driver() && sv.bypassTool() != "" {
		sv.Strategy, _, _ = k.GetStringValue("zapret-discord-youtube")
	}
}

// bypassTasks lists scheduled tasks that start a bypass tool. The CSV
// gives names and actions by column position; the enabled flag comes from
// the task's XML file, because the CSV status column is translated. The
// verbose query can take seconds on a busy PC; if it fails or runs out of
// time its output may be cut, so it is not parsed and the task files are
// read directly instead.
func bypassTasks(a *App, sysRoot string) []schedTask {
	var all []schedTask
	out, err := detectRun(10*time.Second, detSys32("schtasks.exe"), "/Query", "/FO", "CSV", "/V", "/NH")
	if err != nil {
		a.logf("detect tasks: schtasks: %v; reading task files instead", err)
		all = taskFilesList(sysRoot)
	} else {
		all = parseSchtasksCSV(consoleText(out))
	}
	var hits []schedTask
	for _, t := range all {
		low := strings.ToLower(t.Name)
		base := low[strings.LastIndex(low, `\`)+1:]
		named := base == "winws1" || base == "winws2" || base == "winws3"
		if strings.Contains(low, "ezpzdpi") || (!named && bypassToolOf(t.Action) == "") {
			continue
		}
		if strings.Contains(strings.ToLower(detExpand(t.Action)), strings.ToLower(a.dataDir)+`\`) {
			continue
		}
		t.Enabled = taskFileEnabled(sysRoot, t.Name)
		hits = append(hits, t)
	}
	return hits
}

// taskFilesList reads every task definition under %SystemRoot%\System32\Tasks
// (the scheduler's own store). Tasks without an Exec action are skipped.
func taskFilesList(sysRoot string) []schedTask {
	root := filepath.Join(sysRoot, "System32", "Tasks")
	var out []schedTask
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // unreadable folders are skipped, the rest is still read
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		action, ok := taskXMLAction(decodeTaskXML([]byte(detReadFile(path, 256<<10))))
		if ok {
			out = append(out, schedTask{Name: taskNameFromPath(rel), Action: action, Enabled: true})
		}
		return nil
	})
	return out
}

// taskFileEnabled reads %SystemRoot%\System32\Tasks\<path> (UTF-16 XML).
func taskFileEnabled(sysRoot, name string) bool {
	doc := detReadFile(filepath.Join(sysRoot, "System32", "Tasks", strings.TrimPrefix(name, `\`)), 256<<10)
	return taskXMLEnabled(decodeTaskXML([]byte(doc)))
}

// scmEventsLastWeek reads service crash and start-failure events (E07).
func scmEventsLastWeek() []scmEvent {
	const q = "*[System[Provider[@Name='Service Control Manager'] and " +
		"(EventID=7000 or EventID=7023 or EventID=7031 or EventID=7034) and " +
		"TimeCreated[timediff(@SystemTime) <= 604800000]]]"
	out, err := detectRun(2500*time.Millisecond, detSys32("wevtutil.exe"), "qe", "System", "/q:"+q, "/f:xml", "/rd:true", "/c:300")
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseSCMEvents(consoleText(out))
}

// userProfiles lists real user profiles (S-1-5-21-*) from ProfileList.
func userProfiles() []userProfile {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	var out []userProfile
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dir, _, _ := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if dir = detExpand(dir); dir != "" {
			out = append(out, userProfile{SID: sid, Dir: dir, Name: filepath.Base(dir)})
		}
	}
	return out
}

// otherUser returns the profile name when it is not the current user, so
// the text can say whose autostart it is (E15).
func otherUser(name string) string {
	if name == "" || strings.EqualFold(name, os.Getenv("USERNAME")) {
		return ""
	}
	return name
}

// bypassAutoruns finds Run/RunOnce values (machine and every loaded user
// hive) and Startup-folder files that start a bypass tool. Hives of
// logged-off users are not loaded: that needs extra privileges and the
// files stay locked by nothing, so their Startup folders are scanned only.
func bypassAutoruns(a *App, profiles []userProfile) []scanAutorun {
	own := strings.ToLower(a.dataDir) + `\`
	var out []scanAutorun
	addRun := func(root registry.Key, rootName, path, user string) {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			data, _, err := k.GetStringValue(n)
			tool := bypassToolOf(data)
			if err != nil || tool == "" || strings.Contains(strings.ToLower(data), own) {
				continue
			}
			out = append(out, scanAutorun{Ref: runEntryRef(rootName+`\`+path, n), Tool: tool, User: otherUser(user),
				Label: "запись автозапуска «" + n + "» в реестре"})
		}
	}
	const run, runOnce = `Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	for _, p := range []string{run, runOnce, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`} {
		addRun(registry.LOCAL_MACHINE, "HKLM", p, "")
	}
	byName := map[string]string{}
	for _, p := range profiles {
		byName[p.SID] = p.Name
	}
	if hk, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := hk.ReadSubKeyNames(-1)
		hk.Close()
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				addRun(registry.USERS, "HKU", sid+`\`+run, byName[sid])
				addRun(registry.USERS, "HKU", sid+`\`+runOnce, byName[sid])
			}
		}
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	out = append(out, startupFolder(filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`), "")...)
	for _, p := range profiles {
		out = append(out, startupFolder(filepath.Join(p.Dir, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), p.Name)...)
	}
	return out
}

func startupFolder(dir, user string) []scanAutorun {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []scanAutorun
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if tool := startupFileTool(p); tool != "" {
			out = append(out, scanAutorun{Ref: p, Tool: tool, User: otherUser(user),
				Label: "ярлык «" + e.Name() + "» в автозагрузке"})
		}
	}
	return out
}

// startupFileTool looks inside a Startup entry. A .lnk stores its target
// path as ANSI or UTF-16 text, so a byte search with NULs removed finds it
// without a full shell-link parser.
func startupFileTool(path string) string {
	name := filepath.Base(path)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe":
		return bypassToolOf(name)
	case ".lnk", ".bat", ".cmd", ".vbs", ".ps1", ".url":
		body := strings.ReplaceAll(detReadFile(path, 64<<10), "\x00", "")
		return bypassToolOf(name + "\n" + body)
	}
	return ""
}

// defaultRouteInfo finds the adapter Windows uses to reach the internet.
func defaultRouteInfo() scanRoute {
	var idx uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}, &idx); err != nil {
		return scanRoute{}
	}
	r := scanRoute{Split: splitRouteIfaces()[idx]}
	size := uint32(16 << 10)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return r
		}
		for p := aa; p != nil; p = p.Next {
			if p.IfIndex == idx {
				r.OK, r.IfType = true, p.IfType
				r.Name, r.Desc = windows.UTF16PtrToString(p.FriendlyName), windows.UTF16PtrToString(p.Description)
				return r
			}
		}
		return r
	}
	return r
}

// splitRouteIfaces returns adapters that carry both halves of the address
// space (0.0.0.0/1 + 128.0.0.0/1 or ::/1 + 8000::/1): WireGuard-style VPNs
// install these instead of a default route.
func splitRouteIfaces() map[uint32]bool {
	var t *windows.MibIpForwardTable2
	if windows.GetIpForwardTable2(windows.AF_UNSPEC, &t) != nil || t == nil {
		return nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	halves := map[[2]uint32]uint8{}
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength != 1 {
			continue
		}
		fam := r.DestinationPrefix.Prefix.Family
		var first byte
		switch fam {
		case windows.AF_INET:
			first = (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.DestinationPrefix.Prefix)).Addr[0]
		case windows.AF_INET6:
			first = (*windows.RawSockaddrInet6)(unsafe.Pointer(&r.DestinationPrefix.Prefix)).Addr[0]
		default:
			continue
		}
		key := [2]uint32{r.InterfaceIndex, uint32(fam)}
		switch first {
		case 0:
			halves[key] |= 1
		case 0x80:
			halves[key] |= 2
		}
	}
	out := map[uint32]bool{}
	for k, v := range halves {
		if v == 3 {
			out[k[0]] = true
		}
	}
	return out
}

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// readProxy reads the WinINET proxy of the signed-in user (see
// proxyUserKey) and the machine WinHTTP proxy.
func readProxy() scanProxy {
	var p scanProxy
	root, path, _ := proxyUserKey()
	if k, err := registry.OpenKey(root, path, registry.QUERY_VALUE); err == nil {
		en, _, _ := k.GetIntegerValue("ProxyEnable")
		p.Enable = uint32(en)
		p.Server, _, _ = k.GetStringValue("ProxyServer")
		p.PAC, _, _ = k.GetStringValue("AutoConfigURL")
		k.Close()
	}
	p.Dead = proxyDead(p)
	p.WinHTTP = winHTTPProxy()
	return p
}

// proxyUserKey returns where the signed-in user's Internet Settings live.
// EzPzDPI always runs elevated; when someone typed another account's
// password in the UAC prompt, HKCU is that admin's hive, not the hive of
// the person whose browser uses the proxy. So the key is opened under
// HKEY_USERS\<SID> of the user who owns this desktop (the SID of its
// explorer.exe). When that cannot be found, HKCU is used. label names the
// hive for the log.
func proxyUserKey() (root registry.Key, path, label string) {
	if sid := interactiveUserSID(); sid != "" {
		if k, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE); err == nil {
			k.Close()
			return registry.USERS, sid + `\` + internetSettingsKey, `HKU\` + sid
		}
	}
	return registry.CURRENT_USER, internetSettingsKey, "HKCU"
}

// interactiveUserSID returns the SID of the user signed in to this
// desktop: the owner of %SystemRoot%\explorer.exe in our own session, or
// else in the console session. "" when there is none (no shell running).
func interactiveUserSID() string {
	own := ^uint32(0)
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own); err != nil {
		own = ^uint32(0)
	}
	console := windows.WTSGetActiveConsoleSessionId()
	shell := filepath.Join(detSystemRoot(), "explorer.exe")
	consoleSID := ""
	for _, p := range listProcs("explorer.exe") {
		if !strings.EqualFold(p.Path, shell) {
			continue
		}
		var sess uint32
		if windows.ProcessIdToSessionId(p.PID, &sess) != nil || (sess != own && sess != console) {
			continue
		}
		sid := procUserSID(p.PID)
		if !validSID(sid) {
			continue
		}
		if sess == own {
			return sid
		}
		if consoleSID == "" {
			consoleSID = sid
		}
	}
	return consoleSID
}

// procUserSID returns the user SID of a process's token.
func procUserSID(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// proxyDead dials the local endpoints of the active proxy. It is dead only
// when there is at least one local endpoint and none of them accepts a
// connection; remote proxies are not judged.
func proxyDead(p scanProxy) bool {
	var local []string
	if p.Enable != 0 {
		for _, ep := range proxyEndpoints(p.Server) {
			if isLocalEndpoint(ep) {
				local = append(local, ep)
			}
		}
	}
	if ep := pacEndpoint(p.PAC); ep != "" && isLocalEndpoint(ep) {
		local = append(local, ep)
	}
	if len(local) == 0 {
		return false
	}
	for _, ep := range local {
		if c, err := net.DialTimeout("tcp", ep, 400*time.Millisecond); err == nil {
			c.Close()
			return false
		}
	}
	return true
}

type winHTTPProxyInfo struct {
	AccessType    uint32
	Proxy, Bypass *uint16
}

// winHTTPProxy returns the machine WinHTTP proxy (netsh winhttp), via the
// API because netsh prints translated text.
func winHTTPProxy() string {
	if detWinHTTPProxy.Find() != nil {
		return ""
	}
	var info winHTTPProxyInfo
	if r, _, _ := detWinHTTPProxy.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return ""
	}
	defer func() {
		for _, p := range []*uint16{info.Proxy, info.Bypass} {
			if p != nil {
				detGlobalFree.Call(uintptr(unsafe.Pointer(p)))
			}
		}
	}()
	const namedProxy = 3
	if info.AccessType != namedProxy || info.Proxy == nil {
		return ""
	}
	return windows.UTF16PtrToString(info.Proxy)
}

func hostsFilePath() string {
	return filepath.Join(detSystemRoot(), "System32", "drivers", "etc", "hosts")
}

func readHostsFile() string { return detReadFile(hostsFilePath(), 4<<20) }

// hostsWatchList: names whose overrides break the bypass or the check —
// catalog domains, names old unblock guides redirect, and Flowseal's hosts
// payload (discord.com, github.com, telegram).
func hostsWatchList() []string {
	names := []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
		"instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "twitter.com", "x.com", "twimg.com",
		"telegram.org", "t.me", "github.com", "githubusercontent.com"}
	for _, s := range catalog {
		names = append(names, s.Domains...)
		for _, t := range s.Targets {
			if net.ParseIP(t.Host) == nil {
				names = append(names, t.Host)
			}
		}
	}
	return names
}

// droverFiles finds Discord Drover (version.dll + drover.ini in the app
// folder). Discord itself ships no version.dll there, so either file means
// Discord's TCP goes through a proxy while voice does not (E13).
func droverFiles(profiles []userProfile) []string {
	var out []string
	for _, p := range profiles {
		for _, app := range []string{"Discord", "DiscordPTB", "DiscordCanary"} {
			dirs, _ := filepath.Glob(filepath.Join(p.Dir, "AppData", "Local", app, "app-*"))
			for _, d := range dirs {
				if fileExists(filepath.Join(d, "drover.ini")) || fileExists(filepath.Join(d, "version.dll")) {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

func hvciEnabled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Enabled")
	return err == nil && v == 1
}

func (s *envScan) service(name string) (scanService, bool) {
	for _, sv := range s.services {
		if strings.EqualFold(sv.Name, name) {
			return sv, true
		}
	}
	return scanService{}, false
}

func (s *envScan) hasProc(lowName string) bool {
	for _, p := range s.procs {
		if strings.EqualFold(p.Name, lowName) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Other bypass tools (E01-E03, E07, E10-E12, E15, E16)
// ---------------------------------------------------------------------------

// toolInv is everything found for one bypass tool.
type toolInv struct {
	key      string
	procs    []ProcRef
	services []scanService
	tasks    []schedTask
	autoruns []scanAutorun
}

func (t *toolInv) empty() bool {
	return len(t.procs)+len(t.services)+len(t.tasks)+len(t.autoruns) == 0
}

// running: an engine or proxy process or one of its services is up. A
// manager GUI alone does not count.
func (t *toolInv) running() bool {
	for _, p := range t.procs {
		if !p.Manager {
			return true
		}
	}
	for _, sv := range t.services {
		if sv.running() {
			return true
		}
	}
	return false
}

// autostart: something starts it with Windows or at logon.
func (t *toolInv) autostart() bool {
	for _, sv := range t.services {
		if sv.Start <= windows.SERVICE_AUTO_START {
			return true
		}
	}
	return len(t.tasks) > 0 || len(t.autoruns) > 0
}

func (s *envScan) foreignInventory(a *App) map[string]*toolInv {
	inv := map[string]*toolInv{}
	get := func(key string) *toolInv {
		if inv[key] == nil {
			inv[key] = &toolInv{key: key}
		}
		return inv[key]
	}
	for _, p := range s.procs {
		low := strings.ToLower(p.Name)
		tool, ok := foreignProcTools[low]
		if !ok || a.ownsPath(p.Path) {
			continue
		}
		_, manager := foreignManagers[low]
		get(tool).procs = append(get(tool).procs, ProcRef{PID: p.PID, Name: p.Name, Path: p.Path,
			ParentName: s.byPID[p.PPID].Name, Manager: manager})
	}
	for _, sv := range s.services {
		if tool := s.foreignServiceTool(a, sv); tool != "" && !sv.dead() {
			get(tool).services = append(get(tool).services, sv)
		}
	}
	for _, t := range s.tasks {
		if !t.Enabled || taskDead(t) {
			continue
		}
		if tool := bypassToolOf(t.Name + " " + t.Action); tool != "" {
			get(tool).tasks = append(get(tool).tasks, t)
		}
	}
	for _, r := range s.autoruns {
		get(r.Tool).autoruns = append(get(r.Tool).autoruns, r)
	}
	return inv
}

// foreignServiceTool returns the tool of a non-driver service that is not
// ours, or "".
func (s *envScan) foreignServiceTool(a *App, sv scanService) string {
	if sv.driver() || strings.EqualFold(sv.Name, serviceName) || a.ownsPath(sv.Exe) {
		return ""
	}
	return sv.bypassTool()
}

// taskDead: the task runs a bypass file that no longer exists.
func taskDead(t schedTask) bool {
	target := detExpand(commandTarget(t.Action))
	return filepath.IsAbs(target) && !fileExists(target)
}

func (s *envScan) foreignFindings(a *App) []Finding {
	inv := s.foreignInventory(a)
	var out []Finding
	for _, key := range toolOrder {
		if t := inv[key]; t != nil && !t.empty() {
			s.logTool(a, t)
			out = append(out, s.toolFinding(a, t))
		}
	}
	return out
}

// logTool writes the raw inventory to app.log for support (E01).
func (s *envScan) logTool(a *App, t *toolInv) {
	for _, p := range t.procs {
		a.logf("detect %s: proc %d %s parent=%q manager=%v", t.key, p.PID, p.Path, p.ParentName, p.Manager)
	}
	for _, sv := range t.services {
		a.logf("detect %s: service %s state=%d start=%d strategy=%q image=%s", t.key, sv.Name, sv.State, sv.Start, sv.Strategy, sv.ImagePath)
	}
	for _, tk := range t.tasks {
		a.logf("detect %s: task %s action=%s", t.key, tk.Name, tk.Action)
	}
	for _, r := range t.autoruns {
		a.logf("detect %s: autorun %s user=%q", t.key, r.Ref, r.User)
	}
}

// toolDetails describes a tool's folder: Flowseal fingerprint, version,
// strategy, game filter and IP list mode (E02).
type toolDetails struct {
	label, root, version, strategy, ipset string
	flowseal, gameFilter                  bool
}

func toolRoot(exe string) string {
	dir := filepath.Dir(exe)
	switch strings.ToLower(filepath.Base(dir)) {
	case "bin", "x86_64", "x86":
		return filepath.Dir(dir)
	}
	return dir
}

func (t *toolInv) details() toolDetails {
	d := toolDetails{label: toolLabels[t.key]}
	var paths []string
	for _, p := range t.procs {
		if !p.Manager {
			paths = append(paths, p.Path)
		}
	}
	for _, sv := range t.services {
		paths = append(paths, sv.Exe)
		if d.strategy == "" {
			d.strategy = sv.Strategy
		}
	}
	for _, tk := range t.tasks {
		paths = append(paths, detExpand(commandTarget(tk.Action)))
	}
	for _, p := range paths {
		if filepath.IsAbs(p) {
			d.root = toolRoot(p)
			break
		}
	}
	if t.key != toolZapret || d.root == "" {
		return d
	}
	bat := detReadFile(filepath.Join(d.root, "service.bat"), 256<<10)
	d.flowseal = d.strategy != "" || (bat != "" && fileExists(filepath.Join(d.root, "bin", "winws.exe")))
	if !d.flowseal {
		return d
	}
	d.label = "zapret (Flowseal)"
	d.version = flowsealVersion(bat)
	d.gameFilter = fileExists(filepath.Join(d.root, "utils", "game_filter.enabled"))
	if ipset := filepath.Join(d.root, "lists", "ipset-all.txt"); fileExists(ipset) {
		d.ipset = ipsetMode(detReadFile(ipset, 4<<10))
	}
	return d
}

func (s *envScan) toolFinding(a *App, t *toolInv) Finding {
	d := t.details()
	running := t.running()
	f := Finding{ID: "dpi:" + t.key, Kind: "dpi", Level: "info", Active: running, Data: map[string]string{"label": d.label}}
	f.Title = strings.TrimSpace("Найден другой обход: " + d.label + " " + d.version)
	var text []string
	switch {
	case running:
		f.Level = "warn"
		text = append(text, "Он сейчас работает, поэтому проверка покажет результат вместе с ним.")
	case t.autostart():
		text = append(text, "Сейчас он не запущен, но настроен запускаться сам.")
	default:
		text = append(text, "Сейчас он не запущен.")
	}
	if d.root != "" {
		text = append(text, "Папка: "+d.root+".")
		f.Data["root"] = d.root
	}
	if how := s.startMethods(t); how != "" {
		text = append(text, "Как запускается: "+how+".")
	}
	if d.strategy != "" {
		text = append(text, "Способ «"+d.strategy+"».")
	}
	text = append(text, s.toolNotes(t, d, f.Data)...)
	if crash := s.crashNote(t, f.Data); crash != "" {
		f.Level = "warn"
		text = append(text, crash)
	}
	f.Text = strings.Join(text, " ")
	fillToolRefs(&f, t)
	f.Data["version"], f.Data["strategy"], f.Data["ipset"] = d.version, d.strategy, d.ipset
	if d.gameFilter {
		f.Data["game_filter"] = "1"
	}
	confirm := d.label + " будет отключён, но не удалён: его папка останется на месте. " +
		"Вернуть его можно в настройках кнопкой «Вернуть прежний обход»."
	if t.key == toolByeDPI || t.key == toolSpoofDPI {
		confirm += " Если прокси Windows указывал на него, он тоже будет выключен."
	}
	if running {
		f.Acts = []Action{{ID: "check-without", Label: "Проверить без него"},
			{ID: "disable-foreign", Label: "Заменить на EzPzDPI", Confirm: confirm}}
	} else {
		f.Acts = []Action{{ID: "disable-foreign", Label: "Убрать из автозапуска", Confirm: confirm}}
	}
	return f
}

// fillToolRefs copies what disableForeign needs. Managers come first in
// Procs and Services: they restart the engine if it is stopped before them.
func fillToolRefs(f *Finding, t *toolInv) {
	for _, pass := range []bool{true, false} {
		for _, p := range t.procs {
			if p.Manager == pass {
				f.Procs = append(f.Procs, p)
			}
		}
		for _, sv := range t.services {
			_, manager := foreignManagers[strings.ToLower(filepath.Base(sv.Exe))]
			if manager == pass {
				f.Services = append(f.Services, sv.Name)
			}
		}
	}
	for _, tk := range t.tasks {
		f.Tasks = append(f.Tasks, tk.Name)
	}
	for _, r := range t.autoruns {
		f.Shortcuts = append(f.Shortcuts, r.Ref)
	}
}

// startMethods lists how the tool starts: services, tasks, autostart
// entries, and engines started by hand from a console window (E03).
func (s *envScan) startMethods(t *toolInv) string {
	var how []string
	for _, sv := range t.services {
		w := "служба «" + sv.Name + "»"
		if sv.Start <= windows.SERVICE_AUTO_START {
			w += " (вместе с Windows)"
		}
		how = append(how, w)
	}
	for _, tk := range t.tasks {
		how = append(how, "задача планировщика «"+strings.TrimPrefix(tk.Name, `\`)+"»")
	}
	for _, r := range t.autoruns {
		w := r.Label
		if r.User != "" {
			w += " пользователя «" + r.User + "»"
		}
		how = append(how, w)
	}
	for _, p := range t.procs {
		if !p.Manager && launchedByHand(p.ParentName) && len(t.services) == 0 {
			how = append(how, "вручную из окна консоли — если закрыть это окно, обход выключится")
			break
		}
	}
	return strings.Join(how, "; ")
}

// launchedByHand: the engine's parent is a shell or already gone. Flowseal's
// general.bat uses `start`, so its cmd.exe exits and the parent disappears.
func launchedByHand(parent string) bool {
	switch strings.ToLower(parent) {
	case "", "cmd.exe", "explorer.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe":
		return true
	}
	return false
}

// toolNotes adds per-tool facts (E02, E10, E11, E12, E16).
func (s *envScan) toolNotes(t *toolInv, d toolDetails, data map[string]string) []string {
	var notes []string
	for _, p := range t.procs {
		if name := foreignManagers[strings.ToLower(p.Name)]; name != "" {
			data["manager"] = name
			notes = append(notes, "Им управляет программа "+name+": она снова запустит его, если её не закрыть. При замене EzPzDPI закроет её первой.")
			break
		}
	}
	if d.gameFilter {
		notes = append(notes, "Включён игровой фильтр: автор zapret предупреждает, что он может мешать работе сайтов, игр и голоса.")
	}
	if d.ipset == "any" {
		notes = append(notes, "Списки IP в режиме «any»: автор zapret предупреждает, что этот режим может ломать сайты.")
	}
	switch t.key {
	case toolGoodbyeDPI:
		notes = append(notes, "GoodbyeDPI работает только с сайтами (TCP) и не умеет чинить голос Discord — поэтому звонки могут не работать.")
		if s.gdpiRedirectsDNS(t) {
			data["dns_redirect"] = "1"
			notes = append(notes, "Он также перенаправляет DNS-запросы, поэтому проверка DNS на этом компьютере может быть неточной.")
		}
	case toolByeDPI:
		notes = append(notes, "ByeDPI — это локальный прокси: через него идут только сайты, а голос Discord идёт мимо него.")
		for _, p := range t.procs {
			if strings.EqualFold(p.Name, "proxifyre.exe") {
				notes = append(notes, "ProxiFyre направляет выбранные программы, обычно Discord, в этот прокси.")
				break
			}
		}
	}
	low := strings.ToLower(d.root)
	switch {
	case strings.Contains(low, "onedrive"):
		data["onedrive"] = "1"
		notes = append(notes, "Его папка лежит в OneDrive: Windows иногда выгружает такие файлы в облако, и обход не запускается. Если оставляете его, перенесите папку, например, в C:\\zapret.")
	case t.key == toolZapret && strings.Contains(low, "!"):
		notes = append(notes, "В пути к папке есть символ «!»: из-за него zapret не находит свой драйвер. Если оставляете его, перенесите папку, например, в C:\\zapret.")
	}
	return notes
}

func (s *envScan) gdpiRedirectsDNS(t *toolInv) bool {
	for _, sv := range t.services {
		if strings.Contains(strings.ToLower(sv.ImagePath), "--dns-addr") {
			return true
		}
	}
	for _, p := range t.procs {
		if strings.Contains(strings.ToLower(procCommandLine(p.PID)), "--dns-addr") {
			return true
		}
	}
	return false
}

// crashNote explains SCM crash and start-failure events of the tool's
// services in the last week (E07): the classic "works, then disappears
// until reboot" when the service has no recovery actions.
func (s *envScan) crashNote(t *toolInv, data map[string]string) string {
	now := time.Now()
	for _, sv := range t.services {
		crashes, failed := 0, 0
		var last time.Time
		for _, ev := range s.events {
			if !ev.matches(sv.Name, sv.Display) {
				continue
			}
			if ev.ID == 7031 || ev.ID == 7034 {
				crashes++
			} else {
				failed++
			}
			if ev.Time.After(last) {
				last = ev.Time
			}
		}
		switch {
		case crashes > 0:
			data["crashes"] = fmt.Sprint(crashes)
			data["crash_last"] = last.Format(time.RFC3339)
			msg := "Служба «" + sv.Name + "» падала " + timesRu(crashes) + " за неделю (последний раз — " + whenRu(last, now) + ")"
			if !hasRecoveryActions(sv.Name) {
				msg += " и сама не перезапускается"
			}
			return msg + ". Поэтому обход то работает, то пропадает до перезагрузки."
		case failed > 0:
			data["crash_last"] = last.Format(time.RFC3339)
			return "Служба «" + sv.Name + "» не смогла запуститься (последний раз — " + whenRu(last, now) + ")."
		}
	}
	return ""
}

// hasRecoveryActions reports whether SCM restarts the service after a
// crash. Unknown counts as yes, so the text never overclaims.
func hasRecoveryActions(name string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return true
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return true
	}
	defer s.Close()
	acts, err := s.RecoveryActions()
	if err != nil {
		return true
	}
	for _, a := range acts {
		if a.Type != mgr.NoAction {
			return true
		}
	}
	return false
}

// procCommandLine reads another process's command line (Windows 8.1+).
func procCommandLine(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 32<<10)
	var n uint32
	if windows.NtQueryInformationProcess(h, int32(windows.ProcessCommandLineInformation),
		unsafe.Pointer(&buf[0]), uint32(len(buf)), &n) != nil {
		return ""
	}
	return (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
}

// ---------------------------------------------------------------------------
// Engines, leftovers, our own service
// ---------------------------------------------------------------------------

// enginesFinding: more than one WinDivert engine runs at once (E06). They
// process the same packets and break each other.
func (s *envScan) enginesFinding(a *App) (Finding, bool) {
	var labels, dirs []string
	var foreign []ProcRef
	n := 0
	for _, p := range s.procs {
		low := strings.ToLower(p.Name)
		if !packetEngines[low] {
			continue
		}
		n++
		label := "EzPzDPI"
		if !a.ownsPath(p.Path) {
			if label = toolLabels[foreignProcTools[low]]; label == "" {
				label = "zapret"
			}
			foreign = append(foreign, ProcRef{PID: p.PID, Name: p.Name, Path: p.Path, ParentName: s.byPID[p.PPID].Name})
			if p.Path != "" {
				dirs = detAppendUnique(dirs, filepath.Dir(p.Path))
			}
		}
		labels = detAppendUnique(labels, label)
	}
	if n < 2 {
		return Finding{}, false
	}
	title := "Одновременно работают две программы обхода"
	switch {
	case len(labels) == 1:
		title = fmt.Sprintf("Одновременно работают %d %s %s", n, pluralRu(n, "копия", "копии", "копий"), labels[0])
	case len(labels) > 2:
		title = "Одновременно работают несколько программ обхода"
	}
	text := "Сейчас работают: " + ruAndList(labels) + ". Они обрабатывают одни и те же пакеты и мешают друг другу — " +
		"это частая причина обрывов голоса и «то работает, то нет». Оставьте только одну программу."
	if len(dirs) > 0 {
		text += " Папки: " + strings.Join(dirs, "; ") + "."
	}
	return Finding{ID: "engines", Kind: "engines", Level: "error", Active: true, Title: title, Text: text, Procs: foreign}, true
}

func detAppendUnique(list []string, s string) []string {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return list
		}
	}
	return append(list, s)
}

// ruAndList joins "a", "a и b", "a, b и c".
func ruAndList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " и " + items[len(items)-1]
}

// winDivertDriver: WinDivert* and Monkey* (windivert-hide) driver services.
func winDivertDriver(sv scanService) bool {
	low := strings.ToLower(sv.Name)
	return sv.driver() && (strings.HasPrefix(low, "windivert") || strings.HasPrefix(low, "monkey"))
}

// leftoversFinding: services and tasks whose program is gone, and WinDivert
// drivers nobody owns (E09). A registered driver that is not running is not
// a problem by itself, and a driver of unknown software is left alone (E17).
func (s *envScan) leftoversFinding(a *App) (Finding, bool) {
	f := Finding{ID: "leftovers", Kind: "dpi", Level: "info", Data: map[string]string{}}
	var items []string
	for _, sv := range s.services {
		if s.foreignServiceTool(a, sv) != "" && sv.dead() {
			items = append(items, "служба «"+sv.Name+"» ссылается на удалённый файл "+sv.Exe)
			f.Services = append(f.Services, sv.Name)
			f.Data["svc:"+sv.Name] = "dead"
		}
	}
	for _, t := range s.tasks {
		if taskDead(t) {
			items = append(items, "задача «"+strings.TrimPrefix(t.Name, `\`)+"» запускает удалённый файл")
			f.Tasks = append(f.Tasks, t.Name)
			f.Data["task:"+t.Name] = detExpand(commandTarget(t.Action))
		}
	}
	engineAlive := false
	for _, p := range s.procs {
		engineAlive = engineAlive || packetEngines[strings.ToLower(p.Name)]
	}
	for _, sv := range s.services {
		if item := driverLeftover(a, sv, engineAlive); item != "" {
			items = append(items, item)
			f.Services = append(f.Services, sv.Name)
			f.Data["svc:"+sv.Name] = "driver"
		}
	}
	if len(items) == 0 {
		return Finding{}, false
	}
	f.Title = "Остались следы старой программы обхода"
	f.Text = "Найдено: " + strings.Join(items, "; ") + ". Сами по себе они не работают, но могут мешать новому обходу и античитам."
	f.Acts = []Action{{ID: "remove-leftovers", Label: "Убрать остатки",
		Confirm: "EzPzDPI удалит только записи этих служб и задач. Файлы и папки останутся на месте. Продолжить?"}}
	return f, true
}

func driverLeftover(a *App, sv scanService, engineAlive bool) string {
	if !winDivertDriver(sv) {
		return ""
	}
	loaded := sv.State == windows.SERVICE_RUNNING || sv.State == windows.SERVICE_STOP_PENDING
	switch {
	case filepath.IsAbs(sv.Exe) && !fileExists(sv.Exe):
		item := "драйвер «" + sv.Name + "» зарегистрирован, но его файл удалён"
		if loaded {
			item += " (он ещё загружен; Easy Anti-Cheat в таком случае пишет «is loaded but its file is missing», поможет перезагрузка)"
		}
		return item
	case loaded && !engineAlive && (a.ownsPath(sv.Exe) || bypassToolOf(sv.Exe) != ""):
		return "драйвер «" + sv.Name + "» работает, хотя ни одна программа обхода не запущена"
	}
	return ""
}

func (s *envScan) ownFinding() (Finding, bool) {
	sv, ok := s.service(serviceName)
	if !ok || sv.driver() || sv.running() {
		return Finding{}, false
	}
	text := "Обход установлен, но сейчас не работает. Возможно, его остановил антивирус или служба упала."
	var last time.Time
	for _, ev := range s.events {
		if ev.matches(sv.Name, sv.Display) && ev.Time.After(last) {
			last = ev.Time
		}
	}
	if !last.IsZero() {
		text += " Последний сбой — " + whenRu(last, time.Now()) + "."
	}
	return Finding{ID: "own:stopped", Kind: "own", Level: "warn", Title: "Служба EzPzDPI остановлена", Text: text,
		Acts: []Action{{ID: "restart-own", Label: "Запустить снова"}}}, true
}

// ---------------------------------------------------------------------------
// Network: VPN, proxy, hosts (N02, N03, N06)
// ---------------------------------------------------------------------------

var (
	reTunnelDesc    = regexp.MustCompile(`(?i)wintun|wireguard|tap-windows|tap-.*adapter|openvpn|ovpn-dco|amnezia|nordlynx|warp|\bvpn\b|tunnel|l2tp|pptp|sstp|ikev2`)
	reVPNClientProc = regexp.MustCompile(`(?i)^(v2rayn|xray|sing-box|mihomo|clash-verge|verge-mihomo|hiddify|throne|nekoray|amneziavpn|amneziawg|wireguard|openvpn|openvpn-gui|tor|psiphon3|lantern|windscribe|protonvpn|proxifier|warp-taskbar)\.exe$`)
)

// tunnel: the default route goes through a tunnel or virtual adapter, a
// known VPN driver, or split /1 routes. PPP alone is not enough: home PPPoE
// connections are PPP too, so L2TP/PPTP/SSTP/IKEv2 are matched by name.
func (r scanRoute) tunnel() bool {
	if !r.OK {
		return false
	}
	const ifTypePropVirtual = 53 // Wintun and WireGuardNT adapters
	switch r.IfType {
	case windows.IF_TYPE_TUNNEL, ifTypePropVirtual:
		return true
	}
	return r.Split || reTunnelDesc.MatchString(r.Desc+" "+r.Name)
}

func (s *envScan) warpRunning() bool {
	if sv, ok := s.service("CloudflareWARP"); ok && sv.running() {
		return true
	}
	return s.hasProc("warp-svc.exe")
}

// vpnClient names the VPN program for the text, or "".
func (s *envScan) vpnClient() string {
	for _, p := range s.procs {
		if reVPNClientProc.MatchString(p.Name) {
			return strings.TrimSuffix(p.Name, filepath.Ext(p.Name))
		}
	}
	return ""
}

func (s *envScan) vpnFinding() (Finding, bool) {
	warp := s.warpRunning()
	if !s.route.tunnel() {
		if !warp {
			return Finding{}, false
		}
		return Finding{ID: "vpn", Kind: "vpn", Level: "info", Title: "Установлен Cloudflare WARP",
			Text: "Сейчас интернет идёт не через него. Если включить WARP, проверка покажет его работу, а не вашего провайдера."}, true
	}
	name := s.vpnClient()
	if name == "" && (warp || strings.Contains(strings.ToLower(s.route.Desc), "warp")) {
		name = "Cloudflare WARP"
	}
	if name == "" {
		name = s.route.Name
	}
	text := "Сейчас интернет идёт через VPN (" + name + "). Проверка покажет работу VPN, а не вашего провайдера. " +
		"Выключите VPN и нажмите «Проверить снова»."
	if name == "Cloudflare WARP" {
		text = "Сейчас интернет идёт через Cloudflare WARP. Проверка покажет его работу, а не вашего провайдера. " +
			"Отключите WARP в его значке рядом с часами и нажмите «Проверить снова»."
	}
	return Finding{ID: "vpn", Kind: "vpn", Level: "warn", Active: true, Title: "Включён VPN", Text: text,
		Data: map[string]string{"client": name, "adapter": s.route.Name},
		Acts: []Action{{ID: "recheck", Label: "Проверить снова"}}}, true
}

func (p scanProxy) describe() string {
	var parts []string
	if p.Enable != 0 && p.Server != "" {
		parts = append(parts, p.Server)
	}
	if p.PAC != "" {
		parts = append(parts, "автонастройку "+p.PAC)
	}
	return strings.Join(parts, " и ")
}

func (s *envScan) proxyFinding() (Finding, bool) {
	p := s.proxy
	what := p.describe()
	if what == "" {
		if p.WinHTTP == "" {
			return Finding{}, false
		}
		return Finding{ID: "proxy", Kind: "proxy", Level: "info", Title: "Для служб Windows задан прокси",
			Text: "Системные службы Windows ходят через " + p.WinHTTP + " (WinHTTP). На браузер это не влияет, а проверка EzPzDPI идёт напрямую."}, true
	}
	f := Finding{ID: "proxy", Kind: "proxy", Level: "info", Active: true, Title: "В Windows включён прокси",
		Text: "Браузер ходит через " + what + ". Так работают ByeDPI, v2rayN и похожие программы. " +
			"Проверка EzPzDPI идёт напрямую, мимо прокси, поэтому в браузере результат может отличаться.",
		Data: map[string]string{"server": p.Server, "pac": p.PAC}}
	if p.Dead {
		f.Level = "warn"
		f.Title = "Прокси Windows указывает в пустоту"
		f.Text = "В Windows включён прокси " + what + ", но по этому адресу никто не отвечает — вероятно, он остался от удалённой программы. " +
			"Из-за этого браузер не открывает сайты. Проверка EzPzDPI идёт напрямую, мимо прокси."
		f.Acts = []Action{{ID: "proxy-off", Label: "Выключить прокси",
			Confirm: "Будет выключен прокси " + what + ". Прежние настройки сохранятся, их можно вернуть."}}
	}
	if p.WinHTTP != "" {
		f.Text += " Для служб Windows также задан прокси " + p.WinHTTP + "."
	}
	return f, true
}

func (s *envScan) hostsFinding() (Finding, bool) {
	if len(s.hosts) == 0 {
		return Finding{}, false
	}
	kinds := map[string]int{}
	for _, l := range s.hosts {
		kinds[hostsLineKind(l)]++
	}
	n := len(s.hosts)
	f := Finding{ID: "hosts", Kind: "hosts", Level: "info", Active: true, Hosts: s.hosts,
		Title: "В файле hosts есть записи от старых инструкций"}
	text := []string{fmt.Sprintf("В файле hosts %d %s для Discord, YouTube и других сервисов: они жёстко привязывают сайты к заранее записанным адресам.",
		n, pluralRu(n, "строка", "строки", "строк"))}
	if k := kinds["obsolete"]; k > 0 {
		f.Level = "warn"
		text = append(text, fmt.Sprintf("%d из них ведут на устаревшие адреса голосовых серверов Discord — из-за этого голос может не подключаться.", k))
	}
	if kinds["other"] > 0 {
		f.Level = "warn"
		text = append(text, "Когда адреса сервисов меняются, такие записи мешают сайтам открываться.")
	}
	if kinds["flowseal"] > 0 {
		text = append(text, "Часть строк добавлена из набора zapret (Flowseal).")
	}
	text = append(text, "EzPzDPI может отключить эти строки, сохранив копию файла.")
	f.Text = strings.Join(text, " ")
	shown := s.hosts
	if len(shown) > 8 {
		shown = shown[:8]
	}
	confirm := "В файле hosts будут закомментированы строки:\n" + strings.Join(shown, "\n")
	if len(s.hosts) > len(shown) {
		confirm += fmt.Sprintf("\n…и ещё %d", len(s.hosts)-len(shown))
	}
	f.Acts = []Action{{ID: "clean-hosts", Label: "Отключить эти строки", Confirm: confirm + "\nКопия файла сохранится в папке EzPzDPI."}}
	return f, true
}

// ---------------------------------------------------------------------------
// Security and conflicting software (E18, X02, P12, E13, F01, X03)
// ---------------------------------------------------------------------------

var avProcNames = map[string]string{
	"avp.exe": "Kaspersky", "ekrn.exe": "ESET", "dwservice.exe": "Dr.Web", "avastsvc.exe": "Avast",
	"avgsvc.exe": "AVG", "bdservicehost.exe": "Bitdefender",
}

var reConflictService = regexp.MustCompile(`(?i)killer|smartbyte|intel.*connectivity.*network`)

func (s *envScan) thirdPartyAV() []string {
	var names []string
	for _, p := range s.procs {
		if n, ok := avProcNames[strings.ToLower(p.Name)]; ok {
			names = detAppendUnique(names, n)
		}
	}
	return names
}

// conflictServices: Check Point and NIC suites that clash with WinDivert.
func (s *envScan) conflictServices() []string {
	var names []string
	for _, sv := range s.services {
		if sv.driver() || !sv.running() {
			continue
		}
		low := strings.ToLower(sv.Name)
		if low == "tracsrvwrapper" || low == "epwd" {
			names = detAppendUnique(names, "Check Point")
		} else if reConflictService.MatchString(sv.Display) {
			names = detAppendUnique(names, sv.Display)
		}
	}
	return names
}

func (s *envScan) avFinding(a *App) (Finding, bool) {
	f := Finding{ID: "av", Kind: "av", Level: "info", Data: map[string]string{}}
	var who, text []string
	if s.hasProc("adguardsvc.exe") {
		who = append(who, "AdGuard")
		f.Data["adguard"] = "1"
		text = append(text, "AdGuard фильтрует трафик Discord и может ломать голос — исключите Discord в AdGuard "+
			"(Настройки → Сеть → Фильтруемые приложения) или отключите фильтрацию на время звонков. Пока AdGuard работает, оценка голоса неточная.")
	}
	av := s.thirdPartyAV()
	if len(av) > 0 {
		who = append(who, av...)
		text = append(text, "Антивирус ("+strings.Join(av, ", ")+") может удалить файлы обхода или мешать его драйверу. "+
			"Если обход не включится или пропадёт, добавьте папку "+a.dataDir+" в исключения антивируса.")
		if detContainsFold(av, "Kaspersky") {
			text = append(text, "Вероятно, Kaspersky будет блокировать драйвер даже с исключениями — так пишут на его форуме.")
		}
	}
	if cs := s.conflictServices(); len(cs) > 0 {
		who = append(who, cs...)
		text = append(text, "Эта программа может конфликтовать с драйвером обхода: "+strings.Join(cs, ", ")+".")
	}
	if !fileExists(a.engineExe(EngineZapret)) {
		f.Level = "warn"
		text = append(text, s.missingEngineNote(a, &f, av))
	}
	if len(text) == 0 {
		return Finding{}, false
	}
	f.Title = "Может мешать обходу: " + strings.Join(who, ", ")
	if len(who) == 0 {
		f.Title = "Пропал файл обхода"
	}
	f.Text = strings.Join(text, " ")
	return f, true
}

// missingEngineNote explains an engine file that disappeared (X02) and
// offers the Defender exclusion when Defender is the active antivirus.
func (s *envScan) missingEngineNote(a *App, f *Finding, av []string) string {
	sv, ok := s.service("WinDefend")
	defender := ok && sv.running() && len(av) == 0
	if !defender {
		return "Файл обхода пропал из папки EzPzDPI — вероятно, его удалил антивирус. Добавьте папку " + a.dataDir +
			" в исключения антивируса и откройте EzPzDPI снова."
	}
	if !a.cfg.DefenderExcluded {
		f.Acts = []Action{{ID: "defender-exclude", Label: "Добавить в исключения Защитника",
			Confirm: "Папка " + a.dataDir + " будет добавлена в исключения Защитника Windows. Убрать её оттуда можно в настройках."}}
	}
	return "Файл обхода пропал из папки EzPzDPI — скорее всего, его удалил Защитник Windows. " +
		"Это частая ложная тревога: драйвер меняет сетевые пакеты, поэтому антивирусы его не любят."
}

var reAnticheat = regexp.MustCompile(`(?i)^(vgk|vgc|faceit|faceitservice|easyanticheat.*|beservice)$`)

func anticheatLabel(name string) string {
	low := strings.ToLower(name)
	switch {
	case low == "vgk" || low == "vgc":
		return "Riot Vanguard"
	case strings.HasPrefix(low, "faceit"):
		return "FACEIT"
	case strings.HasPrefix(low, "easyanticheat"):
		return "Easy Anti-Cheat"
	}
	return "BattlEye"
}

func (s *envScan) anticheatFinding() (Finding, bool) {
	var names []string
	for _, sv := range s.services {
		if reAnticheat.MatchString(sv.Name) {
			names = detAppendUnique(names, anticheatLabel(sv.Name))
		}
	}
	if len(names) == 0 {
		return Finding{}, false
	}
	return Finding{ID: "anticheat", Kind: "game", Level: "info", Title: "Установлен античит: " + strings.Join(names, ", "),
		Text: "Некоторые античиты не любят сетевые драйверы. Если игра начнёт ругаться, выключите обход на время игры."}, true
}

func (s *envScan) droverFinding() (Finding, bool) {
	if len(s.drover) == 0 {
		return Finding{}, false
	}
	return Finding{ID: "discord-proxy", Kind: "discord", Level: "warn", Active: true,
		Title: "Discord подключается через прокси (Drover)",
		Text: "Через прокси идёт только текст — голос идёт мимо и поэтому, вероятно, обрывается или не подключается. " +
			"Файлы Drover: " + strings.Join(s.drover, "; ") + ".",
		Data: map[string]string{"dirs": strings.Join(s.drover, "|")}}, true
}

func (s *envScan) bfeFinding() (Finding, bool) {
	sv, ok := s.service("BFE")
	if !ok || sv.running() {
		return Finding{}, false
	}
	return Finding{ID: "bfe", Kind: "system", Level: "error", Active: true,
		Title: "Выключена служба базовой фильтрации Windows",
		Text:  "Без неё драйвер обхода не запускается (ошибка 1753). Обычно её выключают программы-«оптимизаторы». EzPzDPI может включить её обратно.",
		Acts:  []Action{{ID: "bfe-on", Label: "Включить службу"}}}, true
}

func (s *envScan) hvciFinding() (Finding, bool) {
	if !s.hvci {
		return Finding{}, false
	}
	return Finding{ID: "hvci", Kind: "system", Level: "info", Title: "Включена «Целостность памяти» Windows",
		Text: "Это защита Windows. Обычно она не мешает обходу, но если драйвер не загрузится (ошибки 577 или 1275), причина, вероятно, в ней. " +
			"Сначала установите все обновления Windows и попробуйте снова."}, true
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

// ---------------------------------------------------------------------------
// Actions: replace, pause, restore (E05, F03, U02)
// ---------------------------------------------------------------------------

func foreignBackupDir(a *App, sub ...string) string {
	return filepath.Join(append([]string{a.dataDir, "backup"}, sub...)...)
}

func svcStartName(t uint32) string {
	switch t {
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	case windows.SERVICE_AUTO_START:
		return "auto"
	case windows.SERVICE_DEMAND_START:
		return "demand"
	case windows.SERVICE_DISABLED:
		return "disabled"
	}
	return fmt.Sprint(t)
}

// disableForeign replaces another tool (E05): managers first, then
// services are stopped and set to disabled (never deleted), tasks
// disabled, autostart entries moved to the backup folder, engine processes
// stopped by PID after checking their path. Everything is recorded in
// a.cfg so restoreForeign can undo it, and journaled.
func disableForeign(a *App, f Finding) error {
	var errs []string
	fail := func(what string, err error) {
		if err != nil {
			a.logf("disable foreign %s: %s: %v", f.ID, what, err)
			errs = append(errs, what+": "+err.Error())
		}
	}
	writeForeignSnapshot(a, f)
	for _, p := range f.Procs {
		if p.Manager {
			_, err := killVerified(a, p)
			fail(p.Name, err)
		}
	}
	for _, name := range f.Services {
		fail("служба «"+name+"»", disableForeignService(a, name))
	}
	for _, t := range f.Tasks {
		fail("задача «"+strings.TrimPrefix(t, `\`)+"»", disableForeignTask(a, t))
	}
	for _, ref := range f.Shortcuts {
		fail("автозапуск", moveAutostart(a, ref))
	}
	for _, p := range f.Procs {
		if !p.Manager {
			_, err := killVerified(a, p)
			fail(p.Name, err)
		}
	}
	if f.ID == "dpi:"+toolByeDPI || f.ID == "dpi:"+toolSpoofDPI {
		// A proxy tool leaves the system proxy pointing at its closed port,
		// which would cut the browser off. proxyOff saves it for undo.
		if readProxy().Dead {
			fail("прокси Windows", proxyOff(a))
		}
	}
	stopIdleWinDivert(a)
	a.saveConfig()
	if len(errs) > 0 {
		return fmt.Errorf("не всё удалось отключить: %s", strings.Join(errs, "; "))
	}
	return nil
}

func disableForeignService(a *App, name string) error {
	si := queryService(name)
	if !si.Exists {
		return nil
	}
	if a.cfg.ForeignDisabled == nil {
		a.cfg.ForeignDisabled = map[string]uint32{}
	}
	if _, seen := a.cfg.ForeignDisabled[name]; !seen {
		a.cfg.ForeignDisabled[name] = si.StartType
		a.saveConfig() // recorded before the change, so a crash cannot lose it
	}
	before := "start=" + svcStartName(si.StartType) + ", остановлена"
	if si.Running {
		before = "start=" + svcStartName(si.StartType) + ", работает"
	}
	err := errors.Join(stopService(name), setServiceStart(name, windows.SERVICE_DISABLED, false))
	a.journal("служба "+name, before, "остановлена, start=disabled")
	return err
}

func disableForeignTask(a *App, name string) error {
	if err := runHidden(detSys32("schtasks.exe"), "/Change", "/TN", name, "/DISABLE"); err != nil {
		return err
	}
	if !detContainsFold(a.cfg.ForeignTasks, name) {
		a.cfg.ForeignTasks = append(a.cfg.ForeignTasks, name)
	}
	a.journal("задача "+name, "включена", "отключена")
	return nil
}

func detContainsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// runValueBackup is the backup file of a Run/RunOnce value.
type runValueBackup struct {
	Key, Value, Data string
	Type             uint32
}

// moveAutostart moves a Startup file into backup\autostart, or saves and
// deletes a Run value, and records it in a.cfg.ForeignShortcuts.
func moveAutostart(a *App, ref string) error {
	dir := foreignBackupDir(a, "autostart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	if a.cfg.ForeignShortcuts == nil {
		a.cfg.ForeignShortcuts = map[string]string{}
	}
	if keyPath, value, ok := parseRunEntryRef(ref); ok {
		return moveRunValue(a, keyPath, value, detUniquePath(filepath.Join(dir, ts+"-run-"+detSafeName(value)+".json")))
	}
	if !fileExists(ref) {
		return nil
	}
	dst := detUniquePath(filepath.Join(dir, ts+"-"+filepath.Base(ref)))
	if err := detMoveFile(ref, dst); err != nil {
		return err
	}
	a.cfg.ForeignShortcuts[dst] = ref
	a.journal("автозагрузка "+ref, "на месте", "перенесён в "+dst)
	return nil
}

func moveRunValue(a *App, keyPath, value, dst string) error {
	root, sub, err := detRegRoot(keyPath)
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	data, typ, err := k.GetStringValue(value)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(runValueBackup{Key: keyPath, Value: value, Data: data, Type: typ})
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return err
	}
	if err := k.DeleteValue(value); err != nil {
		os.Remove(dst)
		return err
	}
	a.cfg.ForeignShortcuts[dst] = runEntryRef(keyPath, value)
	a.journal("автозапуск "+keyPath+`\`+value, data, "удалён из реестра, копия: "+dst)
	return nil
}

func detRegRoot(path string) (registry.Key, string, error) {
	for prefix, root := range map[string]registry.Key{`HKLM\`: registry.LOCAL_MACHINE, `HKU\`: registry.USERS, `HKCU\`: registry.CURRENT_USER} {
		if strings.HasPrefix(strings.ToUpper(path), prefix) {
			return root, path[len(prefix):], nil
		}
	}
	return 0, "", fmt.Errorf("неизвестный раздел реестра %s", path)
}

func detSafeName(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`\/:*?"<>|`, r) || r < 32 {
			return '_'
		}
		return r
	}, s)
}

func detUniquePath(p string) string {
	if !fileExists(p) {
		return p
	}
	ext := filepath.Ext(p)
	for i := 2; ; i++ {
		q := fmt.Sprintf("%s-%d%s", strings.TrimSuffix(p, ext), i, ext)
		if !fileExists(q) {
			return q
		}
	}
}

// detMoveFile renames, falling back to copy+delete across volumes.
func detMoveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	return os.Remove(src)
}

// killVerified stops a process only if the PID still belongs to the same
// executable, so a reused PID never kills an unrelated program.
func killVerified(a *App, p ProcRef) (killed bool, err error) {
	cur := procPath(p.PID)
	if cur == "" {
		return false, nil // already gone
	}
	if !strings.EqualFold(cur, p.Path) {
		a.logf("not killing PID %d: now %s, expected %s", p.PID, cur, p.Path)
		return false, nil
	}
	if err := killPID(p.PID); err != nil {
		return false, err
	}
	a.journal(fmt.Sprintf("процесс %s (PID %d)", p.Name, p.PID), p.Path, "завершён")
	return true, nil
}

func engineImageNames() []string {
	names := make([]string, 0, len(packetEngines))
	for n := range packetEngines {
		names = append(names, n)
	}
	return names
}

// stopIdleWinDivert unloads WinDivert drivers once no engine uses them.
// While any engine (ours included) holds the driver, a stop request would
// leave it stuck in STOP_PENDING, so nothing is done then.
func stopIdleWinDivert(a *App) {
	if len(listProcs(engineImageNames()...)) > 0 {
		return
	}
	for _, sv := range enumWinDivertDrivers() {
		if serviceState(sv) != svcRunning {
			continue
		}
		err := stopService(sv)
		a.journal("драйвер "+sv, "загружен", fmt.Sprintf("остановлен (%v)", errWord(err)))
	}
}

func errWord(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func enumWinDivertDrivers() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, strings.TrimSuffix(servicesKey, `\`), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		low := strings.ToLower(n)
		if strings.HasPrefix(low, "windivert") || strings.HasPrefix(low, "monkey") {
			out = append(out, n)
		}
	}
	return out
}

// foreignSnapshot is written to backup\foreign-<time>.json before a
// replacement, as a human-readable record of what was there (E05).
type foreignSnapshot struct {
	At        time.Time         `json:"at"`
	Finding   string            `json:"finding"`
	Services  []snapshotService `json:"services,omitempty"`
	Tasks     []string          `json:"tasks,omitempty"`
	Autostart []string          `json:"autostart,omitempty"`
	Procs     []ProcRef         `json:"procs,omitempty"`
}

type snapshotService struct {
	Name      string `json:"name"`
	ImagePath string `json:"image_path"`
	Start     string `json:"start"`
	Running   bool   `json:"running"`
}

func writeForeignSnapshot(a *App, f Finding) {
	dir := foreignBackupDir(a)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	ts := time.Now().Format("20060102-150405")
	snap := foreignSnapshot{At: time.Now(), Finding: f.ID, Tasks: f.Tasks, Autostart: f.Shortcuts, Procs: f.Procs}
	for _, name := range f.Services {
		si := queryService(name)
		snap.Services = append(snap.Services, snapshotService{Name: name, ImagePath: si.BinPath,
			Start: svcStartName(si.StartType), Running: si.Running})
		reg := filepath.Join(dir, "service-"+detSafeName(name)+"-"+ts+".reg")
		if err := runHidden(detSys32("reg.exe"), "export", `HKLM\`+servicesKey+name, reg, "/y"); err != nil {
			a.logf("reg export %s: %v", name, err)
		}
	}
	b, _ := json.MarshalIndent(snap, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "foreign-"+ts+".json"), b, 0o644)
}

// PausedForeign records what pauseForeignState stopped, so it can be
// started again later, even by the next run after a crash: it is plain
// JSON for the fix marker.
type PausedForeign struct {
	Services []string     `json:"services"`
	Procs    []PausedProc `json:"procs"`
}

// PausedProc is a process that nothing else would restart (started by
// hand from a .bat or a shortcut): its verified exe, original command line
// and working folder.
type PausedProc struct {
	Exe     string `json:"exe"`
	CmdLine string `json:"cmdline"`
	Dir     string `json:"dir"`
}

// pauseForeign stops other tools for a comparison (F03) without disabling
// anything, and returns a function that starts them again.
func pauseForeign(a *App, fs []Finding) (resume func()) {
	p := pauseForeignState(a, fs)
	return func() {
		if err := resumeForeignState(a, p); err != nil {
			a.logf("resume foreign: %v", err)
		}
	}
}

// pauseForeignState stops other tools without disabling anything: managers
// first (or they restart the engine), then running services, then engine
// processes. It records the services it stopped and the processes no
// service or manager would restart, for resumeForeignState.
func pauseForeignState(a *App, fs []Finding) PausedForeign {
	var p PausedForeign
	for _, f := range fs {
		p.Procs = append(p.Procs, pauseProcs(a, f.Procs, true)...)
		for _, name := range f.Services {
			if queryService(name).Running && stopService(name) == nil {
				p.Services = append(p.Services, name)
				a.journal("служба "+name, "работает", "остановлена на время проверки")
			}
		}
		p.Procs = append(p.Procs, pauseProcs(a, f.Procs, false)...)
	}
	return p
}

func pauseProcs(a *App, list []ProcRef, managers bool) []PausedProc {
	var out []PausedProc
	for _, p := range list {
		if p.Manager != managers {
			continue
		}
		// Read before the process is gone.
		cmd, dir := procCommandLine(p.PID), procCurrentDir(p.PID)
		killed, err := killVerified(a, p)
		if err != nil {
			a.logf("pause %s: %v", p.Name, err)
		}
		_, byManager := foreignManagers[strings.ToLower(p.ParentName)]
		restartedByOthers := strings.EqualFold(p.ParentName, "services.exe") || byManager
		if killed && cmd != "" && !restartedByOthers {
			out = append(out, PausedProc{Exe: p.Path, CmdLine: cmd, Dir: dir})
		}
	}
	return out
}

// resumeForeignState starts the paused services again and relaunches the
// paused processes with their own command line in a minimized console,
// like the .bat did. A process is relaunched only if its exe is a known
// bypass tool that still exists and is not already running (a service or
// manager may have started it). The error lists what could not come back.
func resumeForeignState(a *App, p PausedForeign) error {
	var problems []string
	for _, name := range p.Services {
		err := startForeignService(name)
		a.journal("служба "+name, "остановлена на время проверки", "запущена снова ("+errWord(err)+")")
		if err != nil {
			problems = append(problems, "служба «"+name+"»: "+err.Error())
		}
	}
	if len(p.Services) > 0 && len(p.Procs) > 0 {
		time.Sleep(1500 * time.Millisecond) // let services and managers respawn their engines first
	}
	for _, pr := range p.Procs {
		name := filepath.Base(pr.Exe)
		switch {
		case !relaunchAllowed(pr.Exe):
			a.logf("resume foreign: refusing to start %q", pr.Exe)
			problems = append(problems, name+": неизвестная программа, не запущена")
			continue
		case !fileExists(pr.Exe):
			problems = append(problems, name+": "+errForeignGone.Error())
			continue
		case processRunning(pr.Exe):
			continue
		}
		err := relaunchProcess(pr.Exe, pr.CmdLine, pr.Dir)
		a.journal("процесс "+name, "остановлен на время проверки", "запущен снова ("+errWord(err)+")")
		if err != nil {
			problems = append(problems, name+": "+err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New("не всё удалось запустить снова: " + strings.Join(problems, "; "))
	}
	return nil
}

func processRunning(exe string) bool {
	for _, p := range listProcs(filepath.Base(exe)) {
		if strings.EqualFold(p.Path, exe) {
			return true
		}
	}
	return false
}

// relaunchProcess starts a program with its original command line in a new
// minimized console, the way a .bat started it, so the user can still
// close it as before. The verified exe path is passed separately so the
// command line cannot redirect it. dir is the original working folder;
// the exe's folder is used when it is empty or gone.
func relaunchProcess(exe, cmdline, dir string) error {
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	cl, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return err
	}
	if st, err := os.Stat(dir); dir == "" || err != nil || !st.IsDir() {
		dir = filepath.Dir(exe)
	}
	wd, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_SHOWMINNOACTIVE}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, cl, nil, nil, false, windows.CREATE_NEW_CONSOLE, nil, wd, &si, &pi); err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

// procCurrentDir reads another process's working folder from its process
// parameters. "" when it cannot be read; the caller then uses the exe's
// folder. A 32-bit process still has the 64-bit parameter block, filled in
// at start, which is the folder the .bat started it from.
func procCurrentDir(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var pbi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil) != nil || pbi.PebBaseAddress == nil {
		return ""
	}
	var peb windows.PEB
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(pbi.PebBaseAddress)), (*byte)(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb), nil) != nil || peb.ProcessParameters == nil {
		return ""
	}
	var params windows.RTL_USER_PROCESS_PARAMETERS
	// Only the head up to the current folder is read; the block's full
	// size differs between Windows versions.
	head := unsafe.Offsetof(params.DllPath)
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(peb.ProcessParameters)), (*byte)(unsafe.Pointer(&params)),
		head, nil) != nil {
		return ""
	}
	dos := params.CurrentDirectory.DosPath
	if dos.Length == 0 || dos.Length%2 != 0 || dos.Buffer == nil {
		return ""
	}
	buf := make([]uint16, dos.Length/2)
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(dos.Buffer)), (*byte)(unsafe.Pointer(&buf[0])),
		uintptr(dos.Length), nil) != nil {
		return ""
	}
	return filepath.Clean(string(utf16.Decode(buf)))
}

func startForeignService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

// restoreForeign undoes every disableForeign: start types, tasks and
// autostart entries come back, and auto-start services are started. A tool
// whose program was deleted is not brought back as a broken service.
// The caller stops EzPzDPI first, so two engines never run together.
func restoreForeign(a *App) error {
	var problems []string
	for name, start := range a.cfg.ForeignDisabled {
		err := restoreForeignService(a, name, start)
		switch {
		case errors.Is(err, errForeignGone):
			problems = append(problems, "служба «"+name+"»: папка программы удалена — вернуть нечего")
		case err != nil:
			problems = append(problems, "служба «"+name+"»: "+err.Error())
			continue
		}
		delete(a.cfg.ForeignDisabled, name)
	}
	var keep []string
	for _, t := range a.cfg.ForeignTasks {
		if err := restoreForeignTask(a, t); err != nil && !errors.Is(err, errForeignGone) {
			keep = append(keep, t)
			problems = append(problems, "задача «"+strings.TrimPrefix(t, `\`)+"»: "+err.Error())
		}
	}
	a.cfg.ForeignTasks = keep
	for dst, orig := range a.cfg.ForeignShortcuts {
		if err := restoreAutostart(a, dst, orig); err != nil && !errors.Is(err, errForeignGone) {
			problems = append(problems, "автозапуск "+orig+": "+err.Error())
			continue
		}
		delete(a.cfg.ForeignShortcuts, dst)
	}
	if len(a.cfg.ForeignDisabled) == 0 {
		a.cfg.ForeignDisabled = nil
	}
	if len(a.cfg.ForeignShortcuts) == 0 {
		a.cfg.ForeignShortcuts = nil
	}
	a.saveConfig()
	if len(problems) > 0 {
		return errors.New("не всё удалось вернуть: " + strings.Join(problems, "; "))
	}
	return nil
}

// foreignShortcutNames lists readable names of the autostart entries
// disableForeign moved away (a.cfg.ForeignShortcuts): the Startup file
// name or the Run value name, sorted and without repeats.
func foreignShortcutNames(a *App) []string {
	var out []string
	for _, orig := range a.cfg.ForeignShortcuts {
		if n := autostartDisplayName(orig); n != "" && !detContainsFold(out, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func restoreForeignService(a *App, name string, start uint32) error {
	si := queryService(name)
	if !si.Exists {
		return errForeignGone
	}
	if exe := imageExePath(detExpand(si.BinPath), detSystemRoot()); filepath.IsAbs(exe) && !fileExists(exe) {
		return errForeignGone
	}
	if err := setServiceStart(name, start, false); err != nil {
		return err
	}
	a.journal("служба "+name, "start=disabled", "start="+svcStartName(start))
	if start != windows.SERVICE_AUTO_START {
		return nil
	}
	if err := startForeignService(name); err != nil {
		return fmt.Errorf("тип запуска восстановлен, но служба не запустилась: %w", err)
	}
	return nil
}

func restoreForeignTask(a *App, name string) error {
	if !taskExists(name) {
		return errForeignGone
	}
	if err := runHidden(detSys32("schtasks.exe"), "/Change", "/TN", name, "/ENABLE"); err != nil {
		return err
	}
	a.journal("задача "+name, "отключена", "включена")
	return nil
}

func restoreAutostart(a *App, dst, orig string) error {
	if !fileExists(dst) {
		return errForeignGone
	}
	if keyPath, value, ok := parseRunEntryRef(orig); ok {
		return restoreRunValue(a, dst, keyPath, value)
	}
	if fileExists(orig) {
		return nil // the user put it back already; keep our copy untouched
	}
	if err := os.MkdirAll(filepath.Dir(orig), 0o755); err != nil {
		return err
	}
	if err := detMoveFile(dst, orig); err != nil {
		return err
	}
	a.journal("автозагрузка "+orig, "в копии "+dst, "возвращён")
	return nil
}

func restoreRunValue(a *App, dst, keyPath, value string) error {
	var b runValueBackup
	raw, err := os.ReadFile(dst)
	if err != nil || json.Unmarshal(raw, &b) != nil {
		return errForeignGone
	}
	root, sub, err := detRegRoot(keyPath)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(root, sub, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if b.Type == registry.EXPAND_SZ {
		err = k.SetExpandStringValue(value, b.Data)
	} else {
		err = k.SetStringValue(value, b.Data)
	}
	if err != nil {
		return err
	}
	os.Remove(dst)
	a.journal("автозапуск "+keyPath+`\`+value, "удалён", b.Data)
	return nil
}

// removeLeftovers deletes registrations of dead services, dead tasks and
// orphaned WinDivert drivers (E09/U04), re-checking each one first. Files
// and folders are never deleted.
func removeLeftovers(a *App, f Finding) error {
	var problems, pending []string
	for _, name := range f.Services {
		si := queryService(name)
		if !si.Exists || !leftoverStillDead(f.Data["svc:"+name], si) {
			continue
		}
		a.journal("служба "+name, "ImagePath="+si.BinPath+", start="+svcStartName(si.StartType), "удалена (остаток)")
		err := stopAndDeleteService(name)
		if queryService(name).Exists {
			pending = append(pending, name) // marked for delete: goes away after a reboot
		} else if err != nil {
			problems = append(problems, "служба «"+name+"»: "+err.Error())
		}
	}
	for _, name := range f.Tasks {
		target := f.Data["task:"+name]
		if target == "" || fileExists(target) || !taskExists(name) {
			continue
		}
		a.journal("задача "+name, "запускает "+target+" (файла нет)", "удалена (остаток)")
		if err := runHidden(detSys32("schtasks.exe"), "/Delete", "/F", "/TN", name); err != nil {
			problems = append(problems, "задача «"+strings.TrimPrefix(name, `\`)+"»: "+err.Error())
		}
	}
	if len(pending) > 0 {
		problems = append(problems, "нужна перезагрузка: Windows уберёт "+ruAndList(ruQuoteAll(pending))+" после неё")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func ruQuoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "«" + n + "»"
	}
	return out
}

// leftoverStillDead re-checks a leftover right before removing it, since
// the user may have restored the folder or started a tool meanwhile.
func leftoverStillDead(kind string, si svcInfo) bool {
	exe := imageExePath(detExpand(si.BinPath), detSystemRoot())
	missing := filepath.IsAbs(exe) && !fileExists(exe)
	switch kind {
	case "dead":
		return missing
	case "driver":
		return missing || len(listProcs(engineImageNames()...)) == 0
	}
	return false
}

// ---------------------------------------------------------------------------
// Actions: hosts, proxy, BFE (N06, N03, F01)
// ---------------------------------------------------------------------------

// cleanHosts comments out override lines for watched names (N06). The file
// is backed up first (5 copies kept), its bytes and line endings are kept,
// the ReadOnly attribute is restored and the write is atomic.
func cleanHosts(a *App) (backup string, err error) {
	p := hostsFilePath()
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	stamp := hostsStampPrefix + time.Now().Format("2006-01-02") + " "
	out, changed := disableHostsLines(string(data), hostsWatchList(), stamp)
	if len(changed) == 0 {
		return "", errors.New("в файле hosts уже нет таких записей")
	}
	if backup, err = backupHosts(a, data); err != nil {
		return "", fmt.Errorf("не удалось сохранить копию hosts, файл не изменён: %w", err)
	}
	if err := replaceFileAtomic(p, []byte(out)); err != nil {
		return backup, err
	}
	a.journal("файл hosts", strings.Join(changed, "; "), "строки закомментированы, копия: "+backup)
	flushDNSCacheForHosts()
	return backup, nil
}

// restoreHosts undoes cleanHosts: it removes the "# EzPzDPI disabled
// <date> " stamp so those lines work again, and leaves every other line as
// it is. The current file is backed up first and written atomically, then
// the DNS cache is flushed. Nothing to restore is not an error.
func restoreHosts(a *App) error {
	p := hostsFilePath()
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	out, restored := restoreHostsLines(string(data))
	if len(restored) == 0 {
		return nil
	}
	backup, err := backupHosts(a, data)
	if err != nil {
		return fmt.Errorf("не удалось сохранить копию hosts, файл не изменён: %w", err)
	}
	if err := replaceFileAtomic(p, []byte(out)); err != nil {
		return err
	}
	a.journal("файл hosts", "строки закомментированы EzPzDPI, копия: "+backup, "возвращены: "+strings.Join(restored, "; "))
	flushDNSCacheForHosts()
	return nil
}

func backupHosts(a *App, data []byte) (string, error) {
	dir := foreignBackupDir(a)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := detUniquePath(filepath.Join(dir, "hosts."+time.Now().Format("20060102-150405")+".bak"))
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	old, _ := filepath.Glob(filepath.Join(dir, "hosts.*.bak"))
	sort.Strings(old) // timestamped names sort by age
	for len(old) > 5 {
		os.Remove(old[0])
		old = old[1:]
	}
	return p, nil
}

// replaceFileAtomic writes a temp file next to path and moves it over the
// original, clearing and restoring ReadOnly around the move.
func replaceFileAtomic(path string, data []byte) error {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p16)
	if err != nil {
		return err
	}
	readOnly := attrs&windows.FILE_ATTRIBUTE_READONLY != 0
	if readOnly {
		if err := windows.SetFileAttributes(p16, attrs&^windows.FILE_ATTRIBUTE_READONLY); err != nil {
			return err
		}
		defer windows.SetFileAttributes(p16, attrs)
	}
	tmp := path + ".ezpzdpi.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	t16, _ := windows.UTF16PtrFromString(tmp)
	if err := windows.MoveFileEx(t16, p16, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func flushDNSCacheForHosts() {
	if detDNSFlush.Find() == nil {
		detDNSFlush.Call()
	}
}

// proxyOff turns off a WinINET proxy that points nowhere (N03), saving the
// previous values in a.cfg.ProxyBackup for restoreProxy. It changes the
// signed-in user's settings (proxyUserKey), the same ones readProxy shows.
func proxyOff(a *App) error {
	root, path, label := proxyUserKey()
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	en, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	pac, _, _ := k.GetStringValue("AutoConfigURL")
	if a.cfg.ProxyBackup == nil {
		a.cfg.ProxyBackup = &ProxyBackup{Enable: uint32(en), Server: server, PAC: pac, At: time.Now()}
		if root == registry.USERS {
			a.cfg.ProxyBackup.UserKey = path
		}
		a.saveConfig()
	}
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}
	if pac != "" {
		if err := k.DeleteValue("AutoConfigURL"); err != nil {
			return err
		}
	}
	notifyProxyChanged()
	a.logf("proxy off in %s", label)
	a.journal("прокси Windows", fmt.Sprintf("ProxyEnable=%d ProxyServer=%s AutoConfigURL=%s", en, server, pac), "выключен")
	return nil
}

// restoreProxy puts back what proxyOff saved, into the same user's
// settings. A saved proxy that points at a local port nobody listens on
// (the ByeDPI/SpoofDPI that was replaced is gone) is not written back:
// that would cut the browser off. The backup is then dropped and the
// proxy stays off. The caller restores foreign tools first, so a tool
// that came back has a few seconds to open its port.
func restoreProxy(a *App) error {
	b := a.cfg.ProxyBackup
	if b == nil {
		return nil
	}
	saved := scanProxy{Enable: b.Enable, Server: b.Server, PAC: b.PAC}
	dead := proxyDead(saved)
	for i := 0; dead && i < 4; i++ {
		time.Sleep(750 * time.Millisecond)
		dead = proxyDead(saved)
	}
	desc := fmt.Sprintf("ProxyEnable=%d ProxyServer=%s AutoConfigURL=%s", b.Enable, b.Server, b.PAC)
	if dead {
		a.journal("прокси Windows", "выключен", "оставлен выключенным: сохранённый прокси ("+desc+") никто не слушает")
		a.cfg.ProxyBackup = nil
		a.saveConfig()
		return nil
	}
	// Restore into the hive of the user whose proxy was turned off, even if
	// someone else is signed in now.
	root, path, label := proxyUserKey()
	if b.UserKey != "" {
		root, path, label = registry.USERS, b.UserKey, "HKU (saved user)"
	}
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	errs := []error{k.SetDWordValue("ProxyEnable", b.Enable)}
	if b.Server != "" {
		errs = append(errs, k.SetStringValue("ProxyServer", b.Server))
	}
	if b.PAC != "" {
		errs = append(errs, k.SetStringValue("AutoConfigURL", b.PAC))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	notifyProxyChanged()
	a.logf("proxy restored in %s", label)
	a.journal("прокси Windows", "выключен", desc)
	a.cfg.ProxyBackup = nil
	a.saveConfig()
	return nil
}

// notifyProxyChanged tells running browsers to re-read proxy settings.
func notifyProxyChanged() {
	const settingsChanged, refresh = 39, 37
	if detInternetSetOption.Find() != nil {
		return
	}
	detInternetSetOption.Call(0, settingsChanged, 0, 0)
	detInternetSetOption.Call(0, refresh, 0, 0)
}

// startBFE turns the Base Filtering Engine back on (F01). WinDivert cannot
// open without it (error 1753).
func startBFE(a *App) error {
	si := queryService("BFE")
	if !si.Exists {
		return errors.New("службы BFE нет в системе — Windows повреждена, нужна её проверка (sfc /scannow)")
	}
	if si.Running {
		return nil
	}
	start := si.StartType
	if start == windows.SERVICE_DISABLED || start == windows.SERVICE_DEMAND_START {
		start = windows.SERVICE_AUTO_START
	}
	err := setServiceStart("BFE", start, true)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	a.journal("служба BFE", "start="+svcStartName(si.StartType)+", остановлена", "start="+svcStartName(start)+", запущена")
	for i := 0; i < 25 && serviceState("BFE") != svcRunning; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if serviceState("BFE") != svcRunning {
		return errors.New("служба базовой фильтрации не запустилась — перезагрузите компьютер и попробуйте снова")
	}
	return nil
}
