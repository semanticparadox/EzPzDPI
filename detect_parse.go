package main

// Pure parsers and classifiers for environment detection (module A). They
// have no build tag so they are unit-tested on any OS; detect_windows.go
// feeds them registry values, files and the output of schtasks/wevtutil.
// Everything here is locale independent: fixed CSV column positions, XML
// element names, file formats and executable names, never console text.

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Column positions of `schtasks /Query /FO CSV /V /NH`. The header text is
// translated on Russian Windows, but the column order is fixed.
const (
	schtColTaskName  = 1
	schtColTaskToRun = 8
)

// schedTask is one scheduled task: its full path (\winws1) and the first
// action's command line.
type schedTask struct {
	Name    string
	Action  string
	Enabled bool
}

// parseSchtasksCSV reads verbose schtasks CSV. A task with several triggers
// appears on several rows; only the first row of each task is kept. Rows
// whose name does not start with a backslash (headers, blank lines) are
// skipped, so it does not matter whether /NH was honoured.
func parseSchtasksCSV(out string) []schedTask {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	seen := map[string]bool{}
	var tasks []schedTask
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		var pe *csv.ParseError
		if err != nil && !errors.As(err, &pe) {
			break
		}
		if err != nil || len(rec) <= schtColTaskToRun {
			continue
		}
		name := strings.TrimSpace(rec[schtColTaskName])
		if !strings.HasPrefix(name, `\`) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		tasks = append(tasks, schedTask{Name: name, Action: strings.TrimSpace(rec[schtColTaskToRun]), Enabled: true})
	}
	return tasks
}

// taskXMLEnabled reads <Settings><Enabled> from `schtasks /Query /XML`.
// Triggers have their own <Enabled>, so only the Settings block counts.
// A missing element means enabled (the Task Scheduler default).
func taskXMLEnabled(doc string) bool {
	low := strings.ToLower(doc)
	start := strings.Index(low, "<settings>")
	if start < 0 {
		return true
	}
	end := strings.Index(low[start:], "</settings>")
	if end < 0 {
		end = len(low) - start
	}
	return !strings.Contains(low[start:start+end], "<enabled>false</enabled>")
}

// decodeTaskXML turns a task file from %SystemRoot%\System32\Tasks into
// text. The files are UTF-16 LE with a BOM; UTF-8 (with or without a BOM)
// is accepted too.
func decodeTaskXML(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return utf16Bytes(b[2:], false)
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return utf16Bytes(b[2:], true)
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return string(b[3:])
	case len(b) >= 2 && b[0] == '<' && b[1] == 0:
		return utf16Bytes(b, false) // UTF-16 LE without a BOM
	}
	return string(b)
}

func utf16Bytes(b []byte, bigEndian bool) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
	}
	return string(utf16.Decode(u))
}

// xmlTaskDef is the part of a task definition the scan needs.
type xmlTaskDef struct {
	Exec []struct {
		Command   string `xml:"Command"`
		Arguments string `xml:"Arguments"`
	} `xml:"Actions>Exec"`
}

// taskXMLAction returns the first Exec action of a task file as one
// command line, the way schtasks shows "Task To Run". A command with
// spaces is quoted so commandTarget can split it. ok is false for tasks
// without an Exec action (COM handlers, e-mail) or unreadable XML.
func taskXMLAction(doc string) (action string, ok bool) {
	d := xml.NewDecoder(strings.NewReader(doc))
	// The text is already decoded; the declaration still says UTF-16.
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var t xmlTaskDef
	if err := d.Decode(&t); err != nil || len(t.Exec) == 0 {
		return "", false
	}
	cmd := strings.TrimSpace(t.Exec[0].Command)
	if cmd == "" {
		return "", false
	}
	if strings.ContainsAny(cmd, " \t") && !strings.HasPrefix(cmd, `"`) {
		cmd = `"` + cmd + `"`
	}
	if args := strings.TrimSpace(t.Exec[0].Arguments); args != "" {
		cmd += " " + args
	}
	return cmd, true
}

// taskNameFromPath turns a path relative to the Tasks folder
// ("Zapret/winws1" or `Zapret\winws1`) into the scheduler name `\Zapret\winws1`.
func taskNameFromPath(rel string) string {
	return `\` + strings.TrimLeft(strings.ReplaceAll(rel, "/", `\`), `\`)
}

// scmEvent is a Service Control Manager event from the System log.
type scmEvent struct {
	ID      int
	Time    time.Time
	Params  []string // <Data> values; param1 is the service display name
	Service string   // service key name, decoded from <Binary>
}

type xmlSCMEvent struct {
	System struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data   []string `xml:"Data"`
		Binary string   `xml:"Binary"`
	} `xml:"EventData"`
}

// parseSCMEvents reads the concatenated <Event> elements that
// `wevtutil qe ... /f:xml` prints (there is no root element).
func parseSCMEvents(doc string) []scmEvent {
	dec := xml.NewDecoder(strings.NewReader(doc))
	dec.Strict = false
	var out []scmEvent
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev xmlSCMEvent
		if dec.DecodeElement(&ev, &se) != nil {
			return out
		}
		t, _ := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
		params := make([]string, len(ev.EventData.Data))
		for i, d := range ev.EventData.Data {
			params[i] = strings.TrimSpace(d)
		}
		out = append(out, scmEvent{ID: ev.System.EventID, Time: t, Params: params,
			Service: utf16HexString(ev.EventData.Binary)})
	}
}

// matches reports whether the event names the service by key name or
// display name.
func (e scmEvent) matches(name, display string) bool {
	if e.Service != "" && strings.EqualFold(e.Service, name) {
		return true
	}
	return len(e.Params) > 0 && display != "" && strings.EqualFold(e.Params[0], display)
}

// utf16HexString decodes the hex dump of a UTF-16LE string that SCM puts
// into <Binary> (the service key name), stopping at the first NUL.
func utf16HexString(h string) string {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return ""
	}
	var r []rune
	for i := 0; i+1 < len(b); i += 2 {
		c := rune(b[i]) | rune(b[i+1])<<8
		if c == 0 {
			break
		}
		r = append(r, c)
	}
	return string(r)
}

var reLocalVersion = regexp.MustCompile(`(?im)^\s*set\s+"?LOCAL_VERSION=([^"\r\n]+)"?`)

// flowsealVersion reads `set "LOCAL_VERSION=1.10.4"` from Flowseal's
// service.bat. The folder name is never trusted for the version.
func flowsealVersion(serviceBat string) string {
	m := reLocalVersion.FindStringSubmatch(serviceBat)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// flowsealIPsetNone is the placeholder Flowseal writes to ipset-all.txt
// when the IP list mode is "none".
const flowsealIPsetNone = "203.0.113.113/32"

// ipsetMode classifies Flowseal's lists\ipset-all.txt: the placeholder
// means "none", an empty file means "any" (every IP), anything else is a
// loaded list.
func ipsetMode(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == flowsealIPsetNone {
			return "none"
		}
		return "loaded"
	}
	return "any"
}

// Bypass tool keys used in finding IDs (dpi:<key>).
const (
	toolZapret     = "zapret"
	toolZapret2    = "zapret2"
	toolGoodbyeDPI = "goodbyedpi"
	toolByeDPI     = "byedpi"
	toolSpoofDPI   = "spoofdpi"
)

// toolOrder is the order findings appear in.
var toolOrder = []string{toolZapret, toolZapret2, toolGoodbyeDPI, toolByeDPI, toolSpoofDPI}

var toolLabels = map[string]string{
	toolZapret: "zapret", toolZapret2: "zapret2", toolGoodbyeDPI: "GoodbyeDPI",
	toolByeDPI: "ByeDPI", toolSpoofDPI: "SpoofDPI",
}

// toolPatterns map text (a path, command line or service name) to a tool.
// Order matters: zapret2 must win over zapret, and general*.bat is the
// Flowseal launcher even when the folder name says nothing.
var toolPatterns = []struct {
	re   *regexp.Regexp
	tool string
}{
	{regexp.MustCompile(`winws2\.exe|zapret2|zapret-2`), toolZapret2},
	{regexp.MustCompile(`goodbyedpi`), toolGoodbyeDPI},
	{regexp.MustCompile(`ciadpi|byedpi|proxifyre`), toolByeDPI},
	{regexp.MustCompile(`spoofdpi`), toolSpoofDPI},
	{regexp.MustCompile(`winws|zapret|discordfix|general[\w ().,-]*\.(bat|cmd)`), toolZapret},
}

// bypassToolOf returns the tool a path or command line belongs to, or "".
func bypassToolOf(text string) string {
	low := strings.ToLower(text)
	for _, p := range toolPatterns {
		if p.re.MatchString(low) {
			return p.tool
		}
	}
	return ""
}

// foreignProcTools maps process image names of other bypass tools to the
// tool they belong to.
var foreignProcTools = map[string]string{
	"winws.exe": toolZapret, "winws2.exe": toolZapret2, "goodbyedpi.exe": toolGoodbyeDPI,
	"ciadpi.exe": toolByeDPI, "byedpi.exe": toolByeDPI, "proxifyre.exe": toolByeDPI,
	"spoofdpi.exe": toolSpoofDPI,
	// GUIs and watchdogs that start (and restart) an engine.
	"zapretgui.service.exe": toolZapret, "zapretgui.exe": toolZapret, "zapret_gui.exe": toolZapret,
	"byedpi manager.exe": toolByeDPI,
}

// foreignManagers are GUIs/watchdogs, with the name shown to the user. They
// must be stopped before their engine, or they start it again.
var foreignManagers = map[string]string{
	"zapretgui.service.exe": "Zapret GUI", "zapretgui.exe": "Zapret GUI", "zapret_gui.exe": "Zapret GUI",
	"byedpi manager.exe": "ByeDPI Manager",
}

// packetEngines are processes that open WinDivert. Two of them at once
// process the same packets and break each other (E06). Our own engines are
// listed under their renamed and 0.1.x names.
var packetEngines = map[string]bool{
	"winws.exe": true, "winws2.exe": true, "goodbyedpi.exe": true,
	"ezpz-winws.exe": true, "ezpz-goodbyedpi.exe": true,
}

// knownBypassServices are service names other tools register.
var knownBypassServices = map[string]string{
	"zapret": toolZapret, "discordfix_zapret": toolZapret, "winws1": toolZapret, "winws2": toolZapret,
	"winws3": toolZapret, "zapret2": toolZapret2, "goodbyedpi": toolGoodbyeDPI,
}

var reScriptExt = regexp.MustCompile(`(?i)\.(exe|bat|cmd|lnk|vbs|ps1)$`)

// commandTarget picks the bypass-related file a command line runs, e.g.
// `cmd /c "C:\z\general (ALT).bat"` gives the .bat. It returns "" when no
// token both looks like a program or script and matches a bypass tool.
func commandTarget(cmd string) string {
	for _, tok := range splitCmdLine(cmd) {
		if reScriptExt.MatchString(tok) && bypassToolOf(tok) != "" {
			return tok
		}
	}
	return ""
}

// imageExePath extracts the program path from a service ImagePath (already
// environment-expanded) and resolves the kernel-style prefixes drivers use.
func imageExePath(imagePath, systemRoot string) string {
	p := strings.TrimSpace(imagePath)
	if strings.HasPrefix(p, `"`) {
		if i := strings.Index(p[1:], `"`); i >= 0 {
			p = p[1 : i+1]
		}
	} else {
		low := strings.ToLower(p)
		for _, ext := range []string{".exe", ".sys"} {
			if i := strings.Index(low, ext); i >= 0 {
				p = p[:i+len(ext)]
				break
			}
		}
	}
	p = strings.TrimPrefix(p, `\??\`)
	low := strings.ToLower(p)
	switch {
	case strings.HasPrefix(low, `\systemroot\`):
		p = systemRoot + p[len(`\systemroot`):]
	case strings.HasPrefix(low, `system32\`):
		p = systemRoot + `\` + p
	}
	return p
}

// Run-key autostart entries share the ForeignShortcuts record with moved
// files. They are stored as "reg:<key path>|<value name>".
const runRefPrefix = "reg:"

func runEntryRef(keyPath, value string) string { return runRefPrefix + keyPath + "|" + value }

func parseRunEntryRef(ref string) (keyPath, value string, ok bool) {
	if !strings.HasPrefix(ref, runRefPrefix) {
		return "", "", false
	}
	rest := ref[len(runRefPrefix):]
	// The key path is one of ours (fixed Run/RunOnce paths under a SID), so
	// the first "|" ends it; the value name may contain "|" itself.
	i := strings.Index(rest, "|")
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// --- hosts file (N06) ---

// parseHostsLine returns the IP and names of an active hosts line.
func parseHostsLine(line string) (ip net.IP, names []string, ok bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return nil, nil, false
	}
	ip = net.ParseIP(f[0])
	if ip == nil {
		return nil, nil, false
	}
	return ip, f[1:], true
}

// hostMatches reports whether host equals one of domains or is under one.
func hostMatches(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		d = strings.ToLower(d)
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return true
		}
	}
	return false
}

// isHostsOverride reports whether a line redirects a watched name to a
// real address. Loopback and 0.0.0.0 lines are blocks the user chose and
// are left alone, as are lines that cannot be parsed.
func isHostsOverride(line string, watch []string) bool {
	ip, names, ok := parseHostsLine(line)
	if !ok || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	for _, n := range names {
		if hostMatches(n, watch) {
			return true
		}
	}
	return false
}

// hostsOverrideLines lists the override lines (trimmed) in a hosts file.
func hostsOverrideLines(content string, watch []string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if isHostsOverride(line, watch) {
			out = append(out, line)
		}
	}
	return out
}

// disableHostsLines comments out override lines with a stamp so they can be
// found and restored by hand. Line endings and every other byte are kept.
func disableHostsLines(content string, watch []string, stamp string) (string, []string) {
	lines := strings.Split(content, "\n")
	var changed []string
	for i, line := range lines {
		body := strings.TrimRight(line, "\r")
		if !isHostsOverride(body, watch) {
			continue
		}
		changed = append(changed, strings.TrimSpace(body))
		lines[i] = stamp + line
	}
	return strings.Join(lines, "\n"), changed
}

// hostsStampPrefix starts the stamp cleanHosts puts before a line it
// disabled: "# EzPzDPI disabled 2026-11-16 ".
const hostsStampPrefix = "# EzPzDPI disabled "

var reHostsStamp = regexp.MustCompile(`^# EzPzDPI disabled \d{4}-\d{2}-\d{2} `)

// restoreHostsLines removes the stamp disableHostsLines added, bringing the
// original lines back byte for byte. Lines the user wrote are not touched.
// It returns the new content and the restored lines.
func restoreHostsLines(content string) (string, []string) {
	lines := strings.Split(content, "\n")
	var restored []string
	for i, line := range lines {
		loc := reHostsStamp.FindStringIndex(line)
		if loc == nil {
			continue
		}
		lines[i] = line[loc[1]:]
		restored = append(restored, strings.TrimSpace(strings.TrimRight(lines[i], "\r")))
	}
	return strings.Join(lines, "\n"), restored
}

// flowsealHostsIPs are the addresses of Flowseal's "Update hosts" payload.
var flowsealHostsIPs = map[string]bool{
	"162.159.128.233": true, "162.159.135.232": true, "162.159.137.232": true, "162.159.138.232": true,
	"140.82.121.3": true, "146.75.22.132": true, "149.154.167.220": true,
}

var reObsoleteVoiceHost = regexp.MustCompile(`(?i)^finland\d+\.discord\.media$`)

// hostsLineKind sorts an override line: "obsolete" (old voice-server lines
// that point to dead addresses), "flowseal" (the zapret payload) or "other".
func hostsLineKind(line string) string {
	ip, names, ok := parseHostsLine(line)
	if !ok {
		return "other"
	}
	for _, n := range names {
		if reObsoleteVoiceHost.MatchString(n) {
			return "obsolete"
		}
	}
	if flowsealHostsIPs[ip.String()] {
		return "flowseal"
	}
	return "other"
}

// --- proxy (N03) ---

// proxyEndpoints splits a WinINET ProxyServer value ("127.0.0.1:1080" or
// "http=h:p;https=h:p;socks=h:p") into host:port endpoints.
func proxyEndpoints(server string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(server, ";") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '='); i >= 0 {
			part = part[i+1:]
		}
		if i := strings.Index(part, "://"); i >= 0 {
			part = part[i+3:]
		}
		part = strings.TrimSuffix(part, "/")
		if _, port, err := net.SplitHostPort(part); err != nil || port == "" {
			continue
		}
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

// pacEndpoint returns host:port of a PAC (AutoConfigURL) address.
func pacEndpoint(pac string) string {
	u, err := url.Parse(strings.TrimSpace(pac))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	if strings.EqualFold(u.Scheme, "https") {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// isLocalEndpoint reports whether host:port points at this computer.
func isLocalEndpoint(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// cyrillicScore rates one decoding of console output: real Russian text
// has letters, while a wrong code page turns them into box-drawing signs.
func cyrillicScore(s string) int {
	score := 0
	for _, r := range s {
		switch {
		case r >= 'А' && r <= 'я', r == 'Ё', r == 'ё':
			score++
		case r >= 0x2500 && r <= 0x25FF, r == utf8.RuneError:
			score -= 2
		}
	}
	return score
}

// --- wording ---

// whenRu formats an event time for the UI: "сегодня в 14:32",
// "вчера в 09:10" or "12.11 в 18:05".
func whenRu(t, now time.Time) string {
	t = t.In(now.Location())
	y1, m1, d1 := t.Date()
	y2, m2, d2 := now.Date()
	switch {
	case y1 == y2 && m1 == m2 && d1 == d2:
		return "сегодня в " + t.Format("15:04")
	case t.Year() == now.AddDate(0, 0, -1).Year() && t.YearDay() == now.AddDate(0, 0, -1).YearDay():
		return "вчера в " + t.Format("15:04")
	}
	return t.Format("02.01 в 15:04")
}

// pluralRu picks the Russian word form for n: 1 строка, 2 строки, 5 строк.
func pluralRu(n int, one, few, many string) string {
	if m := n % 100; m >= 11 && m <= 14 {
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

// timesRu gives "1 раз", "3 раза", "5 раз".
func timesRu(n int) string {
	return strconv.Itoa(n) + " " + pluralRu(n, "раз", "раза", "раз")
}

// --- interactive user, autostart names, relaunch (N03, F03) ---

// validSID reports whether s looks like a user SID ("S-1-5-21-…",
// "S-1-12-1-…"), so it is safe to use as a key under HKEY_USERS.
func validSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 184 {
		return false
	}
	parts := strings.Split(s[len("S-1-"):], "-")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// winBase is filepath.Base for Windows paths on any OS.
func winBase(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// autostartDisplayName gives a readable name for a ForeignShortcuts
// record: the Run value name, or the Startup file name without ".lnk".
func autostartDisplayName(orig string) string {
	if _, value, ok := parseRunEntryRef(orig); ok {
		return value
	}
	name := winBase(orig)
	if len(name) > 4 && strings.EqualFold(name[len(name)-4:], ".lnk") {
		name = name[:len(name)-4]
	}
	return name
}

// relaunchAllowed reports whether a recorded process may be started again:
// an absolute local path whose file name is a known bypass tool. The record
// can come from a file on disk, so anything else is refused.
func relaunchAllowed(exe string) bool {
	if len(exe) < 4 || exe[1] != ':' || (exe[2] != '\\' && exe[2] != '/') {
		return false
	}
	c := exe[0] | 0x20
	if c < 'a' || c > 'z' || strings.Contains(exe, "..") {
		return false
	}
	_, known := foreignProcTools[strings.ToLower(winBase(exe))]
	return known
}
