package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// A trimmed /V /NH row has 28 columns; only positions 1 and 8 matter. The
// Russian headers and statuses below prove nothing depends on the language.
const schtasksSample = `"PC","\winws1","N/A","Готово","Интерактивно/в фоне","16.11.2026 10:00:00","0","PC\Art","C:\zapret\zapret-winws\winws.exe --wf-tcp=80,443","N/A","N/A","Включено","Отключено","","SYSTEM","Отключено","72:00:00","Планирование","При входе в систему","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A"
"PC","\winws1","N/A","Готово","Интерактивно/в фоне","16.11.2026 10:00:00","0","PC\Art","C:\zapret\zapret-winws\winws.exe --wf-tcp=80,443","N/A","N/A","Включено","Отключено","","SYSTEM","Отключено","72:00:00","Планирование","При запуске","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A"

"Имя узла","Имя задачи","Время следующего запуска","Состояние","Режим входа в систему","Время прошлого запуска","Прошлый результат","Автор","Задача для выполнения"
"PC","\Microsoft\Windows\Defrag\ScheduledDefrag","N/A","Ready","Background","N/A","0","Microsoft","%windir%\system32\defrag.exe -c -h -o -$","N/A"
"PC","\Discord ""fix""","N/A","Ready","Interactive","N/A","0","Art","cmd /c ""C:\Users\Art\Desktop\zapret-discord-youtube-1.10.4\general (ALT3).bat""","N/A"
`

func TestParseSchtasksCSV(t *testing.T) {
	got := parseSchtasksCSV(schtasksSample)
	want := []schedTask{
		{Name: `\winws1`, Action: `C:\zapret\zapret-winws\winws.exe --wf-tcp=80,443`, Enabled: true},
		{Name: `\Microsoft\Windows\Defrag\ScheduledDefrag`, Action: `%windir%\system32\defrag.exe -c -h -o -$`, Enabled: true},
		{Name: `\Discord "fix"`, Action: `cmd /c "C:\Users\Art\Desktop\zapret-discord-youtube-1.10.4\general (ALT3).bat"`, Enabled: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSchtasksCSV:\n got %#v\nwant %#v", got, want)
	}
	if got := commandTarget(want[2].Action); got != `C:\Users\Art\Desktop\zapret-discord-youtube-1.10.4\general (ALT3).bat` {
		t.Errorf("commandTarget = %q", got)
	}
	if got := commandTarget(want[1].Action); got != "" {
		t.Errorf("commandTarget(defrag) = %q, want empty", got)
	}
}

func TestTaskXMLEnabled(t *testing.T) {
	on := `<Task><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers><Settings><Enabled>true</Enabled></Settings></Task>`
	off := `<Task><Settings>
    <IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd></IdleSettings>
    <Enabled>false</Enabled>
  </Settings></Task>`
	if !taskXMLEnabled(on) || taskXMLEnabled(off) || !taskXMLEnabled(`<Task><Settings/></Task>`) {
		t.Fatal("taskXMLEnabled: wrong result")
	}
}

// Two events as wevtutil prints them: no root element, default namespace.
const wevtutilSample = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7034</EventID><Version>0</Version><Level>2</Level><TimeCreated SystemTime='2026-11-16T11:32:10.4512345Z'/><Channel>System</Channel></System><EventData><Data Name='param1'>zapret</Data><Data Name='param2'>2</Data><Binary>7A00610070007200650074000000</Binary></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7031</EventID><TimeCreated SystemTime='2026-11-15T08:00:00.0000000Z'/></System><EventData><Data Name='param1'>Служба GoodbyeDPI</Data><Data Name='param2'>1</Data><Data Name='param3'>0</Data><Data Name='param4'>0</Data><Data Name='param5'>Нет действия</Data><Binary>47006F006F006400620079006500440050004900000000</Binary></EventData></Event>
`

func TestParseSCMEvents(t *testing.T) {
	ev := parseSCMEvents(wevtutilSample)
	if len(ev) != 2 {
		t.Fatalf("got %d events, want 2", len(ev))
	}
	if ev[0].ID != 7034 || ev[0].Service != "zapret" || ev[0].Params[0] != "zapret" {
		t.Errorf("event 0 = %+v", ev[0])
	}
	if want := time.Date(2026, 11, 16, 11, 32, 10, 451234500, time.UTC); !ev[0].Time.Equal(want) {
		t.Errorf("time = %v, want %v", ev[0].Time, want)
	}
	if ev[1].ID != 7031 || ev[1].Service != "GoodbyeDPI" || len(ev[1].Params) != 5 {
		t.Errorf("event 1 = %+v", ev[1])
	}
	if !ev[1].matches("goodbyedpi", "") || !ev[1].matches("x", "Служба GoodbyeDPI") || ev[0].matches("winws1", "winws1") {
		t.Error("scmEvent.matches: wrong result")
	}
	if got := parseSCMEvents("garbage <Event"); len(got) != 0 {
		t.Errorf("garbage gave %d events", len(got))
	}
}

func TestFlowsealVersion(t *testing.T) {
	bat := "@echo off\r\nset \"LOCAL_VERSION=1.10.4\"\r\n\r\n:: External commands\r\n"
	if got := flowsealVersion(bat); got != "1.10.4" {
		t.Errorf("quoted: %q", got)
	}
	if got := flowsealVersion("set LOCAL_VERSION=1.9.0b\n"); got != "1.9.0b" {
		t.Errorf("unquoted: %q", got)
	}
	if got := flowsealVersion("echo LOCAL_VERSION=2\n"); got != "" {
		t.Errorf("no set: %q", got)
	}
}

func TestIPsetMode(t *testing.T) {
	cases := map[string]string{
		"203.0.113.113/32\r\n": "none",
		"":                     "any",
		"\r\n\r\n":             "any",
		"1.2.3.0/24\n5.6.7.8":  "loaded",
	}
	for in, want := range cases {
		if got := ipsetMode(in); got != want {
			t.Errorf("ipsetMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBypassToolOf(t *testing.T) {
	cases := map[string]string{
		`"C:\zapret-discord-youtube\bin\winws.exe" --wf-tcp=80`: toolZapret,
		`C:\Tools\zapret2\winws2.exe --lua-init=x`:              toolZapret2,
		`C:\GoodbyeDPI\x86_64\goodbyedpi.exe -9 --blacklist`:    toolGoodbyeDPI,
		`C:\ByeDPI\ciadpi.exe -i 127.0.0.1`:                     toolByeDPI,
		`C:\Users\a\Desktop\discord\general (ALT2).bat`:         toolZapret,
		`discordfix_zapret`:                                     toolZapret,
		`C:\Windows\system32\svchost.exe -k netsvcs`:            "",
		`C:\Games\general.exe`:                                  "",
	}
	for in, want := range cases {
		if got := bypassToolOf(in); got != want {
			t.Errorf("bypassToolOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageExePath(t *testing.T) {
	cases := map[string]string{
		`"C:\z\bin\winws.exe" --wf-tcp=80 --filter-udp=50000-50100`: `C:\z\bin\winws.exe`,
		`C:\Program Files\GoodbyeDPI\goodbyedpi.exe -9`:             `C:\Program Files\GoodbyeDPI\goodbyedpi.exe`,
		`\??\C:\z\bin\WinDivert64.sys`:                              `C:\z\bin\WinDivert64.sys`,
		`\SystemRoot\System32\drivers\x.sys`:                        `C:\Windows\System32\drivers\x.sys`,
		`System32\drivers\y.sys`:                                    `C:\Windows\System32\drivers\y.sys`,
	}
	for in, want := range cases {
		if got := imageExePath(in, `C:\Windows`); got != want {
			t.Errorf("imageExePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunEntryRef(t *testing.T) {
	ref := runEntryRef(`HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run`, "zapret | autostart")
	k, v, ok := parseRunEntryRef(ref)
	if !ok || k != `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run` || v != "zapret | autostart" {
		t.Errorf("round trip: %q %q %v", k, v, ok)
	}
	if _, _, ok := parseRunEntryRef(`C:\Users\a\Startup\x.lnk`); ok {
		t.Error("file path parsed as a registry ref")
	}
}

func TestHostsLines(t *testing.T) {
	watch := []string{"discord.com", "discord.media", "youtube.com", "github.com"}
	content := "# Copyright (c) Microsoft\r\n" +
		"127.0.0.1 localhost\r\n" +
		"0.0.0.0 youtube.com # my own block\r\n" +
		"162.159.137.232 discord.com updates.discord.com\r\n" +
		"104.25.158.178 finland10000.discord.media\r\n" +
		"  1.2.3.4\twww.youtube.com\r\n" +
		"#140.82.121.3 github.com\r\n" +
		"not-an-ip discord.com\r\n" +
		"10.0.0.1 nas.local"
	want := []string{
		"162.159.137.232 discord.com updates.discord.com",
		"104.25.158.178 finland10000.discord.media",
		"1.2.3.4\twww.youtube.com",
	}
	if got := hostsOverrideLines(content, watch); !reflect.DeepEqual(got, want) {
		t.Fatalf("hostsOverrideLines = %q", got)
	}
	kinds := []string{hostsLineKind(want[0]), hostsLineKind(want[1]), hostsLineKind(want[2])}
	if !reflect.DeepEqual(kinds, []string{"flowseal", "obsolete", "other"}) {
		t.Errorf("hostsLineKind = %v", kinds)
	}
	out, changed := disableHostsLines(content, watch, "# EzPzDPI disabled 2026-11-16 ")
	if !reflect.DeepEqual(changed, want) {
		t.Errorf("changed = %q", changed)
	}
	if strings.Count(out, "\r\n") != strings.Count(content, "\r\n") || !strings.HasSuffix(out, "10.0.0.1 nas.local") {
		t.Error("line endings or untouched lines changed")
	}
	if !strings.Contains(out, "\r\n# EzPzDPI disabled 2026-11-16   1.2.3.4\twww.youtube.com\r\n") {
		t.Errorf("stamp missing:\n%s", out)
	}
	if again := hostsOverrideLines(out, watch); len(again) != 0 {
		t.Errorf("still active after disable: %q", again)
	}
}

func TestProxyEndpoints(t *testing.T) {
	got := proxyEndpoints("http=127.0.0.1:10809;https=127.0.0.1:10809;socks=socks5://localhost:1080/;ftp=bad")
	if want := []string{"127.0.0.1:10809", "localhost:1080"}; !reflect.DeepEqual(got, want) {
		t.Errorf("proxyEndpoints = %q, want %q", got, want)
	}
	if got := proxyEndpoints("10.0.0.5:3128"); !reflect.DeepEqual(got, []string{"10.0.0.5:3128"}) {
		t.Errorf("plain = %q", got)
	}
	if got := pacEndpoint("http://127.0.0.1:2080/proxy.pac"); got != "127.0.0.1:2080" {
		t.Errorf("pac = %q", got)
	}
	if got := pacEndpoint("https://corp.example/wpad.dat"); got != "corp.example:443" {
		t.Errorf("pac default port = %q", got)
	}
	if !isLocalEndpoint("localhost:1080") || !isLocalEndpoint("[::1]:8080") || isLocalEndpoint("10.0.0.5:3128") {
		t.Error("isLocalEndpoint: wrong result")
	}
}

func TestWhenRu(t *testing.T) {
	now := time.Date(2026, 11, 16, 15, 0, 0, 0, time.UTC)
	cases := map[time.Time]string{
		time.Date(2026, 11, 16, 14, 32, 0, 0, time.UTC): "сегодня в 14:32",
		time.Date(2026, 11, 15, 9, 5, 0, 0, time.UTC):   "вчера в 09:05",
		time.Date(2026, 11, 12, 18, 5, 0, 0, time.UTC):  "12.11 в 18:05",
	}
	for in, want := range cases {
		if got := whenRu(in, now); got != want {
			t.Errorf("whenRu(%v) = %q, want %q", in, got, want)
		}
	}
	for n, want := range map[int]string{1: "1 раз", 3: "3 раза", 5: "5 раз", 12: "12 раз", 22: "22 раза"} {
		if got := timesRu(n); got != want {
			t.Errorf("timesRu(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCyrillicScore(t *testing.T) {
	// "Готово" in cp1251 shown as cp866 turns capitals into box drawing.
	if cyrillicScore("Готово") <= cyrillicScore("ѓ®в®ў®") || cyrillicScore("Готово") <= cyrillicScore("╨У╨╛╤В") {
		t.Error("cyrillicScore prefers a broken decoding")
	}
	if cyrillicScore("plain ascii") != 0 {
		t.Error("ascii should score 0")
	}
}

// utf16LE encodes s as a task file on disk: UTF-16 LE with a BOM.
func utf16LE(s string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

const taskFileSample = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\Арт\Desktop\zapret discord\bin\winws.exe</Command>
      <Arguments>--wf-tcp=80,443 --hostlist="C:\z\list.txt"</Arguments>
    </Exec>
  </Actions>
</Task>`

func TestTaskXMLFile(t *testing.T) {
	for _, raw := range [][]byte{utf16LE(taskFileSample, true), utf16LE(taskFileSample, false), []byte("\xEF\xBB\xBF" + taskFileSample)} {
		doc := decodeTaskXML(raw)
		if doc != taskFileSample {
			t.Fatalf("decodeTaskXML: %q", doc[:min(len(doc), 60)])
		}
		action, ok := taskXMLAction(doc)
		want := `"C:\Users\Арт\Desktop\zapret discord\bin\winws.exe" --wf-tcp=80,443 --hostlist="C:\z\list.txt"`
		if !ok || action != want {
			t.Errorf("taskXMLAction = %q %v", action, ok)
		}
		if taskXMLEnabled(doc) {
			t.Error("Settings Enabled=false read as enabled")
		}
		if got := commandTarget(action); got != `C:\Users\Арт\Desktop\zapret discord\bin\winws.exe` {
			t.Errorf("commandTarget = %q", got)
		}
	}
	com := `<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><ComHandler><ClassId>{X}</ClassId></ComHandler></Actions></Task>`
	if _, ok := taskXMLAction(com); ok {
		t.Error("COM handler task reported as Exec")
	}
	if _, ok := taskXMLAction("<Task><Actions><Exec><Command>x"); ok {
		t.Error("broken XML accepted")
	}
	plain := `<Task><Actions><Exec><Command>"C:\z\winws.exe"</Command></Exec></Actions></Task>`
	if a, ok := taskXMLAction(plain); !ok || a != `"C:\z\winws.exe"` {
		t.Errorf("quoted command = %q %v", a, ok)
	}
	for in, want := range map[string]string{`winws1`: `\winws1`, `Zapret/winws1`: `\Zapret\winws1`, `Zapret\winws2`: `\Zapret\winws2`} {
		if got := taskNameFromPath(in); got != want {
			t.Errorf("taskNameFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRestoreHostsLines(t *testing.T) {
	watch := []string{"discord.com", "youtube.com"}
	orig := "# hosts\r\n" +
		"162.159.137.232 discord.com\r\n" +
		"# EzPzDPI disabled by hand, keep\r\n" +
		"  1.2.3.4\twww.youtube.com\r\n" +
		"127.0.0.1 localhost"
	disabled, changed := disableHostsLines(orig, watch, hostsStampPrefix+"2026-11-16 ")
	if len(changed) != 2 {
		t.Fatalf("disabled %q", changed)
	}
	back, restored := restoreHostsLines(disabled)
	if back != orig {
		t.Errorf("round trip changed the file:\n%q\n%q", back, orig)
	}
	if !reflect.DeepEqual(restored, []string{"162.159.137.232 discord.com", "1.2.3.4\twww.youtube.com"}) {
		t.Errorf("restored = %q", restored)
	}
	if out, none := restoreHostsLines(orig); out != orig || len(none) != 0 {
		t.Errorf("nothing to restore changed something: %q", none)
	}
}

func TestValidSID(t *testing.T) {
	for s, want := range map[string]bool{
		"S-1-5-21-1004336348-1177238915-682003330-1001":  true,
		"S-1-12-1-3263394384-1155424545-2519410612-1234": true,
		"S-1-5-18":                  true,
		"":                          false,
		"S-1-5-21-1-1001\\Software": false,
		"S-1-5-21--1":               false,
		"S-1-":                      false,
		"S-1-5-21-99999999999":      false,
	} {
		if got := validSID(s); got != want {
			t.Errorf("validSID(%q) = %v", s, got)
		}
	}
}

func TestAutostartDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\zapret.lnk`:     "zapret",
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\general (ALT).bat`:          "general (ALT).bat",
		runEntryRef(`HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run`, "GoodbyeDPI"): "GoodbyeDPI",
		`x.LNK`: "x",
		`.lnk`:  ".lnk",
	} {
		if got := autostartDisplayName(in); got != want {
			t.Errorf("autostartDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRelaunchAllowed(t *testing.T) {
	for exe, want := range map[string]bool{
		`C:\zapret\bin\winws.exe`:                            true,
		`d:/tools/GoodbyeDPI/x86_64/goodbyedpi.exe`:          true,
		`C:\Program Files\ByeDPI Manager\ByeDPI Manager.exe`: true,
		`C:\Windows\System32\cmd.exe`:                        false,
		`winws.exe`:                                          false,
		`\\server\share\winws.exe`:                           false,
		`C:\z\..\Windows\winws.exe`:                          false,
		`C:\z\winws.exe.bat`:                                 false,
	} {
		if got := relaunchAllowed(exe); got != want {
			t.Errorf("relaunchAllowed(%q) = %v", exe, got)
		}
	}
}
