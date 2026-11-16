package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSplitCmdLine(t *testing.T) {
	got := splitCmdLine(`--a=1  --hostlist="C:\x y\l.txt" "--b" --c= --fake-tls=^! "--q=^!"`)
	want := []string{"--a=1", `--hostlist=C:\x y\l.txt`, "--b", "--c=", "--fake-tls=!", "--q=^!"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseFlowsealBat(t *testing.T) {
	src := "@echo off\r\nset \"BIN=%~dp0bin\\\"\r\n" +
		"start \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilterTCP% ^\r\n" +
		"--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --dpi-desync-fake-tls=\"%BIN%tls.bin\" --new ^\r\n" +
		"--filter-udp=%GameFilterUDP% --dpi-desync=fake\r\n" +
		"echo done\r\n"
	got, err := parseFlowsealBat(src, `C:\D\zapret\bin`, `C:\D\zapret\lists\`, gameFilterOff)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--wf-tcp=80,443,12",
		"--filter-tcp=443", `--hostlist=C:\D\zapret\lists\list-google.txt`, `--dpi-desync-fake-tls=C:\D\zapret\bin\tls.bin`, "--new",
		"--filter-udp=12", "--dpi-desync=fake",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if _, err := parseFlowsealBat("echo hi", "a", "b", gameFilterOff); err == nil {
		t.Fatal("expected error for a file without winws.exe")
	}
	if _, err := parseFlowsealBat(`"%BIN%winws.exe" --x=%Unknown%`, "a", "b", gameFilterOff); err == nil {
		t.Fatal("expected error for an unknown variable")
	}
}

func TestFlowsealRankOrder(t *testing.T) {
	names := []string{
		"general (EXP)", "general (FAKE TLS AUTO ALT)", "general (ALT10)", "general (SIMPLE FAKE)",
		"general (ALT2)", "general", "general (FAKE TLS AUTO)", "general (ALT)",
	}
	var s []Strategy
	for _, n := range names {
		s = append(s, Strategy{Name: n, rank: flowsealRank(n)})
	}
	sortStrategies(s)
	var got []string
	for _, x := range s {
		got = append(got, x.Name)
	}
	want := []string{
		"general", "general (ALT)", "general (ALT2)", "general (ALT10)", "general (SIMPLE FAKE)",
		"general (FAKE TLS AUTO)", "general (FAKE TLS AUTO ALT)", "general (EXP)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.10.4", "1.10.5", true}, {"1.10.4", "1.9.9", false}, {"1.10.4", "1.10.4", false},
		{"", "1.0", true}, {"v1.11", "1.10.9", false}, {"0.2.3rc3-2", "0.2.4", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

func TestBuildGdpiBlacklist(t *testing.T) {
	got := buildGdpiBlacklist("^dns.google\r\ndiscord.com\n# c\n", "discord.com\ndomain.example.abc\nyoutube.com")
	want := "dns.google\r\ndiscord.com\r\nyoutube.com\r\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

// TestEmbeddedPayload checks the real bundled Flowseal strategies: every file
// parses, no variable is left unresolved and every referenced file exists.
func TestEmbeddedPayload(t *testing.T) {
	dir := t.TempDir()
	zr, err := embeddedZip()
	if err != nil {
		t.Fatal(err)
	}
	if err := extractZip(zr, dir, func(n string) (string, bool) { return n, true }); err != nil {
		t.Fatal(err)
	}
	if err := ensureUserLists(filepath.Join(dir, "zapret", "lists")); err != nil {
		t.Fatal(err)
	}
	info, err := readEmbeddedInfo()
	if err != nil || info.Flowseal == "" || info.GoodbyeDPI == "" {
		t.Fatalf("payload.json: %+v %v", info, err)
	}
	for _, f := range []string{"zapret/bin/winws.exe", "zapret/bin/cygwin1.dll", "zapret/bin/WinDivert64.sys",
		"gdpi/goodbyedpi.exe", "gdpi/WinDivert.dll", "licenses/THIRD-PARTY.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	// Parse with Windows-style roots, then map the paths back to the temp dir.
	const win = `C:\ProgramData\EzPzDPI\zapret`
	files, _ := filepath.Glob(filepath.Join(dir, "zapret", "strategies", "general*.bat"))
	if len(files) < 15 {
		t.Fatalf("only %d strategy files", len(files))
	}
	for _, f := range files {
		src, _ := os.ReadFile(f)
		args, err := parseFlowsealBat(string(src), win+`\bin`, win+`\lists`, gameFilterOn)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		for _, a := range args {
			i := strings.Index(a, win)
			if i < 0 {
				continue
			}
			rel := strings.ReplaceAll(a[i+len(win):], `\`, "/")
			if _, err := os.Stat(filepath.Join(dir, "zapret", rel)); err != nil {
				t.Errorf("%s: referenced file missing: %s", filepath.Base(f), rel)
			}
		}
	}
}

func TestInstallFlowsealZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	add("rel-9.9/bin/winws.exe", "exe")
	add("rel-9.9/bin/new.bin", "bin")
	add("rel-9.9/lists/list-general.txt", "discord.com\n")
	add("rel-9.9/lists/list-general-user.txt", "SHOULD NOT OVERWRITE")
	add("rel-9.9/general (ALT9).bat", `start "" "%BIN%winws.exe" --wf-tcp=443`)
	add("rel-9.9/service.bat", "ignored")
	add("rel-9.9/../evil.txt", "x")
	zw.Close()

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "lists"), 0o755)
	os.MkdirAll(filepath.Join(dir, "strategies"), 0o755)
	os.WriteFile(filepath.Join(dir, "lists", "list-general-user.txt"), []byte("mine"), 0o644)
	os.WriteFile(filepath.Join(dir, "strategies", "general (OLD).bat"), []byte("old"), 0o644)

	n, err := installFlowsealZip(buf.Bytes(), dir)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "lists", "list-general-user.txt")); string(b) != "mine" {
		t.Errorf("user list overwritten: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "strategies", "general (OLD).bat")); err == nil {
		t.Error("old strategy not removed")
	}
	for _, f := range []string{"bin/winws.exe", "bin/new.bin", "strategies/general (ALT9).bat", "lists/list-exclude-user.txt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "service.bat")); err == nil {
		t.Error("service.bat should not be installed")
	}

	if _, err := installFlowsealZip([]byte("not a zip"), dir); err == nil {
		t.Error("expected error for garbage input")
	}
}
