//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLogonTaskXMLValid hands the task definition to the Task Scheduler
// COM API, which validates it against the schema without registering it.
func TestLogonTaskXMLValid(t *testing.T) {
	xml := logonTaskXML("S-1-5-21-1111111111-2222222222-3333333333-1001", `C:\ProgramData\EzPzDPI\EzPzDPI.exe`, []string{"-heal"})
	p := filepath.Join(t.TempDir(), "task.xml")
	if err := os.WriteFile(p, encodeUTF16LE(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	ps := `$s = New-Object -ComObject Schedule.Service; $s.Connect(); $d = $s.NewTask(0); ` +
		`$d.XmlText = [IO.File]::ReadAllText('` + p + `'); ` +
		`"ok " + $d.Triggers.Count + " " + $d.Settings.DisallowStartIfOnBatteries + " " + $d.Principal.RunLevel`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "ok 1 False 1") {
		t.Fatalf("task XML rejected: %v: %s", err, out)
	}
}
