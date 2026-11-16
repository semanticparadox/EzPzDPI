package main

import (
	"strings"
	"testing"
)

func TestEngineLogCode(t *testing.T) {
	cases := []struct {
		name string
		log  string
		code int
		ok   bool
	}{
		{"winws file missing", "windivert: error opening filter: The system cannot find the file specified.", errFileNotFound, true},
		{"winws access denied", "windivert: error opening filter: Access is denied.\r\n", errAccessDenied, true},
		{"winws bad args", "windivert: error opening filter: The parameter is incorrect.", errInvalidParameter, true},
		{"winws signature", "windivert: error opening filter: Windows cannot verify the digital signature for this file. A recent hardware or software change might have installed a file that is signed incorrectly", errInvalidImageHash, true},
		{"winws secure boot line", "windivert: try to disable secure boot and install OS patches", errInvalidImageHash, true},
		{"winws prior driver", "windivert: error opening filter: The driver could not be loaded because a previous version of the driver is still in memory.", errDriverPriorUnload, true},
		{"winws not installed", "windivert: error opening filter: The specified service does not exist as an installed service.", errServiceMissing, true},
		{"winws blocked", "windivert: error opening filter: This driver has been blocked from loading", errDriverBlocked, true},
		{"winws bfe", "windivert: error opening filter: There are no more endpoints available from the endpoint mapper.", errNoEndpoints, true},
		{"winws marked for delete", "windivert: error opening filter: The specified service has been marked for deletion.", errServiceDeleting, true},
		{"winws disabled", "windivert: error opening filter: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.", errServiceDisabled, true},
		{"winws virus", "windivert: error opening filter: Operation did not complete successfully because the file contains a virus or potentially unwanted software.", errVirusInfected, true},
		{"winws app control", "windivert: error opening filter: An Application Control policy has blocked this file.", errPolicyBlocked, true},
		{"winws dark init", "win_dark_init failed. win32 error 1753 (0x000006D9)", errNoEndpoints, true},
		{"gdpi signature", "Error opening filter: 577 Windows cannot verify the digital signature for this file.", errInvalidImageHash, true},
		{"gdpi prior driver", "Error opening filter: 654 The driver could not be loaded", errDriverPriorUnload, true},
		{"gdpi file missing", "Error opening filter: 2 The system cannot find the file specified.", errFileNotFound, true},
		{"gdpi 1275", "Error opening filter: 1275 This driver has been blocked from loading", errDriverBlocked, true},
		{"eac stale driver", "Driver WinDivert is loaded but its file is missing. Please reboot your system to unload the driver", engineCodeEAC, true},
		{"russian code", "Ошибка 1060 при запуске", errServiceMissing, true},
		{"unknown code", "Error opening filter: 31 A device attached to the system is not functioning.", 0, false},
		{"normal output", "windivert initialized. capture is started.", 0, false},
		{"empty", "", 0, false},
		{"no error words", "loaded hostlist 1234 entries", 0, false},
		{"whole log, last wins", "windivert: error opening filter: Windows cannot verify the digital signature\nwindivert: try to disable secure boot and install OS patches\n", errInvalidImageHash, true},
		{"whole log, failure before blank lines", "starting\nError opening filter: 1753 There are no more endpoints\n\n\n", errNoEndpoints, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, ok := engineLogCode(c.log)
			if ok != c.ok || code != c.code {
				t.Fatalf("engineLogCode(%q) = %d, %v; want %d, %v", c.log, code, ok, c.code, c.ok)
			}
		})
	}
}

func TestExplainEngineLog(t *testing.T) {
	cases := []struct {
		line string
		want string // a fragment the advice must contain; "" means no advice
	}{
		{"windivert: error opening filter: The system cannot find the file specified.", "антивирус"},
		{"windivert: try to disable secure boot and install OS patches", "обновления Windows"},
		{"Error opening filter: 654 The driver could not be loaded", "другой версии"},
		{"Error opening filter: 1753 There are no more endpoints", "BFE"},
		{"windivert: error opening filter: Access is denied.", "администратора"},
		{"is loaded but its file is missing. Please reboot your system to unload the driver", "Перезагрузите"},
		{"windivert initialized. capture is started.", ""},
	}
	for _, c := range cases {
		got := explainEngineLog(c.line)
		if c.want == "" {
			if got != "" {
				t.Errorf("explainEngineLog(%q) = %q, want no advice", c.line, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("explainEngineLog(%q) = %q, want it to mention %q", c.line, got, c.want)
		}
	}
}

// Every advice must be plain Russian text without a leftover format verb,
// and every message pattern must point at a code that has advice.
func TestEngineHintsComplete(t *testing.T) {
	for code, h := range engineErrorHints {
		if h == "" || strings.Contains(h, "%") {
			t.Errorf("hint for %d is empty or has a format verb: %q", code, h)
		}
	}
	for _, m := range winMessageCodes {
		if _, ok := engineErrorHints[m.code]; !ok {
			t.Errorf("message %q maps to %d, which has no advice", m.text, m.code)
		}
		if m.text != strings.ToLower(m.text) {
			t.Errorf("message pattern %q must be lower case", m.text)
		}
	}
}
