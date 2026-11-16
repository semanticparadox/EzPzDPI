package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Engine identifies which bundled DPI-bypass program runs a strategy.
type Engine string

const (
	EngineZapret Engine = "zapret"     // bol-van/zapret winws.exe (strategies from Flowseal)
	EngineGDPI   Engine = "goodbyedpi" // ValdikSS/GoodbyeDPI
)

// Strategy is one ready-to-run command line for an engine.
type Strategy struct {
	Name   string
	Engine Engine
	Args   []string
	rank   int
}

// Key is the stable identifier stored in the config.
func (s Strategy) Key() string { return string(s.Engine) + ":" + s.Name }

// gameFilterOff mirrors Flowseal's service.bat default: the game filter
// profile is pointed at a dummy port when it is disabled.
const gameFilterOff = "12"

var errNoWinws = errors.New("в файле нет строки запуска winws.exe")

// parseFlowsealBat extracts the winws.exe argument list from a Flowseal
// general*.bat file and resolves its %BIN%, %LISTS% and game-filter variables.
func parseFlowsealBat(src, binDir, listsDir string) ([]string, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	lines := strings.Split(src, "\n")
	const marker = `winws.exe"`
	var b strings.Builder
	found := false
	for _, line := range lines {
		if !found {
			idx := strings.Index(strings.ToLower(line), marker)
			if idx < 0 {
				continue
			}
			found = true
			line = line[idx+len(marker):]
		}
		t := strings.TrimRight(line, " \t")
		if strings.HasSuffix(t, "^") {
			b.WriteString(strings.TrimSuffix(t, "^"))
			b.WriteString(" ")
			continue
		}
		b.WriteString(t)
		break
	}
	if !found {
		return nil, errNoWinws
	}
	cmd := strings.NewReplacer(
		"%BIN%", withBackslash(binDir),
		"%LISTS%", withBackslash(listsDir),
		"%GameFilterTCP%", gameFilterOff,
		"%GameFilterUDP%", gameFilterOff,
		"%GameFilter%", gameFilterOff,
	).Replace(b.String())
	if i := strings.Index(cmd, "%"); i >= 0 {
		end := min(len(cmd), i+24)
		return nil, fmt.Errorf("неизвестная переменная в стратегии: %q", cmd[i:end])
	}
	args := splitCmdLine(cmd)
	if len(args) == 0 {
		return nil, errNoWinws
	}
	return args, nil
}

func withBackslash(dir string) string {
	return strings.TrimRight(dir, `\/`) + `\`
}

// splitCmdLine splits a cmd.exe-style argument string: whitespace separates
// arguments, double quotes group text and are removed, and outside quotes a
// caret escapes the next character (Flowseal writes "!" as "^!").
func splitCmdLine(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, has, escaped := false, false, false
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			has, escaped = true, false
			continue
		}
		switch {
		case r == '^' && !inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
			has = true
		case (r == ' ' || r == '\t') && !inQuote:
			if has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		args = append(args, cur.String())
	}
	return args
}

var (
	reParenTag = regexp.MustCompile(`\(([^)]*)\)`)
	reAltTail  = regexp.MustCompile(`(?:^|\s)ALT(\d*)$`)
)

// flowsealRank orders strategies the way Flowseal recommends trying them:
// general first, then ALT..ALTn, then the SIMPLE FAKE and FAKE TLS AUTO
// families, then anything new or experimental.
func flowsealRank(name string) int {
	m := reParenTag.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	tag := strings.ToUpper(strings.TrimSpace(m[1]))
	alt := 0
	if am := reAltTail.FindStringSubmatchIndex(tag); am != nil {
		alt = 1
		if am[2] < am[3] {
			alt, _ = strconv.Atoi(tag[am[2]:am[3]])
		}
		tag = strings.TrimSpace(tag[:am[0]])
	}
	switch tag {
	case "":
		return 100 + alt
	case "SIMPLE FAKE":
		return 300 + alt
	case "FAKE TLS AUTO":
		return 400 + alt
	default:
		return 800 + alt
	}
}

// loadZapretStrategies parses every general*.bat in zapretDir/strategies.
func loadZapretStrategies(zapretDir string) ([]Strategy, []error) {
	files, _ := filepath.Glob(filepath.Join(zapretDir, "strategies", "general*.bat"))
	binDir := filepath.Join(zapretDir, "bin")
	listsDir := filepath.Join(zapretDir, "lists")
	var out []Strategy
	var errs []error
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		args, err := parseFlowsealBat(string(data), binDir, listsDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		out = append(out, Strategy{Name: name, Engine: EngineZapret, Args: args, rank: flowsealRank(name)})
	}
	sortStrategies(out)
	return out, errs
}

func sortStrategies(s []Strategy) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].rank != s[j].rank {
			return s[i].rank < s[j].rank
		}
		return s[i].Name < s[j].Name
	})
}

// gdpiFakeHex is the fake TLS payload from GoodbyeDPI's own
// 1_russia_blacklist_YOUTUBE*.cmd scripts.
const gdpiFakeHex = "160301FFFF01FFFFFF0303594F5552204144564552544953454D454E542048455245202D202431302F6D6F000000000009000000050003000000"

// gdpiStrategies are fallbacks taken from GoodbyeDPI's Russian presets.
func gdpiStrategies(blacklist string) []Strategy {
	mk := func(name string, rank int, args ...string) Strategy {
		full := append(append([]string{}, args...), "--blacklist", blacklist)
		return Strategy{Name: name, Engine: EngineGDPI, Args: full, rank: rank}
	}
	return []Strategy{
		mk("GoodbyeDPI -9 fake", 900, "-9", "--fake-gen", "5", "--fake-from-hex", gdpiFakeHex),
		mk("GoodbyeDPI -5 fake", 901, "-5", "-e1", "-q", "--fake-gen", "5", "--fake-from-hex", gdpiFakeHex),
		mk("GoodbyeDPI -9", 902, "-9"),
	}
}

// buildGdpiBlacklist turns zapret host lists into a GoodbyeDPI blacklist:
// comments dropped, zapret's "^" exact-match prefix removed, duplicates merged.
func buildGdpiBlacklist(lists ...string) string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, line := range strings.Split(strings.ReplaceAll(l, "\r\n", "\n"), "\n") {
			h := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "^"))
			if h == "" || strings.HasPrefix(h, "#") || h == "domain.example.abc" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return strings.Join(out, "\r\n") + "\r\n"
}
