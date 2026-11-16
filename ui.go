package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var stdin = bufio.NewReader(os.Stdin)

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[90m"
	cRed    = "\x1b[91m"
	cGreen  = "\x1b[92m"
	cYellow = "\x1b[93m"
	cCyan   = "\x1b[96m"
)

// useColor is switched off when the console cannot render ANSI sequences.
var useColor = true

func col(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

// confirm accepts д/да/y/yes and н/нет/n/no; Enter picks the default.
func confirm(prompt string, def bool) bool {
	hint := " [Д/н]: "
	if !def {
		hint = " [д/Н]: "
	}
	for {
		ans := strings.ToLower(ask(prompt + hint))
		switch ans {
		case "":
			return def
		case "д", "да", "y", "yes", "1":
			return true
		case "н", "нет", "n", "no", "0":
			return false
		}
	}
}

func pause() { ask(col(cDim, "Нажмите Enter, чтобы продолжить...")) }

func okMark(ok bool) string {
	if ok {
		return col(cGreen, "работает")
	}
	return col(cRed, "не работает")
}

// serviceLine renders "YouTube: работает   Discord: не работает".
func serviceLine(r Report) string {
	var parts []string
	for _, s := range r.Services() {
		parts = append(parts, fmt.Sprintf("%s: %s", s, okMark(r.ServiceOK(s))))
	}
	return strings.Join(parts, "   ")
}

func printReport(r Report) {
	for _, s := range r.Services() {
		say("  %s %s", col(cBold, s+":"), okMark(r.ServiceOK(s)))
		for _, p := range r.Results {
			if p.Service != s {
				continue
			}
			if p.OK {
				say("    %s %-28s %s", col(cGreen, "+"), p.Host, col(cDim, fmt.Sprintf("%d мс", p.Took.Milliseconds())))
			} else {
				say("    %s %-28s %s", col(cRed, "-"), p.Host, col(cYellow, p.Err))
			}
		}
	}
}

// shortFailure names the first failing host per service for one-line output.
func shortFailure(r Report) string {
	for _, p := range r.Results {
		if !p.OK {
			return p.Host + ": " + p.Err
		}
	}
	return ""
}
