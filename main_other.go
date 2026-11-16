//go:build !windows

// Development entry point for non-Windows hosts: checks the embedded
// strategies and runs the diagnosis without any bypass engine.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	list := flag.Bool("list", false, "распаковать payload во временную папку и показать стратегии")
	stun := flag.Bool("stun", false, "проверить UDP через STUN")
	flag.Parse()
	switch {
	case *list:
		dir, err := os.MkdirTemp("", "ezpzdpi-*")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer os.RemoveAll(dir)
		zr, err := embeddedZip()
		if err == nil {
			err = extractZip(zr, dir, func(n string) (string, bool) { return n, true })
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		info, _ := readEmbeddedInfo()
		fmt.Printf("payload: Flowseal %s, GoodbyeDPI %s\n", info.Flowseal, info.GoodbyeDPI)
		strats, errs := loadZapretStrategies(filepath.Join(dir, "zapret"), gameFilterOff, `C:\x\list-ezpzdpi.txt`)
		strats = append(strats, gdpiStrategies(`C:\x\blacklist.txt`)...)
		for i, s := range strats {
			fmt.Printf("%2d. %-30s %-11s %d аргументов\n", i+1, s.Name, s.Engine, len(s.Args))
		}
		for _, e := range errs {
			fmt.Println("ошибка:", e)
		}
	case *stun:
		for _, addr := range []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"} {
			r := stunProbe(context.Background(), addr, 10, 200*time.Millisecond)
			fmt.Printf("%-28s sent %d got %d loss %.0f%% median %v maxgap %d %s\n", addr, r.Sent, r.Got, 100*r.Loss(), r.Median, r.MaxGap, r.Err)
		}
	default:
		ctx := context.Background()
		t := NewTester(ctx, allTargets(nil))
		t.Neutral = true
		for _, n := range t.Notes {
			fmt.Println("DNS:", n)
		}
		r := t.Run(ctx)
		byID := catalogByID()
		for _, id := range r.Services() {
			d := Diagnose(byID[id], r)
			fmt.Printf("%-14s %-10s %s\n", byID[id].Name, d.State, d.Detail)
		}
	}
}
