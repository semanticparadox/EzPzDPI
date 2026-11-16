//go:build !windows

// Development entry point for non-Windows hosts: checks the embedded
// strategies and runs the connectivity tester without any bypass engine.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	list := flag.Bool("list", false, "распаковать payload во временную папку и показать стратегии")
	flag.Parse()
	if *list {
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
		strats, errs := loadZapretStrategies(filepath.Join(dir, "zapret"))
		strats = append(strats, gdpiStrategies(`C:\x\blacklist.txt`)...)
		for i, s := range strats {
			fmt.Printf("%2d. %-30s %-11s %d аргументов\n", i+1, s.Name, s.Engine, len(s.Args))
		}
		for _, e := range errs {
			fmt.Println("ошибка:", e)
		}
		return
	}
	ctx := context.Background()
	t := NewTester(ctx, Targets)
	for _, n := range t.Notes {
		fmt.Println("DNS:", n)
	}
	r := t.Run(ctx)
	printReport(r)
	fmt.Printf("passed %d/%d\n", r.Passed(), len(r.Results))
}
