//go:build windows

package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

//go:embed ui/index.html ui/fonts/*.woff2
var uiFS embed.FS

var errNoWebView = errors.New("WebView2 недоступен")

var procGetDpiForSystem = windows.NewLazySystemDLL("user32.dll").NewProc("GetDpiForSystem")

// systemDPI returns the display DPI (96 = 100%).
func systemDPI() int {
	if procGetDpiForSystem.Find() != nil {
		return 96
	}
	if d, _, _ := procGetDpiForSystem.Call(); d >= 96 && d <= 480 {
		return int(d)
	}
	return 96
}

// uiHTML returns the page with fonts inlined as data URLs, so the window
// needs no network and no files on disk.
func uiHTML() (string, error) {
	page, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		return "", err
	}
	html := string(page)
	for _, f := range []string{"Onest.woff2", "Unbounded.woff2"} {
		data, err := uiFS.ReadFile("ui/fonts/" + f)
		if err != nil {
			return "", err
		}
		url := "data:font/woff2;base64," + base64.StdEncoding.EncodeToString(data)
		html = strings.ReplaceAll(html, `"fonts/`+f+`"`, `"`+url+`"`)
	}
	return html, nil
}

// uiTest, when set, drives the window automatically (-uitest).
type uiTest struct {
	shot   string // PNG path for a window capture
	report func(string)
}

// runGUI opens the window and blocks until it is closed.
func runGUI(a *App) error { return runWindow(a, nil) }

func runWindow(a *App, test *uiTest) error {
	html, err := uiHTML()
	if err != nil {
		return err
	}
	// The window size is in physical pixels; scale it for 125-200% displays.
	scale := func(px int) int { return px * systemDPI() / 96 }
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		// Browser data stays in the user's temp folder: it is locked while
		// the window is open and must not block removing the data dir.
		DataPath: filepath.Join(os.TempDir(), "EzPzDPI-webview"),
		WindowOptions: webview2.WindowOptions{
			Title:  appName,
			Width:  uint(scale(1000)),
			Height: uint(scale(720)),
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		return errNoWebView
	}
	defer w.Destroy()
	w.SetSize(scale(760), scale(560), webview2.HintMin)

	c := newController(a)
	c.onChange = func(vs ViewState) {
		b, err := json.Marshal(vs)
		if err != nil {
			return
		}
		w.Dispatch(func() { w.Eval("window.ezpzState && window.ezpzState(" + string(b) + ")") })
	}
	// Bound functions run on the UI thread: every one returns at once and
	// leaves long work to the controller's goroutine.
	bind := func(name string, f any) {
		if err := w.Bind(name, f); err != nil {
			a.logf("bind %s: %v", name, err)
		}
	}
	bind("ezpzReady", func() { go c.Republish() })
	bind("ezpzMain", func() { go c.Main() })
	bind("ezpzSecond", func() { go c.Second() })
	bind("ezpzCancel", func() { go c.Cancel() })
	bind("ezpzStop", func() { go c.Stop() })
	bind("ezpzAction", func(notice, action string) { go c.Action(notice, action) })
	bind("ezpzSettings", func(s SettingsView) { go c.Settings(s) })
	bind("ezpzUpdate", func() { go c.Update() })
	bind("ezpzUninstall", func(restore bool) { go c.Uninstall(restore) })
	bind("ezpzManual", func(key string) { go c.Manual(key) })
	bind("ezpzOpenLog", func() { go c.OpenLog() })
	bind("ezpzOpenURL", func(url string) { go c.OpenURL(url) })
	bind("ezpzSecureDNS", func(enable bool) { go c.SecureDNS(enable) })
	bind("ezpzRestoreForeign", func() { go c.RestoreForeign() })
	bind("ezpzDefender", func(enable bool) { go c.Defender(enable) })
	if test != nil {
		var once sync.Once
		bind("ezpzTestReport", func(summary string) {
			go func() {
				time.Sleep(1500 * time.Millisecond) // let the route drawings settle
				if test.shot != "" {
					if err := captureWindow(uintptr(w.Window()), test.shot); err != nil {
						summary += "\ncapture: " + err.Error()
					}
				}
				test.report(summary)
				w.Dispatch(w.Terminate)
			}()
		})
		inner := c.onChange
		c.onChange = func(vs ViewState) {
			inner(vs)
			if vs.Phase == "diagnosed" {
				once.Do(func() {
					w.Dispatch(func() {
						w.Eval(`setTimeout(function(){ezpzTestReport(JSON.stringify({title:document.getElementById("v-title").textContent,rows:document.querySelectorAll(".row").length,notices:document.querySelectorAll(".notice").length,provenance:(document.querySelector(".provenance")||{}).textContent||"",states:[].map.call(document.querySelectorAll(".row"),function(r){return r.dataset.state})}))},1200)`)
					})
				})
			}
		}
		go func() {
			time.Sleep(2 * time.Second)
			for i := 0; i < 30 && c.Busy(); i++ {
				time.Sleep(time.Second)
			}
			c.Check(false)
		}()
		go func() { // never hang a test run
			time.Sleep(3 * time.Minute)
			test.report("timeout")
			w.Dispatch(w.Terminate)
		}()
	}
	w.Init("window.__EZPZ_APP__ = true;")
	w.SetHtml(html)

	go c.Start()
	w.Run()
	c.Shutdown() // the window closed: abort a running fix and roll it back
	return nil
}

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	gdi32              = windows.NewLazySystemDLL("gdi32.dll")
	procGetClientRect  = user32.NewProc("GetClientRect")
	procGetDC          = user32.NewProc("GetDC")
	procReleaseDC      = user32.NewProc("ReleaseDC")
	procPrintWindow    = user32.NewProc("PrintWindow")
	procCreateCompatDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSect  = gdi32.NewProc("CreateDIBSection")
	procSelectObject   = gdi32.NewProc("SelectObject")
	procDeleteObject   = gdi32.NewProc("DeleteObject")
	procDeleteDC       = gdi32.NewProc("DeleteDC")
)

// captureWindow saves the window's client area as PNG (test mode only).
// PW_RENDERFULLCONTENT captures the DirectComposition content WebView2 draws.
func captureWindow(hwnd uintptr, path string) error {
	var rc struct{ L, T, R, B int32 }
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	w, h := int(rc.R-rc.L), int(rc.B-rc.T)
	if w <= 0 || h <= 0 {
		return errors.New("empty window")
	}
	screen, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, screen)
	mem, _, _ := procCreateCompatDC.Call(screen)
	defer procDeleteDC.Call(mem)
	type bmiHeader struct {
		Size                                uint32
		Width, Height                       int32
		Planes, BitCount                    uint16
		Compression, SizeImage              uint32
		XPels, YPels, ClrUsed, ClrImportant int32
	}
	bi := bmiHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSect.Call(mem, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 {
		return errors.New("CreateDIBSection failed")
	}
	defer procDeleteObject.Call(bmp)
	procSelectObject.Call(mem, bmp)
	const pwClientOnly, pwRenderFullContent = 1, 2
	if r, _, _ := procPrintWindow.Call(hwnd, mem, pwClientOnly|pwRenderFullContent); r == 0 {
		return errors.New("PrintWindow failed")
	}
	src := unsafe.Slice((*byte)(bits), w*h*4)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		img.Pix[i*4+0], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = src[i*4+2], src[i*4+1], src[i*4+0], 255
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// runUITest opens the real window without admin rights and without the
// driver, runs a check automatically and prints what the page rendered.
func runUITest(dataDir, shot string) int {
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), appName+"-uitest")
	}
	a := &App{dataDir: dataDir, cfg: defaultConfig()}
	if err := os.MkdirAll(a.logDir(), 0o755); err != nil {
		say("mkdir: %v", err)
		return 1
	}
	if _, err := a.ensurePayload(false); err != nil {
		say("payload: %v", err)
		return 1
	}
	_ = a.ensureEngineCopies()
	_ = a.writeExtraList()
	a.loadStrategies()
	result := "no report"
	err := runWindow(a, &uiTest{shot: shot, report: func(s string) { result = s }})
	say("uitest: %s", result)
	if err != nil {
		say("uitest error: %v", err)
		return 1
	}
	return 0
}
