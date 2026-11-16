package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Target is one HTTPS endpoint the tester fetches. MinBytes > 0 means the
// body must deliver that many bytes: it catches throttling and the
// "freeze after 16-20 KB" pattern, not only outright blocks.
type Target struct {
	Service  string
	Host     string
	Path     string
	MinBytes int64
}

// Targets are the checks behind "YouTube works" and "Discord works".
var Targets = []Target{
	{"YouTube", "www.youtube.com", "/", 128 << 10},
	{"YouTube", "i.ytimg.com", "/vi/dQw4w9WgXcQ/maxresdefault.jpg", 60 << 10},
	{"YouTube", "redirector.googlevideo.com", "/report_mapping?di=no", 0},
	{"Discord", "discord.com", "/", 64 << 10},
	{"Discord", "gateway.discord.gg", "/", 0},
	{"Discord", "cdn.discordapp.com", "/", 0},
	{"Discord", "updates.discord.com", "/", 0},
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// ProbeResult is the outcome of fetching one Target.
type ProbeResult struct {
	Target
	OK     bool
	Status int
	Bytes  int64
	Took   time.Duration
	Err    string
	// CertErr marks a certificate mismatch: usually an ISP block page
	// reached through a spoofed DNS answer.
	CertErr bool
}

// Report holds the results of one full test round.
type Report struct{ Results []ProbeResult }

func (r Report) Services() []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range r.Results {
		if !seen[p.Service] {
			seen[p.Service] = true
			out = append(out, p.Service)
		}
	}
	return out
}

func (r Report) ServiceOK(svc string) bool {
	found := false
	for _, p := range r.Results {
		if p.Service == svc {
			found = true
			if !p.OK {
				return false
			}
		}
	}
	return found
}

func (r Report) Passed() int {
	n := 0
	for _, p := range r.Results {
		if p.OK {
			n++
		}
	}
	return n
}

func (r Report) AllOK() bool { return len(r.Results) > 0 && r.Passed() == len(r.Results) }

// Latency sums the time of successful probes; lower is better on ties.
func (r Report) Latency() time.Duration {
	var d time.Duration
	for _, p := range r.Results {
		if p.OK {
			d += p.Took
		}
	}
	return d
}

// Better reports whether r beats o: more passed probes, then lower latency.
func (r Report) Better(o Report) bool {
	if r.Passed() != o.Passed() {
		return r.Passed() > o.Passed()
	}
	return r.Latency() < o.Latency()
}

// Tester resolves every host once (so DNS noise does not affect strategy
// comparison) and then probes the pinned addresses.
type Tester struct {
	Targets []Target
	Timeout time.Duration
	addrs   map[string][]string
	Notes   []string
}

func NewTester(ctx context.Context, targets []Target) *Tester {
	t := &Tester{Targets: targets, Timeout: 6 * time.Second, addrs: map[string][]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for _, tg := range targets {
		if seen[tg.Host] {
			continue
		}
		seen[tg.Host] = true
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			ips, note := resolveHost(ctx, host)
			mu.Lock()
			t.addrs[host] = ips
			if note != "" {
				t.Notes = append(t.Notes, note)
			}
			mu.Unlock()
		}(tg.Host)
	}
	wg.Wait()
	return t
}

// DNSTrouble reports whether any host needed the DNS-over-HTTPS fallback.
func (t *Tester) DNSTrouble() bool { return len(t.Notes) > 0 }

func resolveHost(ctx context.Context, host string) ([]string, string) {
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sys, err := net.DefaultResolver.LookupIP(lctx, "ip4", host)
	var good []string
	for _, ip := range sys {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok && usableAddr(a) {
			good = append(good, a.String())
		}
	}
	if len(good) > 0 {
		return good, ""
	}
	doh, derr := dohLookup(ctx, host)
	if derr != nil || len(doh) == 0 {
		return nil, fmt.Sprintf("%s: адрес не найден ни через DNS провайдера (%v), ни через DNS-over-HTTPS", host, errText(err))
	}
	return doh, fmt.Sprintf("%s: DNS провайдера не отдаёт настоящий адрес, взят через DNS-over-HTTPS", host)
}

func usableAddr(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsPrivate() &&
		!a.IsLinkLocalUnicast() && !a.IsMulticast()
}

var dohClient = &http.Client{Timeout: 5 * time.Second}

func dohLookup(ctx context.Context, host string) ([]string, error) {
	endpoints := []string{
		"https://1.1.1.1/dns-query?type=A&name=",
		"https://8.8.8.8/resolve?type=A&name=",
	}
	var lastErr error
	for _, ep := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep+url.QueryEscape(host), nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := dohClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		var body struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			}
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		var ips []string
		for _, a := range body.Answer {
			if ip, err := netip.ParseAddr(a.Data); a.Type == 1 && err == nil && usableAddr(ip) {
				ips = append(ips, ip.String())
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("пустой ответ")
	}
	return nil, lastErr
}

// RecheckSpoofed re-resolves hosts that answered with a foreign certificate
// through DNS-over-HTTPS: an ISP's DNS may return the public IP of its block
// page, which passes the address filter. Returns true if any address changed.
func (t *Tester) RecheckSpoofed(ctx context.Context, r Report) bool {
	changed := false
	for _, p := range r.Results {
		if !p.CertErr {
			continue
		}
		ips, err := dohLookup(ctx, p.Host)
		if err != nil || len(ips) == 0 || overlaps(ips, t.addrs[p.Host]) {
			continue
		}
		t.addrs[p.Host] = ips
		t.Notes = append(t.Notes, p.Host+": DNS провайдера отдаёт адрес страницы-заглушки, взят адрес через DNS-over-HTTPS")
		changed = true
	}
	return changed
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Run probes all targets in parallel.
func (t *Tester) Run(ctx context.Context) Report {
	res := make([]ProbeResult, len(t.Targets))
	var wg sync.WaitGroup
	for i, tg := range t.Targets {
		wg.Add(1)
		go func(i int, tg Target) {
			defer wg.Done()
			res[i] = t.probe(ctx, tg)
		}(i, tg)
	}
	wg.Wait()
	return Report{Results: res}
}

func (t *Tester) probe(ctx context.Context, tg Target) ProbeResult {
	r := ProbeResult{Target: tg}
	ips := t.addrs[tg.Host]
	if len(ips) == 0 {
		r.Err = "нет IP-адреса (DNS)"
		return r
	}
	start := time.Now()
	pctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	var err error
	for i, ip := range ips {
		if i >= 2 || pctx.Err() != nil {
			break
		}
		r.Status, r.Bytes, err = fetch(pctx, tg, ip)
		if err == nil {
			break
		}
	}
	r.Took = time.Since(start)
	if err != nil {
		r.Err = err.Error()
		r.CertErr = isCertErr(err)
		return r
	}
	r.OK = true
	return r
}

type stageError struct {
	stage string
	bytes int64
	err   error
}

func (e *stageError) Error() string { return describeFailure(e.stage, e.bytes, e.err) }

func isCertErr(err error) bool {
	var certErr *x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &invalid)
}

func describeFailure(stage string, n int64, err error) string {
	switch {
	case isCertErr(err):
		return "подмена сертификата (заглушка провайдера)"
	case isTimeout(err):
		switch stage {
		case "tcp":
			return "нет соединения (таймаут)"
		case "tls":
			return "TLS завис (блок по SNI)"
		case "data":
			return fmt.Sprintf("обрыв после %d КБ (замедление)", n>>10)
		default:
			return "таймаут ответа"
		}
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "reset") ||
		strings.Contains(err.Error(), "forcibly closed"):
		return "соединение сброшено (RST)"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		if stage == "data" {
			return fmt.Sprintf("соединение оборвано после %d КБ", n>>10)
		}
		return "соединение закрыто (" + stage + ")"
	default:
		return stage + ": " + shortErr(err)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i > 6 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}

func errText(err error) string {
	if err == nil {
		return "ложный адрес"
	}
	return shortErr(err)
}

// fetch opens TCP+TLS with a Chrome ClientHello (so the DPI and winws see a
// browser-like handshake), sends a GET and reads up to MinBytes of the body.
func fetch(ctx context.Context, tg Target, ip string) (int, int64, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return 0, 0, &stageError{stage: "tcp", err: err}
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: tg.Host}, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(ctx); err != nil {
		return 0, 0, &stageError{stage: "tls", err: err}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+tg.Host+tg.Path, nil)
	req.Header.Set("User-Agent", chromeUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")

	var resp *http.Response
	if uc.ConnectionState().NegotiatedProtocol == "h2" {
		tr := &http2.Transport{DisableCompression: true}
		cc, err := tr.NewClientConn(uc)
		if err != nil {
			return 0, 0, &stageError{stage: "http", err: err}
		}
		defer cc.Close()
		resp, err = cc.RoundTrip(req)
		if err != nil {
			return 0, 0, &stageError{stage: "http", err: err}
		}
	} else {
		req.Header.Set("Connection", "close")
		if err := req.Write(uc); err != nil {
			return 0, 0, &stageError{stage: "http", err: err}
		}
		resp, err = http.ReadResponse(bufio.NewReader(uc), req)
		if err != nil {
			return 0, 0, &stageError{stage: "http", err: err}
		}
	}
	defer resp.Body.Close()
	limit := tg.MinBytes
	if limit <= 0 {
		limit = 4 << 10
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	if err != nil {
		return resp.StatusCode, n, &stageError{stage: "data", bytes: n, err: err}
	}
	return resp.StatusCode, n, nil
}
