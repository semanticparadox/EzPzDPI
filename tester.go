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
	Service  string `json:"service"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	MinBytes int64  `json:"min_bytes,omitempty"`
	// Optional targets do not decide whether the service works; a failure
	// makes the service "partial".
	Optional bool `json:"optional,omitempty"`
	// TCPOnly checks that a TCP connection to port 443 opens (Host is an IP).
	TCPOnly bool `json:"tcp_only,omitempty"`
	// Accept overrides the Accept header (DoH JSON needs application/dns-json).
	Accept string `json:"accept,omitempty"`
	// Range asks for part of a large file ("bytes=0-65535").
	Range string `json:"range,omitempty"`
	// UA overrides the browser User-Agent. It travels inside TLS, so the DPI
	// never sees it; some speed-test servers refuse browser user agents.
	UA string `json:"ua,omitempty"`
	// Label names the part of the service this target stands for
	// ("видео", "превью"), so a partial failure can be explained.
	Label string `json:"label,omitempty"`
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// Failure stages, from the outermost to the innermost.
const (
	StageDNS  = "dns"
	StageTCP  = "tcp"
	StageTLS  = "tls"
	StageHTTP = "http"
	StageData = "data"
)

// Results of the neutral-SNI probe that follows a TLS failure.
const (
	NeutralAnswers = "answers" // the server talks TLS to other names: the block targets this site's name (DPI)
	NeutralSilent  = "silent"  // nothing answers on that address: blocked by IP or the server is down
)

// ProbeResult is the outcome of fetching one Target.
type ProbeResult struct {
	Target
	OK         bool
	Status     int
	Bytes      int64
	Took       time.Duration
	Stage      string
	Err        string
	CertErr    bool
	DNSSpoofed bool
	// AVIntercept: the certificate came from a local antivirus that
	// inspects HTTPS; the result was measured through it.
	AVIntercept bool
	Issuer      string
	CertExpired bool
	// Slow: the body kept arriving but did not finish in time; that is a
	// slow link, not the 16-20 KB freeze.
	Slow    bool
	Neutral string
	IP      string
	Head    []byte
}

// Report holds the results of one test round.
type Report struct{ Results []ProbeResult }

// Services lists service ids in first-seen order.
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

// ServiceOK: every required target of the service answered (or any one of
// them, for services that need only one, like DNS providers).
func (r Report) ServiceOK(svc string) bool {
	if s := catalogByID()[svc]; s != nil && s.AnyOK {
		for _, p := range r.Results {
			if p.Service == svc && !p.Optional && r.okFor(p) {
				return true
			}
		}
		return false
	}
	found := false
	for _, p := range r.Results {
		if p.Service != svc || p.Optional {
			continue
		}
		found = true
		if !r.okFor(p) {
			return false
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
	// Neutral enables the neutral-SNI probe after TLS failures (diagnosis).
	Neutral bool
	addrs   map[string][]string
	spoofed map[string]bool
	Notes   []string
	mu      sync.Mutex
}

func NewTester(ctx context.Context, targets []Target) *Tester {
	t := &Tester{Targets: targets, Timeout: 6 * time.Second, addrs: map[string][]string{}, spoofed: map[string]bool{}}
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
			ips, spoofed, note := resolveHost(ctx, host)
			t.mu.Lock()
			t.addrs[host] = ips
			if spoofed {
				t.spoofed[host] = true
			}
			if note != "" {
				t.Notes = append(t.Notes, note)
			}
			t.mu.Unlock()
		}(tg.Host)
	}
	wg.Wait()
	return t
}

// Subset returns a tester for some targets that reuses the resolved addresses.
func (t *Tester) Subset(keep func(Target) bool) *Tester {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := &Tester{Timeout: t.Timeout, Neutral: t.Neutral, addrs: t.addrs, spoofed: t.spoofed, Notes: t.Notes}
	for _, tg := range t.Targets {
		if keep(tg) {
			n.Targets = append(n.Targets, tg)
		}
	}
	return n
}

// Merge adds the resolved addresses of another tester (for its targets).
func (t *Tester) Merge(o *Tester) {
	t.mu.Lock()
	defer t.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	addrs := map[string][]string{}
	for k, v := range t.addrs {
		addrs[k] = v
	}
	spoofed := map[string]bool{}
	for k, v := range t.spoofed {
		spoofed[k] = v
	}
	for k, v := range o.addrs {
		if _, ok := addrs[k]; !ok {
			addrs[k] = v
		}
	}
	for k, v := range o.spoofed {
		spoofed[k] = spoofed[k] || v
	}
	t.addrs, t.spoofed = addrs, spoofed
}

// captivePortal reports whether the network intercepts plain HTTP with a
// login page (hotel/cafe Wi-Fi), using Windows' own connectivity probe.
func captivePortal(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "http://www.msftconnecttest.com/connecttest.txt", nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode/100 == 3 || (resp.StatusCode == 200 && strings.TrimSpace(string(body)) != "Microsoft Connect Test")
}

// rawIPReachable reports whether the internet answers at all without DNS:
// a TCP connect to well-known IP addresses. It tells "DNS is broken" apart
// from "no network".
func rawIPReachable(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ok := make(chan bool, 3)
	for _, addr := range []string{"77.88.8.8:443", "1.1.1.1:443", "8.8.8.8:443"} {
		go func(addr string) {
			var d net.Dialer
			c, err := d.DialContext(cctx, "tcp4", addr)
			if err == nil {
				c.Close()
			}
			ok <- err == nil
		}(addr)
	}
	for i := 0; i < 3; i++ {
		if <-ok {
			return true
		}
	}
	return false
}

// DNSTrouble reports whether any host needed the DNS-over-HTTPS fallback.
func (t *Tester) DNSTrouble() bool { return len(t.spoofed) > 0 }

func resolveHost(ctx context.Context, host string) (ips []string, spoofed bool, note string) {
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sys, err := net.DefaultResolver.LookupIP(lctx, "ip4", host)
	for _, ip := range sys {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok && usableAddr(a) {
			ips = append(ips, a.String())
		}
	}
	if len(ips) > 0 {
		return ips, false, ""
	}
	doh, derr := dohLookup(ctx, host)
	if derr != nil || len(doh) == 0 {
		return nil, false, fmt.Sprintf("%s: адрес не найден ни через DNS провайдера (%v), ни через DNS-over-HTTPS", host, errText(err))
	}
	return doh, true, fmt.Sprintf("%s: DNS провайдера не отдаёт настоящий адрес, взят через DNS-over-HTTPS", host)
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
		t.mu.Lock()
		if err != nil || len(ips) == 0 || overlaps(ips, t.addrs[p.Host]) {
			t.mu.Unlock()
			continue
		}
		t.addrs[p.Host] = ips
		t.spoofed[p.Host] = true
		t.Notes = append(t.Notes, p.Host+": DNS провайдера отдаёт адрес страницы-заглушки, взят адрес через DNS-over-HTTPS")
		t.mu.Unlock()
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
	t.mu.Lock()
	ips := t.addrs[tg.Host]
	r.DNSSpoofed = t.spoofed[tg.Host]
	t.mu.Unlock()
	if len(ips) == 0 {
		r.Stage = StageDNS
		r.Err = "нет IP-адреса (DNS)"
		return r
	}
	start := time.Now()
	pctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	var res fetchResult
	for i, ip := range ips {
		if i >= 2 || pctx.Err() != nil {
			break
		}
		res = fetch(pctx, tg, ip, false)
		r.IP = ip
		if res.err == nil {
			break
		}
		if issuer := certIssuer(res.err); issuer != "" && isAVIssuer(issuer) {
			r.Issuer = issuer
			if res2 := fetch(pctx, tg, ip, true); res2.err == nil {
				res = res2
				r.AVIntercept = true
				break
			}
		}
	}
	r.Took = time.Since(start)
	r.Status, r.Bytes, r.Head, r.Slow = res.status, res.bytes, res.head, res.slow
	if res.err != nil {
		r.Stage = res.stage
		r.Err = res.err.Error()
		r.CertErr = isCertErr(res.err)
		r.CertExpired = isCertExpired(res.err)
		if t.Neutral && res.stage == StageTLS && !r.CertErr && r.IP != "" {
			nctx, ncancel := context.WithTimeout(ctx, 4*time.Second)
			if neutralAnswers(nctx, r.IP) {
				r.Neutral = NeutralAnswers
			} else {
				r.Neutral = NeutralSilent
			}
			ncancel()
		}
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
func (e *stageError) Unwrap() error { return e.err }

// certIssuer returns the issuer of the certificate that failed
// verification, or "".
func certIssuer(err error) string {
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) && ua.Cert != nil {
		return ua.Cert.Issuer.String()
	}
	var uap *x509.UnknownAuthorityError
	if errors.As(err, &uap) && uap.Cert != nil {
		return uap.Cert.Issuer.String()
	}
	var he x509.HostnameError
	if errors.As(err, &he) && he.Certificate != nil {
		return he.Certificate.Issuer.String()
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) && ci.Cert != nil {
		return ci.Cert.Issuer.String()
	}
	return ""
}

// avIssuers are fragments of the root certificates antivirus products use
// to inspect HTTPS on the user's PC.
var avIssuers = []string{"kaspersky", "eset", "dr.web", "doctor web", "avast", "avg", "bitdefender", "adguard", "sophos", "norton", "mcafee", "fortinet", "check point", "zscaler"}

func isAVIssuer(issuer string) bool {
	l := strings.ToLower(issuer)
	for _, f := range avIssuers {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

func isCertErr(err error) bool {
	var certErr *x509.UnknownAuthorityError
	var certVal x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &certErr) || errors.As(err, &certVal) || errors.As(err, &hostErr) || errors.As(err, &invalid)
}

// isCertExpired reports a certificate that is outside its validity period,
// which on several unrelated sites at once means the PC clock is wrong.
func isCertExpired(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}

func describeFailure(stage string, n int64, err error) string {
	switch {
	case isCertErr(err):
		return "подмена сертификата (заглушка провайдера)"
	case isTimeout(err):
		switch stage {
		case StageTCP:
			return "нет соединения (таймаут)"
		case StageTLS:
			return "TLS завис (блок по имени сайта)"
		case StageData:
			return fmt.Sprintf("обрыв после %d КБ (замедление)", n>>10)
		default:
			return "таймаут ответа"
		}
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
		return "соединение отклонено"
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "reset") ||
		strings.Contains(err.Error(), "forcibly closed"):
		return "соединение сброшено (RST)"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		if stage == StageData {
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

type fetchResult struct {
	status int
	bytes  int64
	head   []byte
	stage  string
	err    error
	slow   bool
}

// slowLinkBytes: a transfer that got this far before timing out was slow,
// not frozen by the ISP (the freeze hits at about 16-25 KB).
const slowLinkBytes = 40 << 10

// speedTarget is a Russian file used as the speed baseline: when it is slow
// too, the whole connection is slow and a slow foreign site is not counted
// as ISP throttling.
var speedTarget = Target{Service: "_speed", Host: "yastatic.net", Path: "/jquery/3.3.1/jquery.min.js", MinBytes: 80000}

// LinkSlow reports whether the speed baseline in this report was slow or
// missing (then slow probes are not held against a service).
func (r Report) LinkSlow() bool {
	for _, p := range r.Results {
		if p.Service == speedTarget.Service {
			return !p.OK || p.Slow
		}
	}
	return true
}

// okFor: a probe counts as working; a slow transfer counts only when the
// whole connection is slow too.
func (r Report) okFor(p ProbeResult) bool { return p.OK && !(p.Slow && !r.LinkSlow()) }

const headLimit = 8 << 10

// fetch opens TCP+TLS with a Chrome ClientHello (so the DPI and winws see a
// browser-like handshake), sends a GET and reads up to MinBytes of the body.
// throughAV skips certificate verification; it is used only after the
// presented certificate was issued by a local antivirus that intercepts
// HTTPS, to measure reachability through it. No credentials are ever sent.
func fetch(ctx context.Context, tg Target, ip string, throughAV bool) fetchResult {
	fail := func(stage string, n int64, err error) fetchResult {
		return fetchResult{stage: stage, bytes: n, err: &stageError{stage: stage, bytes: n, err: err}}
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return fail(StageTCP, 0, err)
	}
	defer raw.Close()
	if tg.TCPOnly {
		return fetchResult{}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: tg.Host, InsecureSkipVerify: throughAV}, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(ctx); err != nil {
		return fail(StageTLS, 0, err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+tg.Host+tg.Path, nil)
	req.Header.Set("User-Agent", chromeUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	if tg.Accept != "" {
		req.Header.Set("Accept", tg.Accept)
	}
	if tg.Range != "" {
		req.Header.Set("Range", tg.Range)
	}
	if tg.UA != "" {
		req.Header.Set("User-Agent", tg.UA)
	}
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")

	var resp *http.Response
	if uc.ConnectionState().NegotiatedProtocol == "h2" {
		tr := &http2.Transport{DisableCompression: true}
		cc, err := tr.NewClientConn(uc)
		if err != nil {
			return fail(StageHTTP, 0, err)
		}
		defer cc.Close()
		resp, err = cc.RoundTrip(req)
		if err != nil {
			return fail(StageHTTP, 0, err)
		}
	} else {
		req.Header.Set("Connection", "close")
		if err := req.Write(uc); err != nil {
			return fail(StageHTTP, 0, err)
		}
		resp, err = http.ReadResponse(bufio.NewReader(uc), req)
		if err != nil {
			return fail(StageHTTP, 0, err)
		}
	}
	defer resp.Body.Close()
	limit := tg.MinBytes
	if limit <= 0 {
		limit = 4 << 10
	}
	head := make([]byte, min(int64(headLimit), limit))
	// Read the head ourselves: io.ReadFull would report a short but complete
	// body and a body cut off by a dropped connection the same way.
	n0 := 0
	err = nil
	for n0 < len(head) && err == nil {
		var k int
		k, err = resp.Body.Read(head[n0:])
		n0 += k
	}
	head = head[:n0]
	switch {
	case err == io.EOF:
		// The whole (small) body arrived.
		return fetchResult{status: resp.StatusCode, bytes: int64(n0), head: head}
	case err != nil:
		r := fail(StageData, int64(n0), err)
		r.status, r.head = resp.StatusCode, head
		return r
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit-int64(n0)))
	total := int64(n0) + n
	if err != nil {
		// The 16-20 KB freeze stops a transfer early; a slow but steady
		// link delivers well past that before the deadline.
		if isTimeout(err) && total >= slowLinkBytes {
			return fetchResult{status: resp.StatusCode, bytes: total, head: head, slow: true}
		}
		r := fail(StageData, total, err)
		r.status, r.head = resp.StatusCode, head
		return r
	}
	return fetchResult{status: resp.StatusCode, bytes: total, head: head}
}

// neutralSNI is a name no DPI blocks. If the server answers a ClientHello
// for it, TLS itself reaches the address and the failure was name-based.
const neutralSNI = "www.example.com"

func neutralAnswers(ctx context.Context, ip string) bool {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	// Verification is off on purpose: this is a reachability probe that sends
	// no request and reads no data, and the server's certificate will not
	// match the neutral name anyway.
	uc := utls.UClient(raw, &utls.Config{ServerName: neutralSNI, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	err = uc.HandshakeContext(ctx)
	if err == nil {
		return true
	}
	// An alert, any parsed server message or a clean close (EOF) after the
	// TCP connect means the server is reachable; silence and resets (what
	// TSPU injects) mean it is not.
	return !isTimeout(err) && !errors.Is(err, syscall.ECONNRESET) &&
		!strings.Contains(strings.ToLower(err.Error()), "reset") && !strings.Contains(err.Error(), "forcibly closed")
}
