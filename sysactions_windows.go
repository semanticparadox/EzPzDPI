//go:build windows

package main

// System actions (module B): secure DNS, Defender exclusion, Start menu and
// "Apps" entries, WebView2 runtime. Every change is something the user
// pressed: it is backed up in a.cfg (or a file under <dataDir>\backup),
// journaled, verified after applying and rolled back when the check fails.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ---------------------------------------------------------------------------
// R04: DLL planting

// hardenDLLSearch limits DLL loading to System32. The exe is often started
// from Downloads, where anyone could drop a fake version.dll or
// WebView2Loader.dll next to it; go-webview2 then falls back to its
// embedded loader. Call it first thing in main.
func hardenDLLSearch() {
	_ = windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
}

// ---------------------------------------------------------------------------
// PowerShell

// psTimeout caps every script: cmdlets that talk to Defender or the DNS
// client can hang when those services are broken.
const psTimeout = 90 * time.Second

// runPS runs a script in a hidden, profile-free PowerShell and returns its
// trimmed stdout. The script travels as -EncodedCommand (UTF-16LE base64),
// so the command line never re-parses it; values inside must still be
// quoted with psQuote. Errors stop the script and come back as err.
func runPS(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, psTimeout)
	defer cancel()
	full := "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n" +
		"[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" +
		"try {\n" + script + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n"
	cmd := exec.CommandContext(ctx, powershellPath(),
		"-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encodePS(full))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// powershellPath is absolute so a planted powershell.exe in the current
// folder or PATH never runs elevated.
func powershellPath() string {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		sys = `C:\Windows\System32`
	}
	return filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
}

func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// psQuote makes a PowerShell single-quoted literal. PowerShell also treats
// the typographic quotes ‘ ’ ‚ ‛ as quote marks, so they are doubled too.
func psQuote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '\u2018', '\u2019', '\u201A', '\u201B':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// psList makes @('a','b') from values that are already validated.
func psList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = psQuote(v)
	}
	return "@(" + strings.Join(q, ",") + ")"
}

func psBool(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// ---------------------------------------------------------------------------
// N05: Windows encrypted DNS (DNS over HTTPS)

// dohProvider is a public resolver Windows 11 can use with DoH.
type dohProvider struct {
	Name     string
	Host     string // TLS name of the template
	Template string
	V4, V6   []string
}

var dohProviders = []dohProvider{
	{"Cloudflare", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query",
		[]string{"1.1.1.1", "1.0.0.1"}, []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}},
	{"Google", "dns.google", "https://dns.google/dns-query",
		[]string{"8.8.8.8", "8.8.4.4"}, []string{"2001:4860:4860::8888", "2001:4860:4860::8844"}},
	{"Quad9", "dns.quad9.net", "https://dns.quad9.net/dns-query",
		[]string{"9.9.9.9", "149.112.112.112"}, []string{"2620:fe::fe", "2620:fe::9"}},
}

func (p dohProvider) addrs() []string { return append(append([]string{}, p.V4...), p.V6...) }

func providerByName(name string) (dohProvider, bool) {
	for _, p := range dohProviders {
		if p.Name == name {
			return p, true
		}
	}
	return dohProvider{}, false
}

const errSecureDNSWin10 = "Защищённый DNS в настройках Windows есть только в Windows 11. " +
	"Включите его в браузере: Chrome или Edge — Настройки → Конфиденциальность и безопасность → " +
	"Безопасность → «Использовать безопасный DNS»; Firefox — Настройки → Приватность и защита → «DNS через HTTPS»."

// secureDNSSupported: per-adapter DoH with Set-DnsClientDohServerAddress
// exists from Windows 11 (build 22000).
func secureDNSSupported() bool {
	return windows.RtlGetVersion().BuildNumber >= 22000
}

// enableSecureDNS switches the internet adapter to a DoH provider that is
// reachable right now. Windows uses DoH whenever the provider answers over
// HTTPS and falls back to plain DNS to the same servers only when it does
// not (captive portals, networks that block DoH): the adapter setting
// applies to every network a laptop joins later, and DNS must never
// disappear. The old settings are backed up first and restored if the
// system resolver does not work afterwards.
func enableSecureDNS(ctx context.Context, a *App) (provider string, err error) {
	if !secureDNSSupported() {
		return "", errors.New(errSecureDNSWin10)
	}
	if b := a.cfg.DNSBackup; b != nil {
		if secureDNSActive(a) {
			return b.Provider, nil
		}
		// Our earlier change is half gone (adapter switched or edited by
		// hand): restore it first so the backup keeps the user's own settings.
		if err := revertSecureDNS(a); err != nil {
			return "", err
		}
	}
	p, err := pickDoHProvider(ctx)
	if err != nil {
		return "", err
	}
	ad, err := internetAdapter(p.V4[0])
	if err != nil {
		return "", err
	}
	if err := backupDNS(ctx, a, ad, p); err != nil {
		return "", err
	}
	if err := applyDoH(ctx, a, ad, p); err != nil {
		return "", rollbackDNS(a, fmt.Errorf("не удалось включить защищённый DNS: %w", err))
	}
	if err := verifySecureDNS(ctx, ad.GUID, p); err != nil {
		return "", rollbackDNS(a, err)
	}
	a.logf("secure dns: %s on %s (if %d)", p.Name, ad.Name, ad.Index)
	return p.Name, nil
}

// rollbackDNS reverts a failed enable and explains both outcomes.
func rollbackDNS(a *App, cause error) error {
	a.logf("secure dns failed: %v", cause)
	if err := revertSecureDNS(a); err != nil {
		return fmt.Errorf("%v. Вернуть прежние настройки DNS тоже не удалось: %v", cause, err)
	}
	return fmt.Errorf("%v. Прежние настройки DNS возвращены", cause)
}

// pickDoHProvider asks every provider at once and takes the first one in
// preference order that answered: some ISPs block one of them.
func pickDoHProvider(ctx context.Context) (dohProvider, error) {
	errs := make([]error, len(dohProviders))
	var wg sync.WaitGroup
	for i, p := range dohProviders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = probeDoH(ctx, p)
		}()
	}
	wg.Wait()
	for i, p := range dohProviders {
		if errs[i] == nil {
			return p, nil
		}
	}
	return dohProvider{}, fmt.Errorf("ни один сервер защищённого DNS (Cloudflare, Google, Quad9) сейчас не отвечает: %v", errs[0])
}

// probeDoH resolves youtube.com the way Windows will: an RFC 8484 request
// to the provider's IP with the template's TLS name, no system DNS, no proxy.
func probeDoH(ctx context.Context, p dohProvider) error {
	q, err := dnsQueryA("youtube.com.")
	if err != nil {
		return err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(p.V4[0], "443"))
		},
		TLSClientConfig:   &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.Template+"?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", p.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if !dnsAnswerHasA(body) {
		return fmt.Errorf("%s: пустой ответ", p.Name)
	}
	return nil
}

// dnsQueryA builds a wire-format A query; ID 0 as RFC 8484 recommends.
func dnsQueryA(name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// dnsAnswerHasA reports whether a DNS response carries a public A record.
func dnsAnswerHasA(msg []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess || p.SkipAllQuestions() != nil {
		return false
	}
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			return false
		}
		if rh.Type != dnsmessage.TypeA {
			if p.SkipAnswer() != nil {
				return false
			}
			continue
		}
		r, err := p.AResource()
		if err == nil && usableAddr(netip.AddrFrom4(r.A)) {
			return true
		}
	}
}

// dnsAdapter is a network adapter as GetAdaptersAddresses sees it.
type dnsAdapter struct {
	Index  uint32 // IPv4 interface index
	Index6 uint32 // IPv6 interface index, 0 when IPv6 is off
	GUID   string // "{...}", the stable identity across reboots
	Name   string // friendly name, for logs only: never put in a script
	IfType uint32
	DNS    []string // DNS servers in use now (static or DHCP)
}

// ifTypePropVirtual is IF_TYPE_PROP_VIRTUAL (WireGuard, Wintun tunnels).
const ifTypePropVirtual = 53

var reAdapterGUID = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

func dnsAdapters() ([]dnsAdapter, error) {
	size := uint32(16 << 10)
	for range 4 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []dnsAdapter
		for aa := first; aa != nil; aa = aa.Next {
			out = append(out, toDNSAdapter(aa))
		}
		return out, nil
	}
	return nil, errors.New("список сетевых адаптеров слишком велик")
}

func toDNSAdapter(aa *windows.IpAdapterAddresses) dnsAdapter {
	ad := dnsAdapter{
		Index:  aa.IfIndex,
		Index6: aa.Ipv6IfIndex,
		GUID:   windows.BytePtrToString(aa.AdapterName),
		Name:   windows.UTF16PtrToString(aa.FriendlyName),
		IfType: aa.IfType,
	}
	for s := aa.FirstDnsServerAddress; s != nil; s = s.Next {
		if ip, ok := netip.AddrFromSlice(s.Address.IP()); ok {
			ad.DNS = append(ad.DNS, ip.Unmap().WithZone("").String())
		}
	}
	return ad
}

func dnsAdapterByGUID(guid string) (dnsAdapter, bool) {
	list, err := dnsAdapters()
	if err != nil {
		return dnsAdapter{}, false
	}
	for _, ad := range list {
		if strings.EqualFold(ad.GUID, guid) {
			return ad, true
		}
	}
	return dnsAdapter{}, false
}

// internetAdapter finds the adapter Windows would use to reach dst, i.e.
// the one that carries the default route. A VPN tunnel is refused: its DNS
// belongs to the VPN app and changes back on every reconnect.
func internetAdapter(dst string) (dnsAdapter, error) {
	ip, err := netip.ParseAddr(dst)
	if err != nil || !ip.Is4() {
		return dnsAdapter{}, fmt.Errorf("неверный адрес %q", dst)
	}
	var idx uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: ip.As4()}, &idx); err != nil {
		return dnsAdapter{}, fmt.Errorf("не найден сетевой адаптер с выходом в интернет: %w", err)
	}
	list, err := dnsAdapters()
	if err != nil {
		return dnsAdapter{}, err
	}
	for _, ad := range list {
		if ad.Index != idx {
			continue
		}
		if !reAdapterGUID.MatchString(ad.GUID) {
			return dnsAdapter{}, fmt.Errorf("у адаптера %s нет идентификатора", ad.Name)
		}
		switch ad.IfType {
		case windows.IF_TYPE_PPP, windows.IF_TYPE_TUNNEL, ifTypePropVirtual:
			return dnsAdapter{}, errors.New("сейчас интернет идёт через VPN или туннель. Выключите VPN и включите защищённый DNS снова")
		}
		return ad, nil
	}
	return dnsAdapter{}, fmt.Errorf("сетевой адаптер %d не найден", idx)
}

const (
	tcpipIfKey  = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	tcpip6IfKey = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
)

// staticDNS reads the adapter's manually set DNS servers. Empty lists mean
// the servers come from DHCP (the router).
func staticDNS(guid string) (v4, v6 []string) {
	return readNameServer(tcpipIfKey + guid), readNameServer(tcpip6IfKey + guid)
}

func readNameServer(path string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	s, _, err := k.GetStringValue("NameServer")
	if err != nil {
		return nil
	}
	return parseServerList(s)
}

// parseServerList splits a NameServer value ("1.1.1.1,8.8.8.8" or space
// separated) and keeps valid addresses only.
func parseServerList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if ip, err := netip.ParseAddr(f); err == nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// splitFamilies separates a saved server list into IPv4 and IPv6.
func splitFamilies(list []string) (v4, v6 []string) {
	for _, s := range list {
		ip, err := netip.ParseAddr(s)
		switch {
		case err != nil:
		case ip.Is4():
			v4 = append(v4, ip.String())
		default:
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dohEntry is one row of Get-DnsClientDohServerAddress. Windows 11 ships
// entries for the big providers, so we save and restore them, not delete.
type dohEntry struct {
	Server   string `json:"server"`
	Template string `json:"template"`
	Fallback bool   `json:"fallback"`
	Auto     bool   `json:"auto"`
}

func (a *App) dohBackupPath() string { return filepath.Join(a.dataDir, "backup", "doh-servers.json") }

// backupDNS records the adapter's current DNS and the provider's DoH rows
// before anything changes, then saves the config.
func backupDNS(ctx context.Context, a *App, ad dnsAdapter, p dohProvider) error {
	v4, v6 := staticDNS(ad.GUID)
	rows, err := readDoHEntries(ctx, p.addrs())
	if err != nil {
		return fmt.Errorf("не удалось прочитать настройки DNS Windows: %w", err)
	}
	data, _ := json.Marshal(rows)
	if err := os.MkdirAll(filepath.Dir(a.dohBackupPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(a.dohBackupPath(), data, 0o644); err != nil {
		return err
	}
	a.cfg.DNSBackup = &DNSBackup{
		IfIndex: ad.Index, IfGUID: ad.GUID, IfName: ad.Name,
		WasDHCP: len(v4) == 0 && len(v6) == 0, Servers: append(v4, v6...),
		Provider: p.Name, At: time.Now(),
	}
	a.saveConfig()
	a.journal("dns backup "+ad.GUID, describeDNS(v4, v6), string(data))
	return nil
}

func describeDNS(v4, v6 []string) string {
	if len(v4) == 0 && len(v6) == 0 {
		return "DHCP"
	}
	return strings.Join(append(append([]string{}, v4...), v6...), ",")
}

// readDoHEntries returns the existing DoH rows for the given servers.
func readDoHEntries(ctx context.Context, servers []string) ([]dohEntry, error) {
	out, err := runPS(ctx, `$want = `+psList(servers)+`
$rows = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object { $want -contains [string]$_.ServerAddress } | ForEach-Object {
  [pscustomobject]@{ server = [string]$_.ServerAddress; template = [string]$_.DohTemplate; fallback = [bool]$_.AllowFallbackToUdp; auto = [bool]$_.AutoUpgrade } })
ConvertTo-Json -InputObject $rows -Compress`)
	if err != nil {
		return nil, err
	}
	var rows []dohEntry
	if out == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("ответ Get-DnsClientDohServerAddress: %w", err)
	}
	return rows, nil
}

// applyDoH registers the provider's DoH template for each of its addresses
// (encrypted first, plain DNS to the same servers only when DoH is
// unreachable) and points the adapter at them.
// Only validated IPs, the interface index and fixed templates reach the
// script; the adapter name never does.
func applyDoH(ctx context.Context, a *App, ad dnsAdapter, p dohProvider) error {
	servers := p.V4
	if ad.Index6 != 0 {
		servers = p.addrs()
	}
	script := fmt.Sprintf(`foreach ($s in %s) {
  if (Get-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue) {
    Set-DnsClientDohServerAddress -ServerAddress $s -DohTemplate %s -AllowFallbackToUdp $true -AutoUpgrade $true | Out-Null
  } else {
    Add-DnsClientDohServerAddress -ServerAddress $s -DohTemplate %[2]s -AllowFallbackToUdp $true -AutoUpgrade $true | Out-Null
  }
}
Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s
Clear-DnsClientCache`, psList(p.addrs()), psQuote(p.Template), ad.Index, psList(servers))
	before := describeDNS(staticDNS(ad.GUID))
	if _, err := runPS(ctx, script); err != nil {
		return err
	}
	a.journal("dns servers "+ad.GUID, before, strings.Join(servers, ",")+" DoH "+p.Template+" with UDP fallback")
	return nil
}

// verifySecureDNS checks that the adapter really uses the provider and that
// the system resolver (what browsers and Discord use) answers through it.
// DoH needs a moment to connect, so it retries briefly.
func verifySecureDNS(ctx context.Context, guid string, p dohProvider) error {
	var lastErr error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1500 * time.Millisecond):
			}
		}
		if ad, ok := dnsAdapterByGUID(guid); !ok || !containsStr(ad.DNS, p.V4[0]) {
			lastErr = errors.New("Windows не применила новые адреса DNS")
			continue
		}
		if lastErr = systemResolves(ctx, "youtube.com"); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("после включения защищённого DNS сайты перестали находиться (%v)", lastErr)
}

func systemResolves(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if usableAddr(ip.Unmap()) {
			return nil
		}
	}
	return errors.New("нет публичного адреса")
}

// systemDNSWorks reports whether the system resolver (what browsers use)
// can find two well-known names, one Russian and one international,
// within about 5 seconds. Either one resolving to a public address is
// enough: it tells "DNS is broken" apart from "one site is blocked".
func systemDNSWorks(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hosts := []string{"ya.ru", "www.google.com"}
	ok := make(chan bool, len(hosts))
	for _, h := range hosts {
		go func() { ok <- systemResolves(ctx, h) == nil }()
	}
	for range hosts {
		if <-ok {
			return true
		}
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// secureDNSActive: our backup exists and the adapter still uses the
// provider we set. Cheap (no PowerShell), safe to call on every refresh.
func secureDNSActive(a *App) bool {
	b := a.cfg.DNSBackup
	if b == nil {
		return false
	}
	p, ok := providerByName(b.Provider)
	if !ok {
		return false
	}
	ad, ok := dnsAdapterByGUID(b.IfGUID)
	return ok && containsStr(ad.DNS, p.V4[0])
}

// revertSecureDNS puts back exactly what backupDNS saved: the adapter's
// static servers (or DHCP) and the provider's DoH rows. If the adapter is
// unplugged, its registry values are restored so Windows uses them when it
// comes back. The backup is kept when anything fails, so it can be retried.
func revertSecureDNS(a *App) error {
	b := a.cfg.DNSBackup
	if b == nil {
		return nil
	}
	if !reAdapterGUID.MatchString(b.IfGUID) {
		return fmt.Errorf("резервная копия DNS повреждена (адаптер %q)", b.IfGUID)
	}
	v4, v6 := splitFamilies(b.Servers)
	ctx := context.Background()
	script := dohRestoreScript(a, b)
	if ad, ok := dnsAdapterByGUID(b.IfGUID); ok {
		script = dnsServersRestoreScript(ad.Index, v4, v6) + "\n" + script
	} else if err := writeStaticDNS(b.IfGUID, v4, v6); err != nil {
		return fmt.Errorf("не удалось вернуть DNS адаптера %s: %w", b.IfName, err)
	}
	if _, err := runPS(ctx, script+"\nClear-DnsClientCache"); err != nil {
		return fmt.Errorf("не удалось вернуть прежние настройки DNS: %w", err)
	}
	cur4, cur6 := staticDNS(b.IfGUID)
	if !sameList(cur4, v4) || !sameList(cur6, v6) {
		return fmt.Errorf("DNS адаптера %s не вернулся к прежнему (%s вместо %s)",
			b.IfName, describeDNS(cur4, cur6), describeDNS(v4, v6))
	}
	a.journal("dns restore "+b.IfGUID, b.Provider, describeDNS(v4, v6))
	a.logf("secure dns reverted on %s", b.IfName)
	a.cfg.DNSBackup = nil
	a.saveConfig()
	_ = os.Remove(a.dohBackupPath())
	return nil
}

// dnsServersRestoreScript resets the adapter to DHCP, then sets the saved
// static servers of each family, so a family that was DHCP stays DHCP.
func dnsServersRestoreScript(ifIndex uint32, v4, v6 []string) string {
	s := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses", ifIndex)
	if static := append(append([]string{}, v4...), v6...); len(static) > 0 {
		s += fmt.Sprintf("\nSet-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s", ifIndex, psList(static))
	}
	return s
}

// writeStaticDNS is the offline path: the same registry values that
// Set-DnsClientServerAddress writes ("" means DHCP).
func writeStaticDNS(guid string, v4, v6 []string) error {
	if err := writeNameServer(tcpipIfKey+guid, v4); err != nil {
		return err
	}
	if err := writeNameServer(tcpip6IfKey+guid, v6); err != nil && len(v6) > 0 {
		return err
	}
	return nil
}

func writeNameServer(path string, list []string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("NameServer", strings.Join(list, ","))
}

// dohRestoreScript restores the saved DoH rows and removes the rows we
// added. Without the backup file it only turns auto-upgrade off, which is
// how Windows ships its built-in rows.
func dohRestoreScript(a *App, b *DNSBackup) string {
	var servers []string
	if p, ok := providerByName(b.Provider); ok {
		servers = p.addrs()
	} else {
		for _, p := range dohProviders {
			servers = append(servers, p.addrs()...)
		}
	}
	data, err := os.ReadFile(a.dohBackupPath())
	var rows []dohEntry
	if err != nil || json.Unmarshal(data, &rows) != nil {
		return fmt.Sprintf(`foreach ($s in %s) {
  if (Get-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue) { Set-DnsClientDohServerAddress -ServerAddress $s -AutoUpgrade $false | Out-Null }
}`, psList(servers))
	}
	var sb strings.Builder
	saved := map[string]bool{}
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.Server)
		if err != nil || !strings.HasPrefix(r.Template, "https://") {
			continue
		}
		saved[ip.String()] = true
		fmt.Fprintf(&sb, "Set-DnsClientDohServerAddress -ServerAddress %s -DohTemplate %s -AllowFallbackToUdp %s -AutoUpgrade %s | Out-Null\n",
			psQuote(ip.String()), psQuote(r.Template), psBool(r.Fallback), psBool(r.Auto))
	}
	var added []string
	for _, s := range servers {
		if !saved[s] {
			added = append(added, s)
		}
	}
	if len(added) > 0 {
		fmt.Fprintf(&sb, "foreach ($s in %s) { Remove-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue | Out-Null }\n", psList(added))
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// X02: Microsoft Defender exclusion for the data folder only

const defenderManualSteps = "Безопасность Windows → Защита от вирусов и угроз → Управление настройками → Исключения"

// defenderScript adds or removes the exclusion and reports what is true
// afterwards, read back with Get-MpPreference: Tamper Protection, another
// antivirus or a company policy can silently ignore the change.
func defenderScript(path string, add bool) string {
	verb := "Remove-MpPreference"
	if add {
		verb = "Add-MpPreference"
	}
	return fmt.Sprintf(`$p = %s
try { $pref = Get-MpPreference } catch { 'nodefender'; exit 0 }
$has = { @((Get-MpPreference).ExclusionPath) -contains $p }
if ((& $has) -eq %s) { 'unchanged'; exit 0 }
%s -ExclusionPath $p -Force
Start-Sleep -Milliseconds 500
if ((& $has) -eq %[2]s) { 'done' } else { 'blocked' }`, psQuote(path), psBool(add), verb)
}

// addDefenderExclusion excludes only <dataDir>. If the folder was already
// excluded by the user we leave the flag off, so uninstall never removes
// an exclusion we did not add.
func addDefenderExclusion(a *App) error {
	out, err := runPS(context.Background(), defenderScript(a.dataDir, true))
	if err != nil {
		return fmt.Errorf("не удалось добавить исключение в Защитник Windows: %w", err)
	}
	switch out {
	case "done":
		a.cfg.DefenderExcluded = true
		a.saveConfig()
		a.journal("defender exclusion", "", a.dataDir)
		return nil
	case "unchanged":
		a.logf("defender: %s is already excluded", a.dataDir)
		return nil
	case "nodefender":
		return fmt.Errorf("Защитник Windows сейчас выключен — вероятно, его заменил другой антивирус. Добавьте папку %s в исключения вашего антивируса", a.dataDir)
	}
	return fmt.Errorf("Защитник Windows не принял исключение: вероятно, его запрещает защита от изменений или правила организации. Добавьте папку %s вручную: %s", a.dataDir, defenderManualSteps)
}

// removeDefenderExclusion undoes only the exclusion we added.
func removeDefenderExclusion(a *App) error {
	if !a.cfg.DefenderExcluded {
		return nil
	}
	out, err := runPS(context.Background(), defenderScript(a.dataDir, false))
	if err != nil {
		return fmt.Errorf("не удалось убрать исключение из Защитника Windows: %w", err)
	}
	switch out {
	case "done", "unchanged":
		a.cfg.DefenderExcluded = false
		a.saveConfig()
		a.journal("defender exclusion", a.dataDir, "")
		return nil
	case "nodefender":
		return fmt.Errorf("Защитник Windows выключен, исключение для %s убрать нельзя. Уберите его позже: %s", a.dataDir, defenderManualSteps)
	}
	return fmt.Errorf("Защитник Windows не дал убрать исключение для %s. Уберите его вручную: %s", a.dataDir, defenderManualSteps)
}

// ---------------------------------------------------------------------------
// P09: Start menu shortcut and "Apps" uninstall entry

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + appName

// startMenuShortcut is in the all-users Start menu, found through the
// known-folder API so a localized or redirected path still works.
func startMenuShortcut() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, appName+".lnk"), nil
}

// installEntries makes the installed copy findable in Пуск and in
// Приложения. The caller has already copied the exe (a.installedExe()).
// A partial result is removed again.
func installEntries(a *App) error {
	exe := a.installedExe()
	if !fileExists(exe) {
		return fmt.Errorf("нет файла %s", exe)
	}
	lnk, err := startMenuShortcut()
	if err != nil {
		return fmt.Errorf("не найдена папка меню «Пуск»: %w", err)
	}
	if err := writeUninstallEntry(a, exe); err != nil {
		return failInstall(a, fmt.Errorf("не удалось добавить EzPzDPI в список приложений: %w", err))
	}
	if err := createShortcut(lnk, exe); err != nil {
		return failInstall(a, fmt.Errorf("не удалось создать ярлык в меню «Пуск»: %w", err))
	}
	if !fileExists(lnk) || !uninstallEntryOK(exe) {
		return failInstall(a, errors.New("ярлык или запись в списке приложений не появились"))
	}
	if !a.cfg.Installed {
		a.cfg.Installed = true
		a.saveConfig()
	}
	return nil
}

// failInstall removes half-made entries of a first install. A refresh of
// an existing install keeps the old entries: they still work.
func failInstall(a *App, err error) error {
	if !a.cfg.Installed {
		_ = removeEntries(a)
	}
	return err
}

// writeUninstallEntry creates or refreshes HKLM\...\Uninstall\EzPzDPI.
func writeUninstallEntry(a *App, exe string) error {
	prev := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE); err == nil {
		prev, _, _ = k.GetStringValue("DisplayVersion")
		k.Close()
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	strs := [][2]string{
		{"DisplayName", appName},
		{"DisplayVersion", version},
		{"Publisher", "semanticparadox"},
		{"DisplayIcon", exe + ",0"},
		{"UninstallString", syscall.EscapeArg(exe) + " -uninstall"},
		{"InstallLocation", a.dataDir},
		{"URLInfoAbout", repoURL},
		{"InstallDate", time.Now().Format("20060102")},
	}
	for _, kv := range strs {
		if err := k.SetStringValue(kv[0], kv[1]); err != nil {
			return err
		}
	}
	dwords := map[string]uint32{"NoModify": 1, "NoRepair": 1}
	if st, err := os.Stat(exe); err == nil {
		dwords["EstimatedSize"] = uint32(st.Size() >> 10) // KB, shown in Apps
	}
	for name, v := range dwords {
		if err := k.SetDWordValue(name, v); err != nil {
			return err
		}
	}
	a.journal("uninstall entry", prev, version)
	return nil
}

// uninstallEntryOK reads the entry back.
func uninstallEntryOK(exe string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	name, _, err1 := k.GetStringValue("DisplayName")
	icon, _, err2 := k.GetStringValue("DisplayIcon")
	return err1 == nil && err2 == nil && name == appName && strings.EqualFold(icon, exe+",0")
}

// createShortcut writes the .lnk through the WScript.Shell COM object;
// both paths are passed as quoted literals.
func createShortcut(lnk, exe string) error {
	script := fmt.Sprintf(`$s = (New-Object -ComObject WScript.Shell).CreateShortcut(%s)
$s.TargetPath = %s
$s.WorkingDirectory = %s
$s.IconLocation = %s
$s.Description = %s
$s.Save()`, psQuote(lnk), psQuote(exe), psQuote(filepath.Dir(exe)), psQuote(exe+",0"),
		psQuote("Проверка и восстановление доступа к YouTube и Discord"))
	if _, err := runPS(context.Background(), script); err != nil {
		return err
	}
	return nil
}

// removeEntries deletes our shortcut and uninstall entry; both are ours by
// exact path and name. Missing ones are fine (offline, damaged installs).
func removeEntries(a *App) error {
	var errs []error
	if lnk, err := startMenuShortcut(); err == nil {
		if err := os.Remove(lnk); err == nil {
			a.journal("start menu shortcut", lnk, "")
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); err == nil {
		a.journal("uninstall entry", appName, "")
	} else if !errors.Is(err, registry.ErrNotExist) {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("не удалось убрать EzPzDPI из меню «Пуск» и списка приложений: %w", errors.Join(errs...))
	}
	a.cfg.Installed = false
	a.saveConfig()
	return nil
}

// ---------------------------------------------------------------------------
// X07: WebView2 runtime

const webView2ClientKey = `Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

// webView2Installed checks the runtime's "pv" version in every place the
// Evergreen installer writes it (per-machine 32-bit view, 64-bit view,
// per-user). "0.0.0.0" is what an uninstall leaves behind.
func webView2Installed() bool {
	places := []struct {
		root  registry.Key
		path  string
		flags uint32
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\` + webView2ClientKey, registry.WOW64_32KEY},
		{registry.LOCAL_MACHINE, `SOFTWARE\` + webView2ClientKey, registry.WOW64_64KEY},
		{registry.CURRENT_USER, `Software\` + webView2ClientKey, 0},
	}
	for _, p := range places {
		k, err := registry.OpenKey(p.root, p.path, registry.QUERY_VALUE|p.flags)
		if err != nil {
			continue
		}
		pv, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}
	return false
}

const (
	webView2BootstrapperURL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
	webView2MaxSize         = 32 << 20
)

// installWebView2 downloads Microsoft's bootstrapper, checks that it is
// validly signed by Microsoft, and runs it silently. It works in the
// admin-only data folder, not %TEMP%: this process is elevated and a
// non-elevated program could otherwise swap the file or plant DLLs next to
// it. The file also stays locked against writes from the check until it
// has run.
func installWebView2(ctx context.Context) error {
	base := defaultDataDir()
	if err := secureDataDir(base); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(base, "webview2-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "MicrosoftEdgeWebview2Setup.exe")
	if err := downloadFile(ctx, webView2BootstrapperURL, path, webView2MaxSize); err != nil {
		return fmt.Errorf("не удалось скачать WebView2: %w", err)
	}
	lock, err := lockAgainstWrites(path)
	if err != nil {
		return fmt.Errorf("файл установщика WebView2 занят другой программой: %w", err)
	}
	defer windows.CloseHandle(lock)
	if err := verifyMicrosoftSignature(ctx, path); err != nil {
		return err
	}
	if err := runInstaller(ctx, path, "/silent", "/install"); err != nil {
		return fmt.Errorf("установщик WebView2 завершился с ошибкой: %w", err)
	}
	if !webView2Installed() {
		return errors.New("установщик WebView2 отработал, но компонент не появился. Перезагрузите компьютер и откройте EzPzDPI снова")
	}
	return nil
}

// downloadFile saves url to path over HTTPS only, with a size cap.
func downloadFile(ctx context.Context, url, path string, max int64) error {
	client := &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) > 10 {
				return errors.New("небезопасное перенаправление")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = errors.New("файл слишком большой")
	}
	return err
}

// lockAgainstWrites opens path for reading while denying write and delete
// access to everyone else; it fails if someone already has it open for
// writing. Execution and signature checks only need read sharing.
func lockAgainstWrites(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	for range 10 { // an antivirus scan of the fresh file can hold it briefly
		h, err = windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
			windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	return h, err
}

// verifyMicrosoftSignature requires a valid Authenticode signature whose
// signer organisation is Microsoft Corporation.
func verifyMicrosoftSignature(ctx context.Context, path string) error {
	out, err := runPS(ctx, fmt.Sprintf(`$sig = Get-AuthenticodeSignature -LiteralPath %s
[pscustomobject]@{ status = [string]$sig.Status; subject = [string]$sig.SignerCertificate.Subject } | ConvertTo-Json -Compress`, psQuote(path)))
	if err != nil {
		return fmt.Errorf("не удалось проверить подпись установщика WebView2: %w", err)
	}
	var sig struct{ Status, Subject string }
	if err := json.Unmarshal([]byte(out), &sig); err != nil {
		return fmt.Errorf("не удалось проверить подпись установщика WebView2: %w", err)
	}
	if sig.Status != "Valid" || !strings.Contains(sig.Subject, "O=Microsoft Corporation") {
		return fmt.Errorf("установщик WebView2 не подписан Microsoft (%s, %s) — он не запущен", sig.Status, sig.Subject)
	}
	return nil
}

// runInstaller runs a verified installer hidden and waits, at most 10 min.
func runInstaller(ctx context.Context, path string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = filepath.Dir(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Run()
}
