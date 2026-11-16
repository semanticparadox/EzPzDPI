# EzPzDPI 0.2: module contracts

EzPzDPI is a portable Windows 10/11 x64 app (Go, cross-compiled from Linux,
no cgo) that diagnoses blocked services for people in Russia and enables a
DPI bypass (zapret winws / GoodbyeDPI) as a Windows service. The process
always runs elevated (manifest `requireAdministrator`). UI is a WebView2
window (`ui/index.html`) driven by JSON state from Go.

Sources of truth:
- `docs/research/2026-11-16-services.json`: verified per-service research.
- `docs/research/2026-11-16-scenarios.json`: scenario spec (`spec.groups[]`,
  `spec.signatures[]`, `spec.voice_test`). Scenario ids (E01, N05, V01, …)
  below refer to it.

Build and check (Go is at `/home/linuxbrew/.linuxbrew/bin/go`):
- `go vet ./... && go test ./...` (Linux, cross-platform files)
- `GOOS=windows GOARCH=amd64 go vet ./...` (Windows files)
- The package needs `assets/payload.zip`; it exists in the repo checkout.

Rules for every module:
- Russian UI text: plain, sentence case, no jargon without explanation,
  neutral wording ("восстановить доступ"), no VPN brand names. Voice results
  are an estimate ("оценка"). Community-reported causes use "вероятно".
- Never change the system silently. Every system change goes through an
  action the user pressed, records a backup in `a.cfg` and calls
  `a.journal(what, before, after)`. Never delete a foreign folder; disable
  foreign services (start=disabled), never delete them unless the action is
  explicitly "remove leftovers" for services whose exe no longer exists.
  Kill processes by PID after verifying the image path, never by name only.
- Locale-independent detection: Windows APIs, registry, XML/CSV with fixed
  column order. Never parse localized console text.
- Keep functions small and documented; no new third-party modules unless
  unavoidable (golang.org/x/sys is available).

Existing shared code you can use (do not change signatures):
- `env.go`: `Finding`, `Action`, `ProcRef`, `Env` (+ `ForeignActive`,
  `Foreign`, `Find`, `Has`).
- `app_windows.go`: `App` (fields `dataDir`, `cfg Config`), `a.logf`,
  `a.journal`, `a.saveConfig`, `a.ownsPath(path)`, `a.installedExe()`,
  `a.logDir()`, `Config` with backup fields `ForeignDisabled`,
  `ForeignTasks`, `ForeignShortcuts`, `DNSBackup`, `ProxyBackup`,
  `DefenderExcluded`, `Installed`.
- `sys_windows.go`: `listProcs(names...) []procInfo` (PID, Name, Path),
  `procPath`, `killPID`, `queryService(name) svcInfo`, `setServiceStart`,
  `stopService`, `stopAndDeleteService`, `serviceState`, `runHidden`,
  `runHiddenOutput`, `createLogonTask`, `deleteTask`, `taskExists`,
  `messageBox`.
- `tester.go`: `dohLookup(ctx, host)`, `NewTester`, `stunProbe` (in udp.go).
- `catalog.go` / `catalog_data.go`: `catalog []Service`.

## Module A: environment detection (`detect_windows.go`, owner: agent A)

Rewrite `detect_windows.go`. Provide exactly:

```go
func detectEnv(a *App) Env
func disableForeign(a *App, f Finding) error    // replace flow (E05)
func pauseForeign(a *App, fs []Finding) (resume func()) // temporary (F03)
func restoreForeign(a *App) error               // undo every disableForeign (E05/U02)
func cleanHosts(a *App) (backup string, err error)      // N06
func removeLeftovers(a *App, f Finding) error   // E09/U04: only dead services/tasks
func proxyOff(a *App) error                     // N03 dead local proxy
func restoreProxy(a *App) error
func startBFE(a *App) error                     // F01
```

Findings to emit (ID / Kind / actions with these exact action IDs):
- Foreign bypass tools, one finding per tool (`dpi:<tool>`, Kind `dpi`):
  E01 inventory (processes incl. managers ZapretGUI.Service.exe, "ByeDPI
  Manager.exe", proxifyre.exe; services by name AND by ImagePath pattern over
  all services; WinDivert/WinDivert14/Monkey driver keys; scheduled tasks by
  name and action (schtasks /Query /FO CSV /V /NH, columns by position);
  Run/RunOnce keys and Startup folders), E02 Flowseal details (strategy from
  registry value `zapret-discord-youtube`, version from service.bat
  `LOCAL_VERSION`, game filter flag file, ipset mode), E03 started by hand
  from a console window (parent cmd.exe) or by shortcut, E07 crashes (System
  log events 7031/7034 for its service in the last 7 days via
  `wevtutil qe System /q:... /f:xml`), E10 GoodbyeDPI TCP-only note, E12
  ByeDPI proxy note, E16 OneDrive/"!" in path. Actions when running:
  `check-without` ("Проверить без него"), `disable-foreign` ("Заменить на
  EzPzDPI", with Confirm text). When installed but stopped:
  `disable-foreign` ("Убрать из автозапуска").
- `engines` (Kind `engines`, Level error): E06 more than one packet engine
  running at once (count distinct engine PIDs incl. ours).
- `leftovers` (Kind `dpi`, Level info): E09 services/tasks whose exe is gone,
  or a stale WinDivert driver service with no owner. Action `remove-leftovers`.
- `own:stopped`: our service `EzPzDPI` exists but is stopped. Action `restart-own`.
- `vpn` (Kind `vpn`, Active): N02 default route through a tunnel adapter
  (GetBestInterfaceEx + adapter description/type, and split default routes
  0.0.0.0/1 + 128.0.0.0/1) or WARP daemon. Action `recheck`.
- `proxy` (Kind `proxy`): N03 WinINET proxy/PAC on. If it points to a local
  port that is not listening: Level warn, text says the browser cannot open
  sites, action `proxy-off`. WinHTTP proxy as info.
- `hosts` (Kind `hosts`): N06 overrides for watched names (catalog domains +
  Flowseal hosts payload names). Action `clean-hosts`.
- `av` (Kind `av`, info): AdGuard (voice note), Kaspersky/ESET/Dr.Web/
  Avast/AVG/Bitdefender, Check Point (TracSrvWrapper/EPWD), Killer/SmartByte/
  Intel connectivity services (E18). If Defender (WinDefend) is the active AV
  and our engine file is missing, action `defender-exclude`.
- `anticheat` (Kind `game`, info): P12 FACEIT/Vanguard/EAC/BattlEye services.
- `discord-proxy` (Kind `discord`, warn): E13 Drover (`%LocalAppData%\Discord\
  app-*\version.dll` + `drover.ini`).
- `bfe` (Kind `system`, error): Base Filtering Engine not running. Action `bfe-on`.
- `hvci` (Kind `system`, info): Memory Integrity on (context for errors 577/1275).
- `arm64` (Kind `platform`, error).

`disableForeign` must: stop managers first, record service start types in
`a.cfg.ForeignDisabled` (only if not already recorded), stop + set disabled,
disable tasks (`schtasks /Change /TN x /DISABLE`, record in
`a.cfg.ForeignTasks`), move autostart shortcuts into
`<dataDir>\backup\autostart\` (record in `a.cfg.ForeignShortcuts`), kill
processes by PID after verifying path, stop the WinDivert driver service if no
foreign engine still runs, journal every step, save config.
`restoreForeign` reverses all of it if the target exe still exists, and
clears the records. `pauseForeign` stops (not disables) and returns a
resume func that starts the same services again.

Unit-test pure helpers (parsers of schtasks CSV, wevtutil XML, service.bat
version, hosts lines) in `detect_test.go` with build tag-free code placed in a
cross-platform file `detect_parse.go`.

## Module B: system actions (`sysactions_windows.go`, `engine_errors.go`, owner: agent B)

Provide exactly:

```go
func hardenDLLSearch()                               // R04: SetDefaultDllDirectories(SYSTEM32)
func secureDNSSupported() bool                       // Windows 11 (build >= 22000)
func enableSecureDNS(ctx context.Context, a *App) (provider string, err error) // N05
func revertSecureDNS(a *App) error
func secureDNSActive(a *App) bool                    // our DoH config is applied
func addDefenderExclusion(a *App) error              // X02, Add-MpPreference -ExclusionPath dataDir
func removeDefenderExclusion(a *App) error
func installEntries(a *App) error                    // P09: Start menu shortcut + Apps uninstall entry
func removeEntries(a *App) error
func webView2Installed() bool                        // X07
func installWebView2(ctx context.Context) error      // download Microsoft bootstrapper, verify signature, /silent /install
func explainEngineLog(line string) string            // X01, in engine_errors.go (cross-platform)
```

`enableSecureDNS`: test DoH providers (Cloudflare 1.1.1.1/1.0.0.1, Google
8.8.8.8/8.8.4.4, Quad9 9.9.9.9/149.112.112.112) by resolving a name through
each provider's DoH endpoint with `dohLookup`-style requests; pick the first
that answers; find the adapter of the default route; back up its DNS
(static list or DHCP via registry `Tcpip\Parameters\Interfaces\{GUID}\NameServer`)
into `a.cfg.DNSBackup`; apply servers (IPv4 and the provider's IPv6) and DoH
templates with no UDP fallback (`Set-DnsClientServerAddress`,
`Set-DnsClientDohServerAddress`/`Add-DnsClientDohServerAddress`, run hidden via
powershell -NoProfile -NonInteractive); flush cache; verify the system
resolver now returns an address for youtube.com; on failure revert. Journal
every step. `revertSecureDNS` restores exactly the backup. Windows 10: return
an error whose text tells the user how to turn on secure DNS in the browser.

`installEntries`: copy is already done by the caller (`a.installedExe()`);
create `%ProgramData%\Microsoft\Windows\Start Menu\Programs\EzPzDPI.lnk`
(PowerShell WScript.Shell COM, hidden) and `HKLM\SOFTWARE\Microsoft\Windows\
CurrentVersion\Uninstall\EzPzDPI` (DisplayName, DisplayVersion=version,
Publisher, DisplayIcon, UninstallString `"<exe>" -uninstall`, NoModify,
NoRepair, InstallLocation, URLInfoAbout=repoURL).

`installWebView2`: download https://go.microsoft.com/fwlink/p/?LinkId=2124703
to a temp file, verify the Authenticode signature is valid and signed by
Microsoft (PowerShell Get-AuthenticodeSignature, Status Valid, signer subject
contains "Microsoft Corporation"), run it with `/silent /install`, wait.

`explainEngineLog`: map winws ("windivert: error opening filter: N") and
GoodbyeDPI ("Error opening filter: N") codes per X01 and the research table
(2, 5, 87, 577 incl. "try to disable secure boot", 654, 1060, 1275, 1753,
EAC stale driver text). Return plain Russian advice. Unit tests in
`engine_errors_test.go`.

## Module C: voice / UDP (`udp.go`, `icmp_windows.go`, `icmp_other.go`, owner: agent C)

Implement the V01/V02 estimate from `spec.voice_test` within the app's time
budget. Provide exactly:

```go
type VoiceResult struct {
	Flows, Answered       int           // handshake burst on the voice rule (stun.l.google.com:19302)
	ControlFlows, ControlOK int         // control outside the rule (stun.cloudflare.com:3478)
	Soak                  *SoakResult   // nil when not run
	State                 SvcState      // StWorks, StPartial, StBlocked, StUnknown
	Detail                string        // plain Russian, says it is an estimate
}
type SoakResult struct {
	Duration time.Duration
	Sent, Got int
	MaxGap   time.Duration   // longest silence
	Gaps     int             // silences > 2 s
	Jitter   time.Duration
	Gateway  *GatewayStats   // nil if unavailable
}
type GatewayStats struct { Sent, Got int; MaxRTT, AvgRTT time.Duration }

func voiceBurst(ctx context.Context, flows int) VoiceResult   // ~3-5 s, each flow a fresh socket
func voiceSoak(ctx context.Context, d time.Duration) *SoakResult // 1 STUN/s to 2 servers on kept flows + gateway ping 5 Hz
func classifyVoice(v VoiceResult) (SvcState, string)          // pure, unit-tested
func defaultGateway() (net.IP, bool)                          // icmp_windows.go (GetBestRoute2 / GetIpForwardTable2); other OS: false
func pingGateway(ctx context.Context, gw net.IP, n int, interval time.Duration) *GatewayStats // IcmpSendEcho on Windows
```

Classes: burst 0% answered and control also 0% = "UDP недоступен вообще"
(StBlocked); rule 0% but control > 0 = "звонки блокируются" (StBlocked);
10-90% = "подключается через раз" (StPartial); soak gaps or loss with a
clean gateway = "подключается, потом обрывается" (StPartial); gateway loss or
spikes = "обрывы ещё в вашем Wi-Fi" (StPartial, say so); 100% and clean soak =
StWorks with "оценка" wording. Keep the existing `stunProbe`/`StunResult`
API working. Unit-test `classifyVoice` with table cases.

## Module D: UI (`ui/index.html`, owner: agent D)

Keep the approved visual direction (route board with the striped ISP
barrier, Unbounded + Onest, palette tokens, dark mode). Implement the full
state contract below and keep a demo mode (`#idle`, `#checking`,
`#diagnosed`, `#fixing`, `#fixed`, `#foreign`, `#uninstalled`) used when the
Go bridge is absent (`window.__EZPZ_APP__` is undefined). Verify with
headless Edge screenshots at 980x680 and 760x560, light and dark, and
reduced motion.

Go → JS: `window.ezpzState(state)` with:

```
phase: idle|checking|diagnosed|fixing|fixed|uninstalled
verdict: {title, text, action, second, calm, busy, cancel_label}
progress: {i, n, eta_sec} | null
provenance: string   // "Напрямую через провайдера" / "Через ваш текущий zapret" / "Через VPN" / "С обходом EzPzDPI"
bypass: {on, strategy, autostart}
services: [{id, name, category, state, fixable, detail, label}]
notices: [{id, kind, level, title, text, actions: [{id, label, confirm}]}]
settings: {autostart, heal, games, enabled: [ids]}
catalog: [{id, name, category, default}]
versions: {app, flowseal, goodbyedpi}
strategies: [{key, name}]
confirm_fix: string     // ask with confirm() before ezpzMain when set and the main action is a fix
foreign_disabled: [names]   // show "Вернуть прежний обход" in settings when non-empty
secure_dns: {supported, active, provider}
defender_excluded: bool
report: string          // plain-text diagnosis report for the "Скопировать отчёт" button
uninstalled: bool
```

States: unknown, testing, works, blocked, throttled, fixed, ip_block, geo,
dns, partial, offline (route drawings exist for all; add a grey "could not
verify" look for `unknown` after a check).

JS → Go bindings (call with exactly these arguments, never pass undefined):
`ezpzReady()`, `ezpzMain()`, `ezpzSecond()`, `ezpzCancel()`, `ezpzStop()`,
`ezpzAction(noticeId, actionId)`, `ezpzSettings({autostart, heal, games,
enabled})`, `ezpzUpdate()`, `ezpzUninstall(restoreForeign)`,
`ezpzManual(key)`, `ezpzOpenLog()`, `ezpzOpenURL(url)`,
`ezpzSecureDNS(enable)`, `ezpzRestoreForeign()`, `ezpzDefender(enable)`.

UI pieces: notices strip between verdict and board (level colours, action
buttons, confirm before actions with `confirm`); provenance line above the
board; settings sheet with service checkboxes grouped by category from
`catalog`, secure-DNS toggle with explanation, Defender exclusion, "Вернуть
прежний обход", update, manual strategy, log, uninstall (confirm; if
`foreign_disabled` non-empty ask whether to restore it); "Скопировать отчёт";
an uninstalled end screen; About text: free, never asks for money,
passwords, phone numbers or Gosuslugi login; not a VPN and does not hide
identity; checks connect directly to the tested sites, nothing is sent to
the authors (R05, R06, R10); progress text with an ETA and a cancel label
"Отменить — ничего не сломается".
