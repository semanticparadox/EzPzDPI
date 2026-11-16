# Third-party components

EzPzDPI bundles unmodified binaries and data files from these projects. Each
component keeps its own license; their license texts ship in the `licenses/`
folder that EzPzDPI unpacks into `C:\ProgramData\EzPzDPI\licenses`.

| Component | What is used | License | Source |
|---|---|---|---|
| zapret by bol-van | `winws.exe` | MIT | https://github.com/bol-van/zapret |
| zapret-discord-youtube by Flowseal | strategy `.bat` files, host lists, fake packet `.bin` files (release 1.10.4) | MIT | https://github.com/Flowseal/zapret-discord-youtube |
| WinDivert by basil00 | `WinDivert.dll`, `WinDivert64.sys` | LGPL-3.0 or GPL-2.0 | https://github.com/basil00/WinDivert |
| Cygwin | `cygwin1.dll` (runtime required by `winws.exe`) | LGPL-3.0 | https://cygwin.com/git/newlib-cygwin.git |
| GoodbyeDPI by ValdikSS | `goodbyedpi.exe` and its WinDivert copy (release 0.2.3rc3-2) | Apache-2.0 | https://github.com/ValdikSS/GoodbyeDPI |

Go libraries compiled into `EzPzDPI.exe`:

| Library | License |
|---|---|
| github.com/refraction-networking/utls | BSD-3-Clause |
| golang.org/x/net, golang.org/x/sys, golang.org/x/crypto | BSD-3-Clause |
| github.com/klauspost/compress, github.com/andybalholm/brotli | BSD-3-Clause / MIT |
| github.com/jchv/go-webview2 | MIT |
| github.com/jchv/go-winloader | ISC |
| Microsoft WebView2 SDK `WebView2Loader.dll` (embedded by go-webview2) | BSD-3-Clause |

Fonts embedded in the window:

| Font | License | Source |
|---|---|---|
| Onest | SIL Open Font License 1.1 | https://github.com/googlefonts/onest |
| Unbounded | SIL Open Font License 1.1 | https://github.com/googlefonts/unbounded |

The window needs the Microsoft Edge WebView2 Runtime, which ships with
Windows 11 and current Windows 10. If it is missing, EzPzDPI offers to
download Microsoft's official installer and checks its signature first.

The LGPL components are distributed as separate, unmodified files and can be
replaced by the user: put another build of `WinDivert.dll` / `WinDivert64.sys`
or `cygwin1.dll` into `C:\ProgramData\EzPzDPI\zapret\bin`. Source code for each
is available at the links above.
