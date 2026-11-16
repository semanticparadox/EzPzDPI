#!/usr/bin/env bash
# Builds dist/EzPzDPI.exe: downloads pinned upstream releases, verifies their
# SHA-256, assembles assets/payload.zip, runs vet/tests and cross-compiles.
set -euo pipefail

VERSION="${VERSION:-0.2.0}"

FLOWSEAL_VER="1.10.4"
FLOWSEAL_URL="https://github.com/Flowseal/zapret-discord-youtube/releases/download/${FLOWSEAL_VER}/zapret-discord-youtube-${FLOWSEAL_VER}.zip"
FLOWSEAL_SHA256="291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34"

GDPI_VER="0.2.3rc3-2"
GDPI_URL="https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.3rc3/goodbyedpi-${GDPI_VER}.zip"
GDPI_SHA256="37f96b32d050dadcc930a639eba68e1ccd57ed5c04a5f77dfca908f01905a4c5"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/.cache/upstream"
STAGE="$ROOT/.cache/stage"
mkdir -p "$CACHE" "$ROOT/assets" "$ROOT/dist"

fetch() { # url sha256 dest
  if [ ! -f "$3" ]; then
    echo "download $1"
    curl -fsSL --retry 3 -o "$3.part" "$1"
    mv "$3.part" "$3"
  fi
  echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $3" >&2; rm -f "$3"; exit 1; }
}

fetch "$FLOWSEAL_URL" "$FLOWSEAL_SHA256" "$CACHE/flowseal.zip"
fetch "$GDPI_URL" "$GDPI_SHA256" "$CACHE/gdpi.zip"

rm -rf "$STAGE" "$CACHE/x"
mkdir -p "$CACHE/x/flowseal" "$CACHE/x/gdpi"
unzip -q "$CACHE/flowseal.zip" -d "$CACHE/x/flowseal"
unzip -q "$CACHE/gdpi.zip" -d "$CACHE/x/gdpi"
FS="$(dirname "$(find "$CACHE/x/flowseal" -path '*/bin/winws.exe' | head -1)")/.."
GD="$(dirname "$(find "$CACHE/x/gdpi" -path '*/x86_64/goodbyedpi.exe' | head -1)")/.."

mkdir -p "$STAGE/zapret/bin" "$STAGE/zapret/lists" "$STAGE/zapret/strategies" "$STAGE/gdpi" "$STAGE/licenses"
cp "$FS"/bin/* "$STAGE/zapret/bin/"
find "$FS/lists" -maxdepth 1 -type f ! -name '*.backup' -exec cp {} "$STAGE/zapret/lists/" \;
cp "$FS"/general*.bat "$STAGE/zapret/strategies/"
cp "$GD"/x86_64/goodbyedpi.exe "$GD"/x86_64/WinDivert.dll "$GD"/x86_64/WinDivert64.sys "$STAGE/gdpi/"
cp "$ROOT"/third_party/LICENSE-*.txt "$STAGE/licenses/"
cp "$GD"/licenses/* "$STAGE/licenses/"
cp "$ROOT/THIRD-PARTY.md" "$STAGE/licenses/THIRD-PARTY.md"
printf '{"flowseal":"%s","goodbyedpi":"%s","source":"embedded"}\n' "$FLOWSEAL_VER" "$GDPI_VER" > "$STAGE/payload.json"

python3 - "$STAGE" "$ROOT/assets/payload.zip" <<'PY'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for base, _, files in sorted(os.walk(stage)):
        for f in sorted(files):
            p = os.path.join(base, f)
            z.write(p, os.path.relpath(p, stage).replace(os.sep, "/"))
PY
echo "payload: $(du -h "$ROOT/assets/payload.zip" | cut -f1)"

cd "$ROOT"
# Windows resources: icon, manifest (requireAdministrator, per-monitor DPI v2)
# and version info, compiled into rsrc_windows_amd64.syso.
VER4="$(echo "$VERSION" | awk -F. '{printf "%d.%d.%d.0", $1, $2, $3}')"
sed -e "s/@VER4@/$VER4/g" -e "s/@VER@/$VERSION/g" winres/winres.json.tmpl > winres/winres.json
(cd winres && go run github.com/tc-hib/go-winres@v0.3.3 make --in winres.json --out ../rsrc --arch amd64)
gofmt -l . | grep -v '^.cache/' && { echo "gofmt needed" >&2; exit 1; } || true
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o dist/EzPzDPI.exe .
(cd dist && sha256sum EzPzDPI.exe | tee EzPzDPI.exe.sha256)
ls -la dist/EzPzDPI.exe
