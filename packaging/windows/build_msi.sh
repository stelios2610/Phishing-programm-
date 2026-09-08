#!/usr/bin/env bash
# Cross-build a 64-bit Windows MSI from Linux (MinGW + embeddable CPython + wixl).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$ROOT/packaging/windows/stage"
RUNTIME="$STAGE/runtime"
RELEASE="$ROOT/release"
PYVER="${PYVER:-3.12.10}"
PYDIR="python-${PYVER}-embed-amd64"
ZIP="$STAGE/${PYDIR}.zip"
URL="https://www.python.org/ftp/python/${PYVER}/${PYDIR}.zip"

rm -rf "$STAGE"
mkdir -p "$RUNTIME" "$RELEASE" "$STAGE"
cd "$ROOT"

echo "Using packaged PhishGuard logo (ICO/BMP)"

echo "Downloading embeddable CPython ${PYVER}..."
curl -fsSL "$URL" -o "$ZIP"
python3 - <<PY
import zipfile
from pathlib import Path
with zipfile.ZipFile("$ZIP") as zf:
    zf.extractall("$RUNTIME")
print("extracted runtime")
PY

PTH=$(ls "$RUNTIME"/python*._pth | head -1)
cat > "$PTH" <<'EOF'
python312.zip
.
import site
EOF

mkdir -p "$RUNTIME/phishguard"
cp "$ROOT/phishguard/__init__.py" "$RUNTIME/phishguard/"
cp "$ROOT/phishguard/engine.py" "$RUNTIME/phishguard/"
cp "$ROOT/phishguard/brands.py" "$RUNTIME/phishguard/"
cp "$ROOT/phishguard/parser.py" "$RUNTIME/phishguard/"
cp "$ROOT/phishguard/confusables.py" "$RUNTIME/phishguard/"
cp "$ROOT/phishguard/lures.py" "$RUNTIME/phishguard/"
cp "$ROOT/packaging/windows/analyze_bridge.py" "$RUNTIME/"
cp "$ROOT/packaging/windows/logo.bmp" "$STAGE/logo.bmp"
cp "$ROOT/phishguard/static/logo-64.png" "$STAGE/logo-64.png"

x86_64-w64-mingw32-windres -I "$ROOT/packaging/windows" \
  "$ROOT/packaging/windows/app.rc" -O coff -o "$STAGE/app.res"
x86_64-w64-mingw32-gcc -municode -O2 -mwindows \
  -o "$STAGE/PhishGuard.exe" \
  "$ROOT/packaging/windows/app.c" "$STAGE/app.res" \
  -luser32 -lgdi32 -lcomctl32 -lshell32

python3 "$ROOT/packaging/windows/gen_wxs.py" \
  --root "$ROOT" --stage "$STAGE" --runtime "$RUNTIME"

MSI="$RELEASE/PhishGuard-Setup.msi"
wixl -v -a x64 -o "$MSI" "$STAGE/product.wxs"
ls -lh "$MSI" "$STAGE/PhishGuard.exe"
file "$STAGE/PhishGuard.exe" "$MSI"
echo "MSI ready: $MSI"
