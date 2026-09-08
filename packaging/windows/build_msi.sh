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

python3 - <<'PY'
from pathlib import Path
try:
    from PIL import Image, ImageDraw
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "pillow"])
    from PIL import Image, ImageDraw

img = Image.new("RGBA", (256, 256), (7, 9, 15, 255))
d = ImageDraw.Draw(img)
d.rounded_rectangle((24, 24, 232, 232), radius=48, fill=(26, 39, 68, 255))
d.polygon([(128, 48), (208, 88), (208, 150), (128, 208), (48, 150), (48, 88)], fill=(110, 168, 255, 255))
d.polygon([(128, 72), (184, 100), (184, 144), (128, 180), (72, 144), (72, 100)], fill=(7, 9, 15, 255))
img.save("packaging/windows/icon_src.png")
img.save("packaging/windows/phishguard.ico", sizes=[(s, s) for s in (16, 32, 48, 64, 128, 256)])
print("wrote ico")
PY

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
# Windows launcher helper (stdin URL -> report)
cp "$ROOT/packaging/windows/analyze_bridge.py" "$RUNTIME/"
# desktop.py is optional; skip FastAPI/static to keep the MSI small

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
