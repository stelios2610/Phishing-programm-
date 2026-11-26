#!/usr/bin/env bash
# Build a Windows desktop folder: NetWatch.exe plus the Python it needs.
# Run the result on a Windows PC. It does not run inside a remote VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$ROOT/packaging/windows/stage"
RELEASE="$ROOT/release"
PYVER="${PYVER:-3.12.10}"
URL="https://www.python.org/ftp/python/${PYVER}/python-${PYVER}-embed-amd64.zip"

rm -rf "$STAGE"
mkdir -p "$STAGE" "$RELEASE"
curl -fsSL "$URL" -o "$STAGE/python-embed.zip"
python3 - <<PY
import zipfile
zipfile.ZipFile("$STAGE/python-embed.zip").extractall("$STAGE")
PY
rm -f "$STAGE/python-embed.zip"
pth="$(ls "$STAGE"/python*._pth | head -1)"
printf 'python312.zip\n.\nimport site\n' > "$pth"
mkdir -p "$STAGE/netwatch"
cp "$ROOT"/netwatch/*.py "$STAGE/netwatch/"
rm -rf "$STAGE/netwatch/__pycache__" "$STAGE/netwatch/static"
cat > "$STAGE/README.txt" <<'EOF'
NetWatch is a desktop application for this Windows PC.

1. Unzip this folder anywhere on the PC whose network you want to watch.
2. Double-click NetWatch.exe.
3. Right-click NetWatch.exe and choose "Run as administrator" if you want
   to see who sent a ping, or to pin the router MAC.

It reads this computer's ARP table and ICMP counters. A copy running on
another machine cannot see this PC's local network.
EOF
x86_64-w64-mingw32-gcc -municode -O2 -s -mwindows \
  -o "$STAGE/NetWatch.exe" \
  "$ROOT/packaging/windows/app.c" \
  -luser32 -lgdi32
(
  cd "$STAGE"
  rm -f "$RELEASE/NetWatch-windows.zip"
  zip -qr "$RELEASE/NetWatch-windows.zip" .
)
ls -lh "$STAGE/NetWatch.exe" "$RELEASE/NetWatch-windows.zip"
file "$STAGE/NetWatch.exe"
