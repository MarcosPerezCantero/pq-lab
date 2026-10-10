#!/usr/bin/env bash
# Collects the distributable artifacts into dist-release/ after any of:
#   npm run tauri build -- --target universal-apple-darwin
#   npm run tauri build -- --target x86_64-pc-windows-gnu --bundles nsis
#   npm run tauri build -- --target x86_64-unknown-linux-gnu --bundles appimage,deb
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/src-tauri/Cargo.toml" | head -1)"
T="$ROOT/src-tauri/target"
OUT="$ROOT/dist-release"
rm -rf "$OUT"
mkdir -p "$OUT"

# macOS (universal: Apple Silicon + Intel)
MAC="$T/universal-apple-darwin/release/bundle"
if [[ -d "$MAC/macos/PQ Lab.app" ]]; then
  cp "$MAC/dmg/PQ Lab_${VERSION}_universal.dmg" "$OUT/PQ-Lab-${VERSION}-macOS-universal.dmg"
  ditto -c -k --keepParent "$MAC/macos/PQ Lab.app" "$OUT/PQ-Lab-${VERSION}-macOS-universal.zip"
fi

# Windows x64: installer + portable folder
WIN="$T/x86_64-pc-windows-gnu/release"
if [[ -f "$WIN/pqlab.exe" ]]; then
  cp "$WIN/bundle/nsis/PQ Lab_${VERSION}_x64-setup.exe" "$OUT/PQ-Lab-${VERSION}-Windows-x64-setup.exe"
  P="$OUT/PQ Lab"
  mkdir -p "$P/pqlab-data"
  cp "$WIN/pqlab.exe" "$P/PQ Lab.exe"
  cp "$WIN/WebView2Loader.dll" "$P/"
  cp "$ROOT/src-tauri/binaries/openssl-x86_64-pc-windows-gnu.exe" "$P/openssl.exe"
  cat > "$P/LEEME.txt" <<TXT
PQ Lab ${VERSION} - version portable para Windows (x64)

Herramienta de laboratorio. No es una autoridad de certificacion de produccion.

1. Descomprime esta carpeta donde quieras (escritorio, USB...).
2. Doble clic en "PQ Lab.exe".

La base de datos y el registro se guardan en la carpeta "pqlab-data" que esta
junto al ejecutable, asi que puedes llevarte la carpeta entera a otro equipo.
Si borras "pqlab-data", la aplicacion usara %APPDATA%\\dev.pqlab.app.

Requisitos: Windows 10 u 11 de 64 bits (incluyen Microsoft Edge WebView2).
No necesita OpenSSL instalado: lleva su propio openssl.exe 3.5.
TXT
  (cd "$OUT" && zip -qr "PQ-Lab-${VERSION}-Windows-x64-portable.zip" "PQ Lab")
  rm -rf "$P"
fi

# Linux x64
LIN="$T/x86_64-unknown-linux-gnu/release/bundle"
for f in "$LIN"/appimage/*.AppImage; do
  [[ -f "$f" ]] && cp "$f" "$OUT/PQ-Lab-${VERSION}-Linux-x86_64.AppImage"
done
for f in "$LIN"/deb/*.deb; do
  [[ -f "$f" ]] && cp "$f" "$OUT/PQ-Lab-${VERSION}-Linux-amd64.deb"
done

(cd "$OUT" && shasum -a 256 * > SHA256SUMS.txt)
ls -la "$OUT"
