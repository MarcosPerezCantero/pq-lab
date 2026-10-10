#!/usr/bin/env bash
# Builds a pinned, statically linked OpenSSL 3.5.x CLI and installs it as the
# Tauri sidecar src-tauri/binaries/openssl-<target-triple>[.exe].
#
#   ./scripts/build-openssl.sh                         # host target
#   TARGET_TRIPLE=x86_64-pc-windows-gnu ./scripts/...  # Windows, cross-built with MinGW-w64
#   TARGET_TRIPLE=universal-apple-darwin ./scripts/... # macOS arm64 + x86_64 (lipo)
set -euo pipefail

OPENSSL_VERSION="3.5.9"
OPENSSL_SHA256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRIPLE="${TARGET_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"
OUT="$ROOT/src-tauri/binaries"
WORK="${OPENSSL_BUILD_DIR:-$ROOT/target-openssl}"
TARBALL="openssl-$OPENSSL_VERSION.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$TARBALL"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

dest_for() {
  if [[ "$1" == *windows* ]]; then echo "$OUT/openssl-$1.exe"; else echo "$OUT/openssl-$1"; fi
}

is_current() {
  [[ -f "$1" ]] && grep -q "OpenSSL $OPENSSL_VERSION " <(strings "$1" 2>/dev/null || true)
}

fetch() {
  mkdir -p "$WORK" "$OUT"
  cd "$WORK"
  [[ -f "$TARBALL" ]] || curl -fsSL -o "$TARBALL" "$URL"
  local actual
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
  else
    actual="$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)"
  fi
  if [[ "$actual" != "$OPENSSL_SHA256" ]]; then
    echo "checksum mismatch for $TARBALL" >&2
    exit 1
  fi
}

# Builds one target triple into its sidecar path.
build_one() {
  local triple="$1" dest conf strip_cmd="strip" extra=()
  dest="$(dest_for "$triple")"
  if is_current "$dest"; then
    echo "sidecar already built: $dest"
    return
  fi
  case "$triple" in
    x86_64-unknown-linux-gnu)  conf="linux-x86_64" ;;
    aarch64-unknown-linux-gnu) conf="linux-aarch64" ;;
    x86_64-apple-darwin)       conf="darwin64-x86_64-cc" ;;
    aarch64-apple-darwin)      conf="darwin64-arm64-cc" ;;
    x86_64-pc-windows-gnu)
      conf="mingw64"
      extra=(--cross-compile-prefix=x86_64-w64-mingw32- -static)
      strip_cmd="x86_64-w64-mingw32-strip"
      ;;
    x86_64-pc-windows-msvc)    conf="VC-WIN64A" ;;
    *) echo "unsupported target triple: $triple" >&2; exit 1 ;;
  esac

  fetch
  local src="$WORK/build-$triple"
  rm -rf "$src"
  mkdir -p "$src"
  tar xzf "$WORK/$TARBALL" -C "$src" --strip-components=1
  cd "$src"

  if [[ "$conf" == VC-* ]]; then
    # Native MSVC build: needs a Windows perl (Strawberry), not the msys one.
    local perl="perl"
    [[ -x /c/Strawberry/perl/bin/perl.exe ]] && perl="/c/Strawberry/perl/bin/perl.exe"
    "$perl" Configure "$conf" no-shared no-tests no-docs no-module no-asm
    nmake build_programs
    cp apps/openssl.exe "$dest"
  else
    ./Configure "$conf" no-shared no-tests no-docs no-module ${extra[@]+"${extra[@]}"}
    make -j"$JOBS" build_programs
    if [[ "$triple" == *windows* ]]; then
      cp apps/openssl.exe "$dest"
    else
      cp apps/openssl "$dest"
    fi
    "$strip_cmd" "$dest" || true
  fi
  chmod 0755 "$dest"
  echo "sidecar installed: $dest"
}

if [[ "$TRIPLE" == "universal-apple-darwin" ]]; then
  build_one aarch64-apple-darwin
  build_one x86_64-apple-darwin
  lipo -create -output "$(dest_for universal-apple-darwin)" \
    "$(dest_for aarch64-apple-darwin)" "$(dest_for x86_64-apple-darwin)"
  lipo -info "$(dest_for universal-apple-darwin)"
else
  build_one "$TRIPLE"
fi
