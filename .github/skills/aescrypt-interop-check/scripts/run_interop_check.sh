#!/usr/bin/env bash
set -euo pipefail

if ! command -v aescrypt >/dev/null 2>&1; then
  echo "ERROR: aescrypt is not installed. Install the original AES Crypt CLI first."
  exit 1
fi

REPO_ROOT="${1:-$PWD}"
cd "$REPO_ROOT"

OURS="dotnet TronAesCrypt.Main/bin/Debug/net10.0/linux-x64/AesCrypt.dll"
PASS='InteropPass!2026'
WORKDIR="$(mktemp -d)"

printf 'WORKDIR=%s\n' "$WORKDIR"
printf 'AESCRYPT=%s\n' "$(command -v aescrypt)"

# Build our tool

dotnet build TronAesCrypt.Main/TronAesCrypt.Main.csproj -c Debug --nologo >/dev/null

printf 'Interoperability test file\n' > "$WORKDIR/source.bin"
head -c 8192 /dev/urandom >> "$WORKDIR/source.bin"
printf '\nEnd\n' >> "$WORKDIR/source.bin"

# Direction 1: our encrypt -> original decrypt
$OURS -e -p "$PASS" -o "$WORKDIR/ours-encrypted.aes" "$WORKDIR/source.bin"
aescrypt -d -p "$PASS" -f -o "$WORKDIR/decrypted-by-aescrypt.bin" "$WORKDIR/ours-encrypted.aes"

SRC_HASH="$(sha256sum "$WORKDIR/source.bin" | awk '{print $1}')"
DEC1_HASH="$(sha256sum "$WORKDIR/decrypted-by-aescrypt.bin" | awk '{print $1}')"

printf 'SRC_HASH=%s\n' "$SRC_HASH"
printf 'DEC1_HASH=%s\n' "$DEC1_HASH"

if [[ "$SRC_HASH" != "$DEC1_HASH" ]]; then
  echo "FAIL our->aescrypt mismatch"
  exit 2
fi

echo "PASS our->aescrypt"

# Direction 2: original encrypt -> our decrypt
aescrypt -e -p "$PASS" -f -o "$WORKDIR/aescrypt-encrypted.aes" "$WORKDIR/source.bin"
$OURS -d -p "$PASS" -o "$WORKDIR/decrypted-by-ours.bin" "$WORKDIR/aescrypt-encrypted.aes"

DEC2_HASH="$(sha256sum "$WORKDIR/decrypted-by-ours.bin" | awk '{print $1}')"
printf 'DEC2_HASH=%s\n' "$DEC2_HASH"

if [[ "$SRC_HASH" != "$DEC2_HASH" ]]; then
  echo "FAIL aescrypt->our mismatch"
  exit 3
fi

echo "PASS aescrypt->our"
echo "ALL_INTEROP_TESTS_PASSED"
