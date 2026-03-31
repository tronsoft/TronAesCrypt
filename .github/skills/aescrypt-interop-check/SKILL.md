---
name: aescrypt-interop-check
description: Validate interoperability between TronAesCrypt and the original AES Crypt CLI. Use this skill whenever the user asks to verify compatibility with the original aescrypt tool, cross-decrypt files between tools, or confirm encryption/decryption parity with hashes. Always begin by checking whether `aescrypt` is installed and stop with clear install guidance if it is missing.
---

# AES Crypt Interop Check

Use this skill to prove that TronAesCrypt and the original `aescrypt` command-line tool can read each other's encrypted files.

## When to use

Use this skill when the user asks for:
- Compatibility checks with original AES Crypt
- Round-trip encryption/decryption across both tools
- Hash-based validation that decrypted bytes match the original

## Preconditions

1. Confirm the original CLI is installed:
   - Run: `command -v aescrypt`
   - If missing, stop and report: "`aescrypt` is not installed. Install it first and rerun this skill."
2. Confirm repository root is available and buildable.
3. Build TronAesCrypt CLI:
   - `dotnet build TronAesCrypt.Main/TronAesCrypt.Main.csproj -c Debug --nologo`

## Required verification flow

Run both directions and verify with SHA-256:

1. TronAesCrypt encrypt -> aescrypt decrypt
2. aescrypt encrypt -> TronAesCrypt decrypt

For each direction:
- Use the same password.
- Compare source and decrypted file hashes using `sha256sum`.
- Treat mismatched hash as failure.

## Canonical command sequence

From repository root, run this script:

`bash /home/tron/.agents/skills/aescrypt-interop-check/scripts/run_interop_check.sh`

## Expected output contract

Return a concise report containing:
- Whether `aescrypt` was found
- Build result
- Direction 1 result (pass/fail + hashes)
- Direction 2 result (pass/fail + hashes)
- Final verdict (`ALL_INTEROP_TESTS_PASSED` or failure reason)
- Temp working directory path used

## Failure handling

- If `aescrypt` is missing: stop immediately and report install prerequisite.
- If build fails: stop and report build error summary.
- If any hash differs: report mismatch with both hashes and direction.
