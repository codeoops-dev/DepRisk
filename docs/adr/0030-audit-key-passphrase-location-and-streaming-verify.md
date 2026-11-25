# ADR 0030: A passphrase for the audit key, a key location for `init`, `doctor --format json`, streaming `audit verify`

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The audit log is signed with an ECDSA P-256 key that `deprisk init` writes to `.deprisk/audit.key` as an unencrypted PKCS#8 PEM, with owner-only permissions where the OS has them (ADR 0005). Anyone who can read that file can write entries that verify. Three smaller gaps were listed with it: the key can only live inside `.deprisk/`, `doctor` has no machine-readable form, and `audit verify` reads the whole log into memory (with a 512 MiB cap).

## Decision

**A passphrase for the key (optional; a key without one keeps working).** `init --encrypt` writes the private key as an encrypted PKCS#8 PEM (`BEGIN ENCRYPTED PRIVATE KEY`; PBES2 with PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-CBC), which is what .NET writes and reads with no dependency. The passphrase is **never an argument**: it would show in the process list, the shell history and the audit log. It comes from `DEPRISK_KEY_PASSPHRASE` (the passphrase itself) or `DEPRISK_KEY_PASSPHRASE_FILE` (a file with one line). Both set, or either set but empty, is an error. It is read by every command that signs: the commands of an initialized project (which write an audit entry) and `vex --sign --key`.

- A key file decides whether a passphrase is needed: a plain key never asks for one, so a stale or contradictory variable cannot break a project that has none. An encrypted key with no passphrase, or a wrong one, stops the command with exit code 3 (the audit rule: no entry, no work), and `vex --sign` with exit code 4. No message repeats the passphrase.
- A new encrypted key needs at least 12 characters. An existing key is not held to it.
- The cost is the key derivation, paid at each command of an initialized project: about 0.35 s on the machine used here.
- **Interoperable, checked with OpenSSL 3.0.13:** OpenSSL reads a key encrypted by DepRisk, and DepRisk reads a key encrypted by OpenSSL (`-v2 aes-256-cbc -v2prf hmacWithSHA256`). That is the **migration path for an existing plain key**, with no new command (and no command that rewrites a private key in place): `openssl pkcs8 -topk8 -in .deprisk/audit.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -out audit.key.enc`, check it, then replace the file. The passphrase is then given as above.
- Limits: the passphrase is a .NET string for the time it is used (the runtime offers no zeroable form for this call), and the file it may come from is not checked for permissions (`doctor` checks only an unprotected key).

**A key location for `init`.** `init --key-file <file>` writes the private key to that file (the directory must exist; an existing file is never overwritten) instead of `.deprisk/audit.key`. Commands find it through `DEPRISK_KEY_FILE`; without the variable they look in `.deprisk/audit.key` as before. A key from the variable must be the key of the store (`audit.pub`), or the command stops before writing: entries signed by another key would never verify. The first log entry says that the key is "outside .deprisk"; the path is not recorded, and `--key-file`'s value is masked among the logged arguments like `--key`'s.

**`doctor --format json`.** `deprisk doctor --format json` writes `{schemaVersion, tool, checks:[{name,status,detail}], warnings}` (`schemas/doctor.v1.schema.json`). The table is unchanged except for a new `audit-key` line in an initialized project: where the key is, whether it is encrypted and where the passphrase comes from (never its value), and a warning when the key is missing, cannot be loaded (wrong passphrase, not the store's key), or is unprotected and readable by other users (non-Windows). Doctor loads the key to find these out, so it pays the key derivation once. The exit code is still 0 whatever the warnings. The details contain paths of this machine: the JSON is not deterministic across machines, unlike the analysis outputs.

**Streaming `audit verify`.** The log is read once in 64 KiB blocks and one line is held at a time (a line over 1 MiB is a failure, counted and skipped without being held), so memory does not grow with the log and the 512 MiB cap is gone. Behavior is otherwise the same: same checks, same messages, same line numbers, same head. A last entry without a line ending is still reported first, with its line number. The log is read as it was when the pass began and **no lock is taken**, so a command that appends an entry is never made to wait for a long verification.

## Consequences

- Nothing changes for an existing project: `init` without options, keys without a passphrase, `audit verify` results.
- `CliContext` reads the key and passphrase variables through `GetEnvironmentVariable`, so tests give them without touching the process environment (the test context hides the process's own `DEPRISK_KEY_*` variables).
- The README says how to give the passphrase in CI (a masked secret in `DEPRISK_KEY_PASSPHRASE`).

## Known limits

- A passphrase protects a key at rest; anyone who can run commands as the user, or read the process environment, can still use it. It is not a substitute for keeping the key in a secret store or on another machine (`--key-file` on a mounted secret).
- An existing key is protected only through the OpenSSL step above; DepRisk has no command for it.
- On Windows the unprotected-key warning is not available (no file mode to read there); an encrypted key is the answer.
- Verification takes no lock, so a verification that runs while an entry is being written can in principle see that last entry half written and report it as incomplete; the write is a single call, and a second verification settles it.
