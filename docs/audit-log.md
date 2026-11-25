# Audit log format (version 1)

Status: **implemented** (`deprisk init`, `deprisk audit verify`, and every command that records an entry).
Schema: [`schemas/audit-entry.v1.schema.json`](../schemas/audit-entry.v1.schema.json). Rationale for the algorithms: [ADR 0005](adr/0005-audit-signatures-ecdsa-p256.md).

The audit log answers: *who ran what, where, when, on which inputs, with which result, and what changed, and has any of that been altered since?*

## Where it lives

```text
.deprisk/
├── audit.key      private signing key (PKCS#8 PEM, optionally encrypted with a passphrase). Secret. Owner-only permissions where supported. May live elsewhere (see below).
├── audit.pub      public key (SubjectPublicKeyInfo PEM). Safe to share.
├── audit.log      the log: one entry per line (JSON Lines), UTF-8, LF line endings
└── .gitignore     contains "audit.key" so the private key is never committed
```

`audit.log` and `audit.pub` may be committed or archived. Commands find the store in the current directory or the nearest parent that has one (like Git). A project without a store works exactly as before and writes nothing.

Once a project has a store, auditing is **mandatory**: if the key is missing or the log is damaged, commands stop with exit code 3 instead of continuing unrecorded.

## Entry

Every line is one JSON object with exactly these properties:

| Property | Type | Meaning |
|---|---|---|
| `schemaVersion` | integer | `1` |
| `seq` | integer ≥ 1 | Sequence number, starting at 1, increasing by exactly 1 |
| `timestamp` | string | UTC, `yyyy-MM-ddTHH:mm:ss.fffZ` |
| `actor` | string | Operating-system user |
| `host` | string | Machine name |
| `cwd` | string | Working directory of the command |
| `gitCommit` | string or null | Current commit, read from `.git` (no `git` process is run); null if unknown |
| `command` | string | For example `init`, `scan` |
| `args` | array of strings | Arguments as typed. Values of options that look like secrets are replaced by `***` |
| `inputsDigest` | 64 hex | SHA-256 over what the command read (for `scan`: each input file's SHA-256 and relative path, sorted) |
| `outputsDigest` | 64 hex | SHA-256 over the canonical result (for `scan`: the canonical scan JSON, whatever output format was chosen) |
| `changes` | array | `{ "subject": string, "from": string or null, "to": string or null }`: what was created or changed |
| `prevHash` | 64 hex | Hash of the previous line; 64 zeros for the first entry |
| `signature` | string | ECDSA P-256 / SHA-256 signature, Base64 of the 64-byte `r‖s` |

Unknown properties are errors, not extensions: a verifier must reject them (otherwise unsigned data could be smuggled into a line).

## Canonical form

Entries are serialized with the rules of **RFC 8785 (JSON Canonicalization Scheme)**, restricted to the types used here:

- object keys sorted by UTF-16 code units (this gives: `actor, args, changes, command, cwd, gitCommit, host, inputsDigest, outputsDigest, prevHash, schemaVersion, seq, signature, timestamp`; inside a change: `from, subject, to`)
- no whitespace between tokens
- strings escape only `"` `\` and control characters (`\b \t \n \f \r`, others as `\u00xx` with lowercase hex); everything else is written as is, in UTF-8
- integers in plain decimal; no floating-point numbers appear
- `null` is written as `null`
- a lone UTF-16 surrogate cannot be written in UTF-8; it is replaced by U+FFFD before hashing

The stored line **is** the canonical form of the full entry (including `signature`). A verifier requires the line to equal the canonical serialization of what it parsed.

## Signing and chaining

1. Build the entry without `signature` and serialize it canonically: this is the **body**.
2. `signature = Base64( ECDSA-P256-SHA256( UTF-8(body) ) )`, raw 64-byte `r‖s`.
3. Serialize the entry including `signature`: this is the **line**.
4. The next entry's `prevHash` = `SHA-256( UTF-8(line) )` as lowercase hex (the line without its newline).

## Verification (`deprisk audit verify`)

For each line, in order, a verifier checks:

1. valid UTF-8 and JSON; exactly the properties above, correct types, correct formats
2. `schemaVersion` is `1`
3. `seq` equals the expected number (1, 2, 3, ...)
4. `prevHash` equals the hash of the previous line (zeros for the first)
5. the line equals its own canonical form
6. the signature verifies with the public key

Any failure reports the line number and reason, and the command exits with code **3**.

The log is read once, in blocks, and one line is held at a time: memory does not grow with the log (ADR 0030). It is read as it was when the pass began; no lock is taken, so a command that appends an entry never waits for a verification.

## Protecting the key

- **Encrypt it.** `deprisk init --encrypt` writes the private key as an encrypted PKCS#8 PEM (PBES2: PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-CBC). The passphrase is given in the environment variable `DEPRISK_KEY_PASSPHRASE`, or in a file (one line) named by `DEPRISK_KEY_PASSPHRASE_FILE`; never on the command line. Every command of the project that signs needs it; without it, or with a wrong one, the command stops with exit code 3. A new key needs at least 12 characters. The cost is the key derivation, about a third of a second per command.
- **Keep it elsewhere.** `deprisk init --key-file <file>` writes the key to that file; commands find it through `DEPRISK_KEY_FILE`. The key must be the one `audit.pub` belongs to, or the command stops before writing.
- **Encrypt an existing key** with OpenSSL (it reads keys that DepRisk encrypts, and DepRisk reads the ones it encrypts): `openssl pkcs8 -topk8 -in .deprisk/audit.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -out audit.key.enc`, then replace `audit.key` with the result (after checking that `deprisk doctor` is happy with it).
- `deprisk doctor` shows where the key is, whether it is encrypted and where its passphrase comes from, and warns when commands would stop (missing key, wrong passphrase, a key that is not the store's) or when an unprotected key can be read by other users.

## What the log proves, and what it does not

| Attack | Detected? |
|---|---|
| Editing an entry | Yes (signature, canonical form) |
| Inserting or deleting an entry in the middle, reordering | Yes (sequence, chain) |
| Replacing entries with ones signed by another key | Yes, if the verifier has the right public key |
| Removing entries from the **end** | **Not by the log alone.** Use `--head`: store the `head:` hash somewhere you trust and check `deprisk audit verify --head <hash>` |
| An attacker with the **private key** forging entries | No. Protect the key; keep it off shared machines; anchor heads externally |
| Replacing the whole `.deprisk/` directory (log, key, and public key) | Only if you hold an independent copy of the public key (`--pubkey`) or a pinned head |
| An interrupted write | Yes: a log that does not end with a newline is reported as incomplete |

Planned (see README roadmap): Merkle checkpoints and anchoring heads outside the machine.

## Concurrency and size

Appends take an exclusive file lock and compute the next sequence number and `prevHash` under that lock, so parallel runs cannot fork the chain. Appending reads only the last line. Verification reads the whole file into memory (limit 512 MB); streaming verification is future work.
