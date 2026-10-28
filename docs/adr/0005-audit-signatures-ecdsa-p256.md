# ADR 0005: Audit log signatures use ECDSA P-256, not Ed25519

- **Status:** Accepted
- **Date:** 2026-10-28
- **Supersedes:** the mention of Ed25519 in the first drafts of the README, threat model, and `audit-entry` schema.

## Context

The audit log (README, "Tamper-evident audit log") is signed so that edits are detectable offline by anyone holding the public key. The first design named Ed25519. When implementing it we found that the .NET base class library, including the .NET 10 SDK we target, has **no Ed25519 implementation**; it offers ECDSA, RSA, and (new) post-quantum algorithms.

Alternatives:

1. **Ed25519 through a third-party library** (a native libsodium wrapper or a managed implementation such as BouncyCastle). Nicer properties (deterministic signatures, simple keys), but it adds a dependency to the one component whose job is to be trustworthy, plus native binaries or a large managed library to review, ship, and keep patched. DepRisk is a supply-chain security tool; every dependency we add is a dependency we must also be able to defend.
2. **ECDSA over NIST P-256 with SHA-256 from the base class library.** No new dependency, available on Windows, Linux, and macOS, backed by the platform's cryptographic provider, widely accepted by security and compliance teams, and verifiable with standard tools (OpenSSL, any language).
3. **Writing our own Ed25519.** Rejected: never implement cryptography ourselves.

## Decision

- Entries are signed with **ECDSA P-256 / SHA-256** using the BCL (`System.Security.Cryptography.ECDsa`).
- Signatures use the fixed-width **IEEE P1363 `r || s` encoding (64 bytes)**, stored as standard Base64 (88 characters, ending in `==`).
- Keys are stored as PEM: PKCS#8 for the private key (`.deprisk/audit.key`, owner-only permissions where supported), SubjectPublicKeyInfo for the public key (`.deprisk/audit.pub`).
- The signed bytes are the RFC 8785 canonical JSON of the entry without its `signature` field (see `docs/audit-log.md`).
- Verification rejects any key that is not P-256.

## Consequences

- No new runtime dependency for signing or verifying.
- ECDSA signatures are **randomized**: signing the same entry twice gives different signatures. This does not matter for verification, and the hash chain does not depend on determinism of signatures beyond the stored line.
- ECDSA is not quantum-resistant, which is also true of Ed25519. The .NET base class library already includes ML-DSA; moving the log to a post-quantum scheme later means a new `schemaVersion` and an ADR.
- Implementations in other languages can verify logs with their standard library (P-256, SHA-256, raw `r||s` signatures).
- If a future .NET release adds Ed25519, switching is a format change (`schemaVersion` 2) and needs a new ADR.
