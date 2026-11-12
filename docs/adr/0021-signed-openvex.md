# ADR 0021: Signed OpenVEX documents and validation against the official schema

- **Status:** Accepted
- **Date:** 2026-11-12

## Context

A VEX statement is made for other people to rely on (ADR 0016). Two questions follow: is the document well-formed according to the specification everyone else reads, and can a recipient tell that it comes from the party that says so and was not changed on the way? ADR 0016 left both open: the document had only been checked against our own reading of the specification, and it was not signed.

## Decision

**Validation against the official schema, in CI.** The OpenVEX JSON schema of the specification (`openvex/spec`, `openvex_json_schema.json`) is fetched in CI and pinned by its SHA-256, the way the SARIF schema already is: a change upstream fails the build loudly instead of silently changing what we check. The CI step validates the document that `deprisk vex` writes, and the predicate inside a signed envelope. The tool itself does not embed a schema validator; the structure is also covered by unit tests.

**The signature is a DSSE envelope around an in-toto statement.** `deprisk vex --sign` writes one line of JSON, the [DSSE](https://github.com/secure-systems-lab/dsse) envelope that Sigstore and in-toto tooling use: `payloadType` `application/vnd.in-toto+json`, a Base64 `payload`, and `signatures` with a key id and the signature. The payload is an [in-toto Statement v1](https://github.com/in-toto/attestation) whose `predicateType` is `https://openvex.dev/ns/v0.2.0` and whose `predicate` is the OpenVEX document, unchanged. This is the shape in which the OpenVEX project itself distributes attested documents, so existing tools can read it, and an envelope can later be given a Sigstore signature without changing the document.

**Why an envelope and not a field in the document.** OpenVEX defines no embedded signature. A signature that is part of the signed object cannot cover itself, and canonicalizing a JSON document so that it can is an old source of bugs. DSSE signs a precise byte string: `DSSEv1 <len(type)> <type> <len(payload)> <payload>`. The payload type is inside what is signed, so a signature over one kind of object cannot be replayed as another: a signature the audit log made with the same key does not verify as a VEX signature (a test checks this).

**Algorithm.** ECDSA over P-256 with SHA-256, signature in ASN.1 DER form, the form OpenSSL, Sigstore, and the in-toto libraries produce and expect. The key is a PEM file: PKCS#8 (`BEGIN PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`, what `openssl ecparam -genkey` writes). The audit log's signature (ADR 0005) stays what it was (raw 64-byte form over its own canonical text). CI verifies a signed document with OpenSSL, not only with our code, so the format is checked against an independent implementation.

**What is signed is about something.** A statement needs at least one subject, an artifact with a SHA-256 digest (`--subject-file <file>`, hashed by the tool so a digest cannot be mistyped, or `--subject-digest sha256:<hex>` with the product as the name). A signature over nothing in particular would attest nothing. Only the file name, never the path, goes into the statement.

**The key is explicit.** `--key <file>` is required for `--sign`; there is no implicit use of the audit log's key (it is easy to point at it, but a key for signing documents that go to customers and a key for a local audit log are different things and should rotate separately). The value of `--key` is redacted in the audit log's record of the command line (as for every option called `key`), and the key is never written to the output.

**Verification is the recipient's decision.** `deprisk vex verify <envelope> --pubkey <public key> [--subject-file <file>]` checks the envelope's shape, that a signature verifies with the key the recipient supplied (the key id in the envelope is a hint and decides nothing), that the payload is an in-toto statement for OpenVEX 0.2.0, and, if files are given, that each is one of the subjects. Exit code 3 (the existing integrity failure) when something does not verify; the output says which part. Which public key to trust is not something the tool can know.

## Known limits

- A valid signature says who signed and that the document is unchanged, not that its statements are true. The statements are as good as the symbol maps and the call graph (ADR 0012, ADR 0019).
- No key management: no key generation, no rotation, no certificates, no transparency log. Sigstore keyless signing (OIDC identity, Fulcio, Rekor) is a later option; the envelope is the one such tools use.
- One signature per envelope, from one key. Verification accepts envelopes with several signatures if one of them verifies with the supplied key.
- The official schema is checked in CI, not at run time; a document produced by this tool is not validated again when it is read by `verify` beyond the OpenVEX context and the presence of statements.
- DSSE signatures are not deterministic (ECDSA is randomized): signing the same document twice gives two different envelopes, both valid. The predicate is identical.

## Consequences

- Customers and auditors can verify a VEX document with the public key alone, with this tool or with OpenSSL.
- Exit code 3 now also covers a signed VEX document that does not verify (README).
- Signing is a new capability that touches secrets: the key file is read once, used, and disposed; it is not stored, logged, or copied.
