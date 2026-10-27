# Security Policy

DepRisk is a security tool that analyzes untrusted source code and makes security-relevant recommendations. We take vulnerabilities in DepRisk itself seriously.

## Supported versions

DepRisk is **pre-alpha**. Only the latest release and the `main` branch receive security fixes. This will be updated when 1.0 is released.

| Version | Supported |
|---|---|
| latest release | ✅ |
| `main` | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue and how to reproduce it.

If private reporting is unavailable to you, open a public issue that says only "I need to report a security issue privately" (no technical details), and a maintainer will arrange a private channel.

### What to include

- affected version or commit, and your OS
- a minimal reproduction (input files, command line)
- impact: what an attacker can achieve
- whether you plan to disclose publicly, and any deadline

### What to expect

DepRisk is maintained by a very small team, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge your report | within 7 days |
| Initial assessment and severity | within 14 days |
| Fix or mitigation for confirmed issues | depends on severity; critical issues are prioritized |
| Credit in the advisory | yes, unless you prefer to stay anonymous |

We follow coordinated disclosure: please give us reasonable time to release a fix before publishing details.

## Scope

In scope:

- the DepRisk CLI, reachability analyzer, verification kernel, audit log, and bundle handling
- bypass of signature verification for data bundles or audit logs
- ways a malicious project, lockfile, SBOM, or bundle can cause code execution, file writes outside the intended directories, or data exfiltration
- flaws that make the verification kernel accept a plan that violates its proven properties (P1–P6 in the README)
- audit-log tampering that `deprisk audit verify` fails to detect

Out of scope:

- findings that only reflect the documented [limitations](README.md#threat-model-and-limitations) (for example, missed reachability through reflection)
- vulnerabilities in third-party dependencies with no demonstrable impact on DepRisk
- social-engineering or physical attacks
- denial of service from unrealistically large inputs, unless it bypasses documented resource limits

## Safe harbor

Good-faith security research that follows this policy will not be pursued by the maintainers. Please avoid accessing data that is not yours, degrading services, or testing against systems you do not own.

## Hardening notes for users

- Verify release checksums and signatures before installing.
- Import only data bundles whose signatures you have verified against a key you trust.
- Keep your audit key private; export checkpoints to write-once storage if you need stronger tamper evidence.
- Run `apply --validate` only with a sandbox you control.

See also: [docs/threat-model.md](docs/threat-model.md).
