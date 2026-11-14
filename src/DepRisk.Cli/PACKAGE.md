# DepRisk

Reachability-aware, uncertainty-driven dependency vulnerability triage and verified remediation planning, from your terminal.

> **Status: pre-alpha (`0.2.0-alpha.1`).** This release reads the resolved dependency graph of NuGet and npm projects, matches it against OSV advisory data that you supply, ranks the findings (a baseline of CISA KEV, EPSS, and CVSS, or an uncertainty model with placeholder parameters), says whether the vulnerable code is reachable from your application (C# for NuGet, JavaScript and TypeScript for npm), explains each finding, exports OpenVEX statements that can be signed, gates CI with a policy, and keeps a signed, tamper-evident audit log. Everything works offline. Remediation planning is on the roadmap and is not in this release.
>
> **Reachability needs symbol maps** (a curated list of the entry points through which application code reaches the flaw of an advisory): OSV carries none, so there is no symbol data for real advisories yet, and the uncertainty model is not calibrated. Treat the output as a way to reason about your own data, not as a verdict.

```bash
dotnet tool install -g DepRisk.Cli --prerelease

dotnet restore                                # NuGet; for npm, a package-lock.json is enough
deprisk scan .                                # resolved dependency graph (--ecosystem nuget|npm to choose)
deprisk match --advisories NuGet.zip          # known vulnerabilities in those versions (npm: npm.zip)
deprisk rank --advisories NuGet.zip --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv.gz
deprisk reach --advisories NuGet.zip --symbols symbols/   # can the vulnerable code be reached? (see docs/symbol-maps.md)
deprisk ci --advisories NuGet.zip --fail-on "kev&fixable,cvss>=9" --format sarif --out deprisk.sarif
deprisk vex --product pkg:nuget/App@1.0.0 --author "Example Corp" --advisories NuGet.zip --symbols symbols/ --sign --key vex.key --subject-file App.nupkg --out vex.intoto.json
deprisk vex verify vex.intoto.json --pubkey vex.pub
deprisk doctor
```

The reachability analyzer is bundled with this package for linux-x64, linux-arm64, osx-x64, osx-arm64, and win-x64; on another platform build it from source (`cargo build --release --locked` in `analyzers/reach`) and pass `--analyzer <path>`. `deprisk doctor` shows which one is used.

Nothing is downloaded by the tool. Get the data on a connected machine and pass the files in:
OSV dumps (`https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip` or `.../npm/all.zip`), the EPSS scores CSV, and the CISA KEV JSON.

Exit codes: 0 success, 1 policy gate failed, 3 integrity failure (audit log or a signed VEX document that does not verify), 4 input or configuration error, 5 internal error.

- Source, documentation, and roadmap: https://github.com/codeoops-dev/DepRisk
- License: Apache-2.0
