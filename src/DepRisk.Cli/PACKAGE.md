# DepRisk

Reachability-aware, uncertainty-driven dependency vulnerability triage and verified remediation planning, from your terminal.

> **Status: pre-alpha.** This release reads the resolved NuGet dependency graph of your projects, matches it against OSV advisory data that you supply (offline), and keeps a signed, tamper-evident audit log. Risk ranking, reachability analysis, and remediation planning are on the roadmap.

```bash
dotnet tool install -g DepRisk.Cli --prerelease

dotnet restore
deprisk scan . --format json                  # resolved dependency graph (offline, deterministic)
deprisk match --advisories NuGet.zip          # known vulnerabilities in those versions
deprisk init                                  # optional: start a signed audit log in .deprisk/
deprisk audit verify                          # verify the audit log
deprisk doctor
```

`match` never downloads anything. Get the advisory data on a connected machine from OSV's data dump
(`https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip`) and pass the file, a directory of `.json` files, or one `.json` file to `--advisories`.
Matching is by package version only: whether the vulnerable code is actually reachable is not considered yet.

- Source, documentation, and roadmap: https://github.com/codeoops-dev/DepRisk
- License: Apache-2.0
