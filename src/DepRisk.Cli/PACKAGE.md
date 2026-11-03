# DepRisk

Reachability-aware, uncertainty-driven dependency vulnerability triage and verified remediation planning, from your terminal.

> **Status: pre-alpha (`0.1.0-alpha.1`).** This release reads the resolved dependency graph of NuGet and npm projects, matches it against OSV advisory data that you supply, ranks the findings with a baseline method (CISA KEV, then EPSS, then CVSS), gates CI with a policy, and keeps a signed, tamper-evident audit log. Everything works offline. Reachability analysis, uncertainty modeling, and remediation planning are on the roadmap and are not in this release.

```bash
dotnet tool install -g DepRisk.Cli --prerelease

dotnet restore                                # NuGet; for npm, a package-lock.json is enough
deprisk scan .                                # resolved dependency graph (--ecosystem nuget|npm to choose)
deprisk graph .                               # its hypergraph: every requirement checked against what is installed
deprisk match --advisories NuGet.zip          # known vulnerabilities in those versions (npm: npm.zip)
deprisk rank --advisories NuGet.zip --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv.gz
deprisk ci --advisories NuGet.zip --fail-on "kev&fixable,cvss>=9" --format sarif --out deprisk.sarif
deprisk init                                  # optional: start a signed audit log in .deprisk/
deprisk audit verify                          # verify the audit log
deprisk doctor
```

Nothing is downloaded by the tool. Get the data on a connected machine and pass the files in:
OSV dumps (`https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip` or `.../npm/all.zip`), the EPSS scores CSV, and the CISA KEV JSON.
Matching is by package version only: whether the vulnerable code is actually reachable is not considered yet.

Exit codes: 0 success, 1 policy gate failed, 3 audit log integrity failure, 4 input or configuration error, 5 internal error.

- Source, documentation, and roadmap: https://github.com/codeoops-dev/DepRisk
- License: Apache-2.0
