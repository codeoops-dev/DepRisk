# ADR 0016: `explain` and the OpenVEX export

- **Status:** Accepted
- **Date:** 2026-11-05

## Context

With reachability (ADR 0012 to 0014) and the uncertainty model (ADR 0015), DepRisk has verdicts that people will want to question, and verdicts that other people may want to rely on. Two things are needed: a way to ask "why is this finding where it is?" with an answer that can be checked, and a standard, machine-readable way to say "this product is (not) affected" that downstream tools understand. OpenVEX 0.2.0 is that format.

## Decision

**One analysis, four commands.** `rank`, `ci`, `explain`, and `vex` all run the same pipeline (`RankPipeline`: scan, match, optional reachability, baseline ranking, optional risk model), so they always talk about the same findings. `explain` and `vex` accept the analysis options of `rank` (`--advisories`, `--epss`, `--kev`, `--ecosystem`, `--strict`, the reachability options, the risk model options).

**`explain <advisory-id-or-alias> [path]`.** Finds the findings for the advisory (all packages and versions; `--package` narrows). For each it returns: the finding as ranked; the full reachability verdict with its path (when `--symbols` was given); its position and why; the evidence; and what would change the picture. In the baseline method, "why" compares the finding with the one ranked directly above it and names the first key of the baseline ordering that decided it (KEV, EPSS, CVSS, database severity, identifier). With the risk model, it names the statistic, the value, the neighbour's value, the baseline rank, and the calibration. **Every sentence is produced by a fixed template from data in the same result**, never free text: an explanation can be checked line by line, is identical on every run, and cannot say more than the data does. Missing signals are described as missing, never as zero. Output: table or `explain.v1` JSON. Text that comes from advisories or the analyzer has control characters removed.

**`vex [path] --product <purl|iri> --author <text>`.** Writes an OpenVEX 0.2.0 document: one statement per finding (advisory, package, version), for the product the author names, with the vulnerable package as a subcomponent (Package URL: `pkg:nuget/Id@Version`, `pkg:npm/%40scope/name@Version`). The author, the product, and the time are the author's assertions, so they are required (`--timestamp` pins the time; without it the current UTC time is used, which makes the document differ between runs; the document id is a digest of the content and changes with it).

**Statuses, conservatively.**
- `not_affected` with justification `vulnerable_code_not_in_execute_path`: only for a verdict of `unreachable`, which the analyzer gives only for a complete symbol list, fully read source, no unreadable reflection or receiver; the CLI makes it `unknown` for a package that is not a direct dependency; and `vex` re-checks, at the moment of writing, that the package is a direct dependency at **every** location, that the analysis skipped no file and found no unreadable file, and that the symbol list has provenance. If any of that fails the statement is `under_investigation` with a note saying the conditions were not all met. The impact statement names the analyzer and its version, the digest of the analyzed sources, and the digest of the symbol maps.
- `affected` for `reachable`, with the required action statement (upgrade to the fixed version, or "no fixed version is known; avoid or restrict the use of the symbol") and an impact statement naming the symbol.
- `under_investigation` for everything else: `possibly-reachable`, `unknown` (with the reason), and findings that were not analyzed. Without `--symbols` every statement is `under_investigation`: matching by version says "this version is in an affected range", not "this product is affected".
- `fixed` is not produced: DepRisk reports what is present.

**Not signed.** OpenVEX documents can be signed; this one is not. Signing belongs with the key management of the audit log and the offline bundles (roadmap), and an unsigned document must be treated as an assertion by the author named in it.

## Known limits

- The `not_affected` claim is as good as the symbol map and the call graph (ADR 0012). The document says so in the impact statement; downstream tools may not show it.
- The document is built from the OpenVEX 0.2.0 specification; it has not been validated against the official schema in CI (the schema is not available offline). The structure is covered by unit tests, and a validation step with the OpenVEX tooling is a follow-up.
- One statement per package version: findings in several projects of one repository are merged into one statement; the product is one name given by the author.
- `explain` explains one advisory at a time and does not compare it with other advisories beyond the neighbour above it.

## Consequences

- People can verify a ranking decision from the sentences and the JSON next to them.
- The strongest claim DepRisk can make (not affected) is behind the strictest conditions, checked twice, and the evidence travels with the claim.
