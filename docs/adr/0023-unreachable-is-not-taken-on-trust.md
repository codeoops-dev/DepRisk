# ADR 0023: "Unreachable" is not taken on trust

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

`unreachable` is the only reachability label that makes a finding quieter: ranking lowers it, policy gates can skip it, and `deprisk vex` may turn it into an OpenVEX `not_affected` statement that goes to customers. By ADR 0013 the label means: a symbol list declared complete, fully read sources, no unresolved reflection or receiver, and a direct dependency. The analyzer applies all of that itself, and the CLI added the one rule it could check on its own (a package that is only transitive is `unknown`). The rule about the symbol list was left to the analyzer alone: the CLI believed an `unreachable` for a list marked `complete: false`.

That is how the code was written because the analyzer is the component that owns `complete`, and a correct analyzer never says it. The decision here, taken at the user's request, is that a rule whose input the CLI already has should not depend on the analyzer being correct: a faulty or replaced analyzer would otherwise turn an incomplete list into `unreachable`, and from there into a VEX statement.

## Decision

**`ReachService` enforces it, for every command.** When the analyzer answers `unreachable` for a finding whose symbol set is not declared complete, the verdict becomes `unknown` with the reason `symbol-list-incomplete`, without symbol or path, and the source of the list is kept. The check lives in the one service that `reach`, `rank --symbols`, `ci --symbols`, `explain`, and `vex` all use, so no command can bypass it.

**The override is visible.** The result carries a diagnostic naming the finding and package: the analyzer said `unreachable` for a list that is not declared complete, the answer was changed, and a correct analyzer does not do that, so it should be reported. A change that happens silently would hide an analyzer bug or a tampered analyzer.

**Nothing else is changed.** A path (`reachable`, `possibly-reachable`) is a claim of presence, not of absence, and `unknown` is already the cautious answer; neither is touched. `unreachable` for a complete list is unchanged.

**What the CLI cannot check, and does not pretend to.** Whether the sources were read completely, whether reflection or a receiver of unknown type was unresolved, and whether the call graph is right are the analyzer's to know; the CLI has no input to check them against. Those remain trust in the analyzer, which is why the analyzer is bundled and verified (ADR 0022) and why `explain` shows the path or the reason.

## Known limits

- The CLI does not validate that the label and the reason of an answer fit together (an `unreachable` with the reason `static-path`, for example). A further check of that kind is possible and has not been added. (Added by ADR 0026.)
- A faulty analyzer can still say `unreachable` for a complete list, wrongly. The benchmark harness (ADR 0017) measures how often `unreachable` is wrong (the count of unsound `unreachable` calls); that is the evidence to ask for, not a rule that can be written in advance.

## Consequences

- An incomplete list can no longer lead to `unreachable`, a lowered rank, a policy exemption, or a VEX `not_affected`, whatever the analyzer returns (tests cover `reach`, and `vex` through the service).
- Two places now state the same rule (analyzer and service); a disagreement shows up as the diagnostic.
