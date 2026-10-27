# ADR 0003: Untrusted optimizer, small proven verification kernel

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

Remediation plans are produced by an optimization pipeline (Monte Carlo sampling, MILP solving) that is complex and floating-point heavy. Users will apply these plans to their projects, so an incorrect plan (for example, one that violates a compatibility constraint or the effort budget) has real cost. Proving the whole pipeline correct is infeasible for a small team.

Alternatives considered:

1. **Trust the optimizer and test heavily.** Cheap, but offers no strong guarantee.
2. **Formally verify the entire optimizer.** Prohibitively expensive and brittle.
3. **Separate generation from checking.** Keep the optimizer outside the trusted base and verify each plan with a small, independently proven checker (a "certificate checking" approach).

## Decision

- The optimizer is **untrusted**. It emits a plan in a documented format.
- A small **verification kernel written in Ada/SPARK** checks each plan before it can be applied. It uses scaled-integer arithmetic only and has a deliberately minimal input format.
- The kernel's guarantees are limited to properties P1–P6 listed in the README and `docs/method.md`: unique version per package, hyperedge consistency, budget, policy, correctness of fix claims, and absence of runtime errors.
- The kernel does **not** attest to plan optimality or to the correctness of reachability labels; the project states this explicitly.
- The build fails if any verification condition is unproven.

## Consequences

- The trusted code base stays small enough to prove and review.
- Any optimizer or solver change cannot compromise consistency guarantees as long as the kernel accepts the plan.
- Requires maintaining GNATprove-based proofs and a stable minimal interchange format between the .NET core and the kernel; changes to either need an ADR.
- Users get a precise, honest claim: "this plan is consistent and within budget, as checked by a proven kernel," not "this plan is optimal."
