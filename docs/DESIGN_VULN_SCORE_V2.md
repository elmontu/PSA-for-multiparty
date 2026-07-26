# Vulnerability Score V2 — dual-tier deployment (4 parties)

## ⚠️ SUPERSEDED — historical only

This document is a speculative roadmap that was revised multiple times
before the actual problem statement was locked. It is **retained for
history only**; do NOT use it to plan work.

The canonical problem specification is now
[`PROBLEM_STATEMENT.md`](./PROBLEM_STATEMENT.md).
The theoretical framing is in
[`THEORY_TDR.md`](./THEORY_TDR.md).

Content below is the historical V2 draft, kept intact for audit
traceability but not authoritative.

---

## Deployment shape

**Parties (4, all data holders + role-differentiated):**

| Party | Data held | Role |
|---|---|---|
| Bank A | Loan_A[firm_id] per its own customers | Data + score recipient (per-firm scores for its customers) |
| Bank B | Loan_B[firm_id] per its own customers | Data only |
| Department of Statistics | Sector[firm_id], employees, revenue | Data |
| IRAS | Income[firm_id], taxable_profit, sector_code | Data + score recipient (per-sector aggregates for supervision) |

**Universe of firm IDs:** union of everyone's IDs. The "intersection" concept from OIRA doesn't map directly — different parties know overlapping but not identical sets. For vulnerability scoring, the relevant per-firm set is `firms known to ALL contributing data sources for that ratio`.

## Score model

Per firm F, a vulnerability score:

```
vuln_score(F) =
    w_1 * (loan_to_income(F))
  + w_2 * (debt_to_ebitda(F))
  + w_3 * (leverage_ratio(F))
  + ...
```

Where each ratio requires values from ≥ 2 parties:

- **loan_to_income(F)** = (Loan_A[F] + Loan_B[F]) / Income[F]
- **debt_to_ebitda(F)** = (Loan_A[F] + Loan_B[F]) / EBITDA[F]  (EBITDA derived from IRAS filings + DoS revenue)
- **liability_intensity(F)** = (Loan_A[F] + Loan_B[F]) / Revenue[F]

Sector score over time = distribution of vuln_score across firms in sector, computed weekly/monthly.

## Two output tiers

**Tier 1: Per-firm scores to Bank A (Option A)**
- Bank A learns vuln_score(F) for F ∈ Bank_A_customers
- Bank A DOES NOT learn vuln_score(F) for firms it doesn't already serve
- Bank B, DoS, IRAS learn NOTHING at this tier
- Bank A already knows the identity of its own customers — no membership leak; the score IS what needs privacy

**Tier 2: Sector aggregates to supervisor (Option B)**
- Supervisor (could be a fifth party, or IRAS wearing a supervisory hat) receives:
  - Per-sector: count of firms with vuln_score > threshold, mean/median/std score, buckets
- Individual firm identities and scores NOT revealed
- Full OIRA-style double-blind at this tier

## Threat model

**Semi-honest 4-party model.** Any subset up to 3 parties may be corrupted (up to N−1). At least one honest party required.

**Special roles:**
- Bank A as a data holder AND score recipient: from Bank A's view, it sees its own inputs and its authorized outputs. Its knowledge of vuln_score(F) for its own customer F is intended.
- Bank A must NOT learn any Bank B-only customer's data (loan values), any DoS-only info, any IRAS-only info (income figures).
- Bank B, DoS, IRAS must not learn any per-firm score.

**Aux-info attack (from OIRA framework):** even Bank A learning per-firm scores for its OWN customers has aux-info implications — if Bank A publishes derived statistics, external adversary can correlate against public filings. Score confidentiality at Bank A must be preserved (contractual + technical: TEE for score storage, audit).

## Implementation roadmap — realistic multi-session

**Session 1 (this session): building blocks**

1. `secureDivideU64Bin`: bit-by-bit long division on `SharedU64Bin`.
   Uses existing `secureAddU64Bin` + `secureSubU64Bin`. Handles div-by-zero.
2. Unit test with cleartext parity across 20+ cases including edge cases.
3. This design doc.

Deliverable: proven secure-division primitive.

**Session 2: value aggregation + ratio circuit**

4. `secureAddU64Bin` chain across N parties (already have pairwise; needs
   N-party aggregation wrapper).
5. Per-firm ratio: `share(loan_A) + share(loan_B)` then divide by `share(income)`.
   Bit-shared throughout; result is `SharedU64Bin`.
6. Unit test: cleartext parity on synthetic 4-party (Loan_A, Loan_B, Income)
   with 20 firms.

**Session 3: full per-firm score assembly**

7. `computeVulnScore(shares_of_metrics, weights)` — weighted sum of ratios
   in fixed-point arithmetic. Weights are PUBLIC (regulator-visible; not
   secret). Reveals only the final score share to the designated recipient
   (Bank A for its customers).
8. Per-firm PSI: intersect all 4 parties' known-firm-IDs. Only firms with
   full data (loan_A, loan_B, income, sector) get scored.
9. Reveal phase: for each firm F where Bank A is authorized, reveal
   `score(F)` to Bank A only (via masking).

**Session 4: Tier 2 sector aggregates**

10. Per-firm scores stay in bit-shared form; instead of revealing per-firm to
    Bank A, aggregate by sector via secure grouped-sum.
11. Reveal `(sector, count, mean_score)` to supervisor via OIRA-style
    aggregate.
12. DP noise on sector aggregates via the OIRA budget accountant we already have.

**Session 5: wire protocol + deployment doc**

13. Port from in-process to real sockets, integrate with existing MpsaDriver
    star topology.
14. Beaver-triple production via real MPC (MpOleTriple in-tree) not trusted
    dealer.
15. Deployment doc for the 4-party regulatory scenario.

## Building block: `secureDivideU64Bin`

Standard non-restoring long division on unsigned bit-shared 64-bit integers:

```
Given: SharedU64Bin num, SharedU64Bin denom
Compute: SharedU64Bin quotient, SharedU64Bin remainder, SharedBit divByZero

Algorithm (64 iterations):
    R := 0 (as SharedU64Bin, 64 bits shared zero)
    Q := 0
    for i in 63 downto 0:
        R := (R << 1) | num.bits[i]     // shift-in the next numerator bit
        (R_minus_denom, borrow) := secureSubU64Bin(R, denom)
        // If borrow == 0 then R >= denom, so we take the subtraction; else keep R.
        R := select(borrow, R, R_minus_denom)  // multiplexer, MPC
        Q.bits[i] := NOT borrow                 // quotient bit
    return (Q, R, divByZeroCheck)

divByZeroCheck: compare denom to zero using existing secureLessThan or
                secureEqual; if divByZero == 1, output canonical (0, 0, 1).
```

Cost per division:
- 64 iterations × (secureSubU64Bin = 128 triples + select-mux = 128 triples)
- = ~16k Beaver bit-triples per division
- For 20 firms: ~320k triples. Feasible for demo.

## Deferred / risk items

- **Fixed-point precision**: ratios like loan/income are typically < 100 (as a
  multiplier), scaled by 10^6 for 6-digit precision → fits in u32. Fits in
  the u64 arithmetic comfortably.
- **Signed values (negative EBITDA for distressed firms)**: handled via
  two's-complement bit-shares, but the current secureLessThan is unsigned.
  A signed comparison layer is a follow-on.
- **Multiple ratios per firm**: each ratio requires its own division. For 3
  ratios × 20 firms = 60 divisions = ~1M triples. Manageable in-process,
  network cost real over wire.
- **Combining with OIRA**: Tier-2 sector aggregates should reuse the DP
  budget accountant. Bank A → sector-supervisor query = budget spend.
- **Malicious security**: everything semi-honest; production upgrade later.

## What this session ships

- This doc (`DESIGN_VULN_SCORE_V2.md`).
- `secureDivideU64Bin` primitive (`MpMpcArithmetic.{h,cpp}` extension).
- Unit test.

Everything else deferred to next sessions per this roadmap.
