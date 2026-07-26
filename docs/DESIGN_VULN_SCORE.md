# Vulnerability Score — DOUBLE-BLIND MPC computation (multi-session)

## ⚠️ SUPERSEDED — historical only

This document is a speculative roadmap that was revised multiple times
before the actual problem statement was locked. It is **retained for
history only**; do NOT use it to plan work.

The canonical problem specification is now
[`PROBLEM_STATEMENT.md`](./PROBLEM_STATEMENT.md).
The theoretical framing is in
[`THEORY_TDR.md`](./THEORY_TDR.md).

Content below is the historical Session 2 revision, kept intact for
audit traceability but not authoritative for current or future work.

---

## REVISION NOTE (Session 2)

The initial version of this doc assumed the target output was
**per-company scores** revealed to SP. That's wrong for the actual
requirement. Per-company scores REVEAL MEMBERSHIP indirectly: if
`(company_id_hash, score)` is revealed, and scores are distinctive
enough (e.g., one company has an unusually high leverage ratio), SP can
match rows to real-world entities using public financial disclosures.
The whole point of the double-blind protocol collapses.

**Correct requirement:** SP learns **only an aggregate statistic** over
the intersection — never any per-company value. The primitive is
**MPSI-Cardinality-Sum (MPSI-CS)**, already vendored from MPSO
(`volePSI/upstream/mpso/mpso/MPSICS.{h,cpp}`).

## Use case (unchanged)

Regulator / supervisor needs to understand system-wide financial
vulnerability across companies where multiple banks each hold pieces of
each company's picture. What the regulator (SP) actually wants:

- **Aggregate risk statistics** across companies in the intersection:
  - "How many intersection companies have total-leverage > threshold?"
  - "What is Σ (loan-to-income ratio) across intersection companies?"
  - "Distribution of leverage buckets across intersection?"

What SP must NOT learn:
- Which specific company IDs are in the intersection
- Per-company scores or metrics
- Per-bank contribution to any specific company

## Why membership hiding matters

Two leak vectors that any per-row output enables:

1. **Direct ID reveal.** If output rows are keyed by company_id, SP
   trivially knows membership.
2. **Payload fingerprinting.** Even if IDs are hashed and rows shuffled,
   distinctive plaintext values (e.g., "total_loan = $47.3M") can be
   matched against public disclosures / other sources to re-identify
   companies.

MPSI-CS closes both by revealing ONLY `Σ f(intersection member)` for a
single caller-chosen `f`. No per-row payload ever crosses the wire in
cleartext.

## The primitive: MPSICS

Signature (from `MPSICS.h`):

```cpp
u64 MPSICardSumParty(u32 idx, u32 numParties, u32 numElements,
                     std::vector<block>& set, u32 numThreads);
```

Semantics after reading `MPSICS.cpp`:

- Each block in `set` packs `(key : low64, value : high64)`.
- `idx=0` (party 0) receives the aggregate: `Σ high64 for i in intersection`.
- All other parties receive `0` (they contributed to the sum but don't see it).
- Sockets are opened internally at `PORT + max(i,j)*100 + min(i,j)`
  (hardcoded).

**Aggregate model:**

Party j pre-computes its per-item contribution `v_i^{(j)}` in cleartext
locally (e.g., "loan_from_bank_j_to_company_i"). Packs `(id_i, v_i^{(j)})`
into blocks. All parties run MPSICS. Party 0 learns
`Σ_{i in intersection} Σ_j v_i^{(j)}`.

## Score models fit for MPSICS

MPSICS returns exactly one scalar. To build a "vulnerability score" out
of one scalar output per protocol run, one of:

| Score model | Per-item value contributed by bank j | SP learns |
|---|---|---|
| **Total leverage** | `loan_ij` | Σ total loan across intersection |
| **Bank-flag high-risk count** | `1` if bank_j flagged company_i as high-risk (local decision), else `0` | number of banks × companies flagged high-risk in intersection |
| **Weighted score** | `w_j * metric_ij` where `w_j` public | weighted-sum across intersection |
| **Bucket histogram** | Run MPSICS once per bucket-threshold, indicator = `1_{ratio_ij > t_k}` | count per bucket |

Notice **each of these needs only local per-party pre-computation** plus
MPSICS. No secure division needed — because the ratio computation happens
inside each bank on its own data (which is fine — the bank sees its own
data), and only the boolean/counter is packed as `v_i^{(j)}`.

For **ratios that span multiple banks** (e.g., total_loan / total_income
where loans come from bank A and income from bank B):
- Cannot be computed per-bank locally.
- Requires two MPSICS calls: one for `Σ loan_i`, one for `Σ income_i`.
- SP receives two scalars; divides in cleartext.
- SP learns `(Σ loan) / (Σ income)` across intersection — a system-level
  ratio, not per-company.

For **companywise ratios revealed only through aggregates**:
- Need arbitrary function `g(x^{(1)}_i, x^{(2)}_i, x^{(3)}_i, ...)` per
  company then aggregate → far more complex; would need secure
  multiplication in MPC on secret-shared per-company values.
- Deferred to a much later stage (would need to extend MPSICS or fall
  back to full MPC via `MpsaJoinMpcDriver`).

## Roadmap — revised, multi-session

### Session 2 (THIS SESSION)

1. **This revision** of the design doc.
2. **Standalone test** proving MPSICS actually runs against our built
   library: 3 in-process parties, small (id, value) inputs, verify
   output equals cleartext intersection-sum. This tells us the vendored
   code is functional before we plan wire integration.
3. Document any surprises (build-time issues, hardcoded socket topology
   collisions, runtime errors).

Deliverable: proven MPSICS baseline + honest report of what integration
needs.

### Session 3

4. **Adapter layer** to fit MPSICS into MPSA's socket topology. MPSICS
   opens its own mesh sockets at `PORT + i*100 + j`. If we can use a
   port range disjoint from MPSA's, the mesh runs alongside the star.
   Otherwise, patch MPSICS to accept caller sockets.
5. **New CLI mode** `frontend -mpsa-vs` (vulnerability sum):
   - Same CSV format as `-mpsa` but `--value-col` selects which column
     is the per-bank value contribution.
   - SP runs MPSICS as party 0; each sender as party i.
   - Output: single scalar (or vector for bucket histograms) written to
     `--out`.
6. Companion smoke: `tests/run_mpsa_vs_smoke.sh` with 3 banks + 25
   companies, verify SP receives correct sum.

### Session 4

7. **Bucket histogram mode**: multi-run MPSICS wrapper to produce a
   vector output (`--buckets 0.1,0.3,0.5,1.0`).
8. **Compound ratio mode**: two-scalar MPSICS pair for cross-bank
   ratios like `Σ loan / Σ income`, cleartext-divide post-reveal.
9. **Wire-protocol robustness**: MPSICS uses `coproto::asioConnect` —
   works but needs error handling parity with rest of MPSA (auth,
   session-id, AEAD wrapping). Bring under the T14 identity + T10
   threshold umbrella.
10. Deployment doc — regulator-facing operational spec.

### Session 5+ (later)

- Per-company aggregate-only scoring (`g(x, y, z)` inside MPC, aggregate
  outside) — full MPC path.
- Malicious security upgrade (corrected OKVS from
  ASIACRYPT'24 / eprint 2024/1989).
- Differential-privacy noise on the aggregate output (T8-style).

## What Session 1's `secureAddU64Bin`/`secureSubU64Bin` still buys

Those primitives are NOT wasted. They remain valid building blocks for:

- Secure operations on bit-shared values in future full MPC path
- Session 5+ per-company aggregate-scoring stage
- Any secure computation of nontrivial functions of secret shares

They just aren't the critical-path primitive for the double-blind
requirement — MPSICS is.

## What this design does NOT change

- The current `-mpsa` and `-mpsa vole` paths continue to exist. They
  serve a different threat model (SP allowed to see per-row plaintext).
- A-sum / A-mset-row integrity checks continue to guard the shuffle-
  based path.
- MPSO vendoring (Stage B) — the vendored MPSICS is what makes this
  entire design tractable.

## Non-goals

- Hiding intersection cardinality itself. SP knows |intersection| = C
  in MPSICS. Full C-hiding requires padding + DP noise; T8/`padCmax`
  scaffolding already exists in the tree but is not composed with
  MPSICS yet.
- Sender-attribution hiding for the aggregate. If SP knows N banks
  participated and one bank's contribution is uniquely detectable
  (e.g., only bank A operates in region X), aggregation across a small
  N can still reveal contributions. Standard DP mitigation applies.
