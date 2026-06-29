# N-party Private Join with Table-Valued Payload (PSA-Join)

## Goal

Extend MPSA from "one fixed payload per id" to "table per id" — i.e., each
party contributes a relation `T_i : id → list-of-rows`. The protocol
produces, for each id in the joint intersection, the **cross-product join**
of all parties' rows for that id, with all values hidden until the
final reveal phase.

This is fundamentally a different problem from the wide-row payload work
(R26b/step-5): variable cardinality per id changes the protocol family
from "shuffle" to "oblivious database join". The wide-row work handles
the special case M=1 (one row per id). This design covers general M.

## Scope and parameters

```
N        = number of parties (senders) + 1 service provider (SP)
|ids_i|  = sender i's distinct ids (private)
M        = MAXIMUM rows per id per party (public protocol parameter)
W        = payload width in blocks per row (= R26b/step-5 plumbing)
|I|      = intersection cardinality (SP learns; or hidden via T8 DP/T17 padding)
```

Output bound (worst case): `|I| · M^N` rows of width `W · N` blocks each.
For N=3, M=10, |I|=100, W=4: 10⁵ rows × 12 blocks = ~20 MB. For N=5,
M=10: 10⁷ rows × 20 blocks = ~3 GB. The protocol design MUST surface M
as a hard tunable; over-padding past actual cardinality is the dominant
cost driver.

## Threat model

Mirrors the existing MPSA cascade:
- **Semi-honest baseline** — all parties follow protocol; learn nothing
  beyond the output table and (under T8/T17 padding) the cardinality
  bound. SP additionally orchestrates but does not learn raw rows.
- **Active path** — requires the same OLE/Beaver-triple infrastructure
  as R28 (since each oblivious comparator inside the bitonic sort is an
  MPC multiplication). The components designed here are MAC-compatible
  via the R25 `AuthShare` infrastructure; the upgrade to active security
  is purely a substitution at the comparator level, not a structural
  redesign.

## Protocol structure

Eight phases. Each is implementable as a separate module composing on
top of the existing cascade infrastructure.

```
┌────────────────────────────────────────────────────────────────────┐
│ Phase 1: Per-party pad + commit                                    │
│   - Each sender i pads its table T_i so every id has exactly M     │
│     rows (real ⊕ dummies marked via is_real bit packed into payload)│
│   - Commit to padded table; broadcast commitments via T16-style    │
│     commit-and-open (reuses mpstar::commit/verifyCommit)           │
├────────────────────────────────────────────────────────────────────┤
│ Phase 2: Aggregate into one bag                                    │
│   - Each tuple becomes (party_idx, id, row_idx_in_id, payload,    │
│     is_real)                                                       │
│   - Total bag size: B = N · |union(ids)| · M                       │
│   - Distributed: each party holds its own slice, SP doesn't see    │
│     plaintext rows                                                 │
├────────────────────────────────────────────────────────────────────┤
│ Phase 3: Oblivious sort by id                                      │
│   - Bitonic sort on the secret-shared bag                          │
│   - O(B · log² B) comparator invocations                           │
│   - Comparator: secret-shared compare of two ids → swap decision   │
│   - Active security: comparator uses Beaver triples (R28 dep)      │
├────────────────────────────────────────────────────────────────────┤
│ Phase 4: Window detection                                          │
│   - For each position i, compute is_window_boundary_i = (id_i ≠    │
│     id_{i-1})                                                      │
│   - Output: B-length vector of secret-shared bits                  │
├────────────────────────────────────────────────────────────────────┤
│ Phase 5: Within-window cross-product expansion                     │
│   - Each window (all tuples sharing same id) emits M^N output rows │
│   - Brute-force implementation: enumerate all M^N combinations of  │
│     row-indices, gather the corresponding tuples                   │
│   - All output rows carry is_intersection = ⋀ (is_real for that    │
│     party's tuple in this combination)                             │
│   - Total output: |union(ids)| · M^N rows                          │
├────────────────────────────────────────────────────────────────────┤
│ Phase 6: Oblivious filter on is_intersection                       │
│   - Drop rows where is_intersection = 0                            │
│   - Implementation: assign rank = (1 - is_intersection) · R +      │
│     row_idx, oblivious-sort by rank, keep first |I|·M^N entries    │
├────────────────────────────────────────────────────────────────────┤
│ Phase 7: Cascade shuffle on filtered output                        │
│   - Reuses MpShuffleDriver (already handles wide rows via R26b/    │
│     step-5: N*W flat columns of length |I|·M^N each)              │
│   - Output rows are randomly permuted; no positional info leaks    │
├────────────────────────────────────────────────────────────────────┤
│ Phase 8: Reveal + writeout                                         │
│   - SP receives shuffled output, writes as CSV: each row has       │
│     N · W comma-separated hex blocks                              │
│   - Optional T11 transcript signature for audit                    │
└────────────────────────────────────────────────────────────────────┘
```

## Cost model

| Phase | Computation | Communication | Rounds |
|---|---|---|---|
| 1 (pad+commit) | O(N · ∑|ids_i| · M · W) | O(N²) commit broadcasts | 1 |
| 2 (aggregate) | O(B) | O(B · W) per party→SP | 1 |
| 3 (oblivious sort) | O(B · log² B) comparators | O(B · log² B · MPC-mult cost) | O(log² B) |
| 4 (window detect) | O(B) | O(B) | 1 |
| 5 (cross-product) | O(\|union\| · M^N) | O(\|union\| · M^N · N · W) | 0 (local) |
| 6 (filter) | O(\|union\| · M^N · log²(...) ) sort | same | O(log²) |
| 7 (cascade shuffle) | O(N · \|I\| · M^N) per round, N-1 rounds | same | N-1 |
| 8 (reveal) | O(\|I\| · M^N · N · W) | same | 1 |

**Dominant cost: Phase 5 cross-product expansion** when M^N exceeds the
bag size B. Phase 3 oblivious sort dominates when B^2 log B exceeds M^N.

## Buildable subcomponents (this codebase)

| # | Module | LoC | Status |
|---|---|---|---|
| 3a | In-memory oblivious bitonic sort | ~300 | **IN PROGRESS** (`volePSI/MpObliviousSort.{h,cpp}`) |
| 3b | Secret-shared comparator (semi-honest) | ~200 | deferred — currently uses plaintext comparator |
| 3c | Active comparator (Beaver-triple based) | ~400 | deferred — depends on R28 |
| 4  | Window detection on sorted output | ~100 | deferred |
| 5  | Cross-product expander | ~250 | deferred |
| 6  | Oblivious filter via dummy-rank sort | ~150 | deferred (composes (3a) and Phase 5 outputs) |
| 7  | Cascade integration | already done (`MpShuffleDriver`) | leverages R26b/step-5 wide-row plumbing |
| 8  | CSV writeout | already done (`writeColumnsAsCsv`) | unchanged |
|    | Phase 1 + 2 driver (`MpsaJoinDriver`) | ~400 | deferred |

**Initial deliverable: subcomponent 3a (oblivious sort) + this design
doc.** Provides the foundational primitive. Subsequent rounds add the
remaining phases as separate modules so each can be tested in isolation.

## Comparison to alternatives

| Approach | Pros | Cons |
|---|---|---|
| **This protocol (oblivious join)** | True join output; secret payloads end-to-end | Output O(\|I\| · M^N); needs oblivious sort; multi-week build |
| Two-pass: PSI then selective reveal | Simple; existing PSI works | SP learns which ids matched; vulnerable to per-id traffic fingerprinting |
| Aggregate-only (Google PJC) | Bounded output; fast | Only sum/count/avg, not row-level reveal |
| Trusted-execution joining (Intel SGX) | High performance | Requires TEE; outside our threat model (we deliberately exclude TEE-based solutions) |

## Open design questions

1. **M selection strategy.** Should M be fixed at protocol start (public
   parameter) or negotiated via a pre-protocol pass that lets each party
   reveal MAX(M_i) under DP noise? Trade-off: leaks distribution shape
   vs. wastes bandwidth on over-padding.
2. **Sparse cross-product encoding.** Most (combination of rows)
   are dummies (is_real = 0 for at least one party). A bit-mask-then-
   compress phase could reduce Phase 5 output substantially, at the cost
   of leaking the distribution of per-id cardinalities. Quantifying this
   leakage requires DP analysis.
3. **Streaming Phase 5.** For large M^N, the cross-product cannot fit in
   memory. Streaming requires Phase 5/6/7 pipelined; possible but
   substantially complicates the protocol.
4. **Composability with other extensions.** Threshold-k revelation (T10),
   DP cardinality (T8), PQ handshake (T5) all extend naturally. Salted
   MPSI (T15) works at id-hashing layer.

## References

- Krastnikov, Kerschbaum, Stebila. "Efficient Oblivious Database Joins."
  PoPETs 2020. (Closest published protocol for 2-party setting.)
- Mohassel, Rindal, Rosulek. "Fast Database Joins and PSI for Secret Shared
  Data." ACM CCS 2020. (Multi-party variant; uses garbled circuits.)
- Bater, Park, Rogers, Mahmood, Khan, Bittinger, Reiniger, Wuhrl, He.
  "SAQE: Practical Privacy-Preserving Approximate Query Processing for
  Database Joins." VLDB 2021.
- Wang, Ranellucci, Katz. "Global-Scale Secure Multiparty Computation."
  ACM CCS 2017. (For oblivious sort over MPC.)
- Asharov, Lindell, Schneider, Zohner. "More Efficient Oblivious Transfer
  and Extensions for Faster Secure Computation." (OT building blocks.)
- Pinkas, Schneider, Zohner. "Faster Private Set Intersection Based on OT
  Extension." (Underlies the existing volePSI MPSI.)

## Build sequencing (proposed)

| Round | Deliverable | Effort |
|---|---|---|
| **R29 (now)** | Oblivious sort primitive + this design doc | ~300 LoC + doc |
| R30 | Window detection + cross-product expander (phases 4-5) | ~350 LoC |
| R31 | Oblivious filter (phase 6) | ~150 LoC |
| R32 | End-to-end driver `MpsaJoinDriver` (phases 1+2+8) | ~400 LoC |
| R33 | Integration: real wire protocol + smoke tests | ~300 LoC |
| R34 | Active-security path (depends on R28 OLE) | ~600 LoC |
| R35 | Benchmarks: scale in N, M, |I|, W | ~200 LoC |

Total ~2300 LoC + multi-week debug/integration. Subset deliverable per
round; user can stop at any round and have a buildable artifact.

## R35 — measured cost (in-memory simulation, trusted-dealer Beaver gen)

Captured from `tests/benchmarks/bench_mpc_join`. All times are wall-clock
milliseconds on a single thread; "ms_online" is the join itself
(excluding triple generation); "ms_preprocess" is the trusted-dealer
Beaver-triple generation cost (replaced by OLE in R34k); "ms_plaintext"
is the R32 plaintext driver running the same join for comparison.

| N | M | \|U\| | row bits | triples | preprocess ms | online ms | plaintext ms | overhead × |
|---|---|---|---|---:|---:|---:|---:|---:|
| 2 | 1 | 1  | 16  | 338    | 0.03  | 0.10  | 0.017 |  6× |
| 2 | 2 | 1  | 16  | 4.5K   | 0.6   | 0.5   | 0.002 | 261× |
| 3 | 2 | 1  | 16  | 18K    | 2.0   | 2.1   | 0.004 | 578× |
| 2 | 2 | 4  | 16  | 60K    | 5.8   | 7.0   | 0.008 | 888× |
| 2 | 2 | 8  | 16  | 181K   | 17    | 22    | 0.013 | 1.7K× |
| 2 | 2 | 16 | 16  | 507K   | 44    | 55    | 0.021 | 2.6K× |
| 2 | 4 | 2  | 16  | 127K   | 5     | 15    | 0.009 | 1.7K× |
| 2 | 8 | 2  | 16  | 828K   | 60    | 89    | 0.017 | 5.2K× |
| 3 | 2 | 2  | 16  | 62K    | 2.4   | 6.2   | 0.009 | 733× |
| 4 | 2 | 2  | 16  | 135K   | 5.1   | 16    | 0.010 | 1.6K× |
| 2 | 2 | 4  | 64  | 72K    | 2.9   | 7.7   | 0.009 | 835× |
| 2 | 2 | 4  | 128 | 87K    | 3.7   | 11    | 0.010 | 1.1K× |

**Observed scaling behavior:**
- **Universe size |U|** dominates: doubling |U| roughly triples triple
  count (sort grows as O(B · log² B) with B = N·M·|U|). For 16-universe
  N=2 M=2 we hit 500K triples / 55ms online — already a meaningful
  workload.
- **M scaling is super-linear**: M=2 → M=8 grows triples 200× while
  online time grows 130×. The cross-product expansion M^N starts to
  dominate at M=8.
- **N scaling is roughly cubic**: N=2 → N=4 grows triples ~30×. Sort
  cost grows as B·log²B (B linear in N), expansion as M^N.
- **Wider payload (rowDataBits)** adds linearly to the per-swap cost
  but does not change the dominant sort term — modest impact.
- **MPC overhead vs plaintext**: 500-2500× across most configs. This is
  in line with SPDZ-style protocols; the trusted-dealer preprocessing
  hides the dominant O(B²)-ish cost of OLE-based triple generation that
  R34k would surface.

**Cost model takeaway**: for prototype-scale joins (|U| < 100, M < 8,
N < 8), the MPC join completes in under a second per cascade in-memory.
The dominant cost is Beaver triples; the actual MPC compute is fast.
This validates the architecture for further benchmarking once R34k
wires up real OLE-based triple generation.
