# DEPLOYMENT_FULL_MPC.md — Full-MPC Multi-Agency Vulnerability Score

**Status:** Governing plan.
**Supersedes for deployment work:** `DESIGN_VULN_SCORE.md`, `DESIGN_VULN_SCORE_V2.md`, and any
per-session implementation notes.
**Complements:** `PROBLEM_STATEMENT.md` (SVS problem lock), `THEORY_TDR.md` (theory framing).
**Authoritative spec (requirements):** the requirements document titled "Objective /
Participating parties / … / Required solution deliverables" that this plan traces to
as §1–§26.
**Authoritative spec (protocol):** `docs/PROTOCOL_PI_SECTORVULN.md` (Π_SECTORVULN Rev 6)
+ `docs/PROTOCOL_PI_SECTORVULN_R7.md` (Rev 7 deltas: R26 CDF-monotonicity clamp,
R27 conditional oblivious small-domain radix sort). When the plan below
references "Protocol §X" it means the composed Rev 6 + Rev 7 spec: sections
unchanged by Rev 7 use Rev 6; §8.2.1 (new) + §12 (R26 patched) + §16 (R28) +
§17 (R29, 14 blockers) use Rev 7. The plan's phases are the *implementation
milestones* that realise the composed spec.

Every future implementation session **MUST** open by declaring which section(s) of the spec and
which phase of this plan it targets, and **MUST** close by re-checking the acceptance criteria
listed against that phase. Deviations must be recorded explicitly at the bottom of this file.

---

## 0. Alignment check protocol (mandatory)

For every implementation session:

1. **Pre-flight.** State (a) which spec §s it addresses; (b) which phase (1–17) below it advances;
   (c) which existing code it modifies; (d) what it will *not* do.
2. **In-flight.** For any design decision, cite the spec § that governs it. If two spec sections
   conflict, escalate rather than choose silently.
3. **Post-flight.** Re-run the phase's acceptance criteria (below). Any failure blocks the session
   from being marked complete. Any deviation appends to the *Deviation Log* at the end of this
   doc, with justification and revised acceptance criteria.

Anti-patterns already observed (do not repeat):
- Building sector-level ratios and calling them "vulnerability score" — spec §17 requires
  entity-level ratios first, aggregated only via secure percentile.
- Using `MpsaDriver` row-level output for entity-level scoring — spec §3 forbids per-entity
  release; the existing `PROBLEM_STATEMENT.md §6` already excluded this path.
- Reading plaintext CSV to compute "ratios from ground truth" as if it were a PSA output —
  spec §3 forbids any plaintext leakage; §7 requires cryptographic PSA.
- Introducing DP as the primary defence — spec §21 permits DP *only* after secure aggregation,
  as an optional final release-side layer.
- **Using PSI-AD (PSI with payload) or any PSI that reveals match status.** Spec §3
  forbids match-status disclosure; alignment must happen inside the SP-aided protocol on
  masked / secret-shared records, never on the wire as an interactive PSI. See Phase 2.
- **Using ≥3-node MPC farms** (3-party replicated, N-node SPDZ with N≥3, garbled-circuit
  farms, honest-majority BGW, etc.). **The aggregate-only path** uses the PSA-paper
  single-SP topology (1 SP + K clients). **The SectorVuln entity-level path** uses a
  two-domain (S1+S2) MPC per `PROTOCOL_PI_SECTORVULN.md §0` — this is a documented
  exception justified by needing secure division + secure percentiles on secret n_valid,
  which exceeds the single-SP utility boundary. Neither path uses ≥3 compute nodes.
  See Phase 3.

---

## 1. Stakeholders and trust boundaries (spec §2)

Topology matches the PSA-paper deployment: **star with 1 SP + K clients + workflow
orchestrator** for aggregate-only paths, extended to **two computation domains (S1 + S2)
for SectorVuln entity-level paths** per `PROTOCOL_PI_SECTORVULN.md §0`. Neither path
uses a ≥3-node MPC farm.

| Party | Class | Data held | Learns | Constraint |
|---|---|---|---|---|
| MAS | Client (data input) | loan/credit attributes | Nothing entity-level | May not learn unapproved DOS/MOM attributes |
| DOS | Client (data input) | income / economic attributes | Nothing entity-level | May not learn MAS loan-membership |
| MOM | Client (data input) | manpower attributes | Nothing entity-level | May not learn MAS loan-membership |
| **SP** (aggregate-only path) | Server-aided compute + orchestrator | Masked / secret-shared messages; final disclosure-controlled aggregate | Only §22 output | Cannot reconstruct any entity value alone |
| **S1** (SectorVuln path) | MPC compute node, GovTech-operated infra | 2-of-2 share of every protected value; own DKG share `k1` | Nothing entity-level — sees only its shares + opened public differences | See `Protocol §0`; non-collude with S2 |
| **S2** (SectorVuln path) | MPC compute node, independent operator | 2-of-2 share of every protected value; own DKG share `k2` | Nothing entity-level | See `Protocol §0`; non-collude with S1 |
| GovTech (GT) | Workflow orchestrator (out-of-band) | None entity-level | Workflow state, version attestations, disclosure-controlled outputs. In SectorVuln, receives shares from S1 and S2 at output opening (Protocol §12.1) and combines them; never holds any single share alone. | Per spec §2: may not receive plaintext IDs, entity records, matched/unmatched lists, MAS loan-membership, or reconstruction-sufficient shares |
| External consumer | Reader | Only released sector-level rows | §22 schema | No entity-level data ever |

**SP identity.** The SP may be MAS itself (natural for supervisory outputs), an approved
independent trustee, or in principle GovTech provided the workflow-orchestrator role and
the SP role are cleanly separated (spec §2 restricts GovTech from seeing entity-level
data or reconstruction-sufficient shares, so SP-as-GovTech only works if SP-side blinding
is strong enough to satisfy those constraints). Choice is a policy decision; the protocol
is agnostic.

**Trust model.**
- SP is *honest-but-curious* in the baseline (semi-honest, spec §4): follows the protocol
  but tries to infer from received messages. Client blinding (SPDZ-style masks, OSN shares,
  Beaver-triple openings that reveal only differences) keeps SP blind to inputs.
- Clients are semi-honest. Any single client colluding with SP reveals only what SP + that
  one client's own inputs already imply (which is only that one client's own set).
- Malicious upgrade (Phase 17) hardens SP: signed transcripts, MACs on shares to SP, ZK
  proofs on ratio-computation gates, verifiable aggregate.
- **Max tolerated collusion** for the semi-honest baseline: SP + up to K-1 clients (any
  single honest client suffices to keep its own data private, thanks to secret-sharing +
  masking). Malicious-secure upgrade preserves this bound.

---

## 2. Security objectives (spec §3, §4)

The protocol must prevent ANY party from learning:

- Whether a specific entity is present in another party's dataset (**membership hiding**).
- Any entity-level value or ratio (**no per-entity release**).
- Match status of any specific entity (**no match-flag leakage**).
- Source-specific matched counts.
- Sizes/positions/timings/errors that reveal membership.

Additional invariants:

- **Zero-payload ≠ non-membership.** A protected 0 must be indistinguishable from a real 0 or an
  absent record, up to the disclosure-controlled aggregate.
- **Loan-membership and loan-value are separate protected values.**
- **Fresh session id + fresh nonces + fresh randomness per execution.**
- **All comms mutually authenticated + encrypted.**

**Baseline:** semi-honest, N–1 collusion of data-input parties; MPC-node collusion capped by chosen
protocol (3-party replicated → 1 corruption; SPDZ → any minority under MACs).

**Malicious upgrade path** (spec §4, addressed in Phase 17): input-consistency checks, MACs over
shares, ZK for select gates, verifiable computation, transcript validation.

---

## 3. End-to-end architecture (spec §5)

```
[Client agencies]                 [SP — single server, server-aided]   [Disclosure]
                                                                                    
  Local prep                                                                        
  ────────                                                                          
  select approved fields                                                            
  normalise ID              ── blind OPRF query ──▶   SP holds K_run
  standardise sector           (id blinded by r)  ◀── y' = OPRF(K_run, x')
  encode payload            (agency unblinds → handle)                              
  fixed-length pad                                                                  
                                                                                    
  ─── client peer-mesh  ────────────────────────────────                            
        (MpStarChannel)                                                             
   Additive-share (handle, payload, membership_bit) across the K clients            
   (K(K-1)/2 pairwise sockets; dummies fill each agency's B slots)                  
                                                                                    
                                    ▼                                               
                        ┌──────────────────────────────┐                            
                        │ SP-orchestrated OSN cascade  │                            
                        │ (MpShuffleDriver pattern)    │                            
                        │ obliviously sorts records by │                            
                        │ handle so same-entity        │                            
                        │ records go adjacent          │                            
                        │ — SP sees only masked routes │                            
                        └───────────────┬──────────────┘                            
                                        │                                           
                        ┌───────────────┴──────────────┐                            
                        │ Client-mesh secure comp:     │                            
                        │  adjacent-equality           │                            
                        │  → alignment_bit (shared)    │                            
                        │  inclusion_bits              │                            
                        │  ratio_computation (13, §13) │                            
                        │  winsorisation (§15)         │                            
                        │  percentile-rank norm  (§16) │                            
                        │  weighted composite    (§18) │                            
                        │  missing-comp policy   (§19) │                            
                        │ (SP orchestrates rounds;     │                            
                        │  SP sees Beaver openings +   │                            
                        │  OSN traffic only)           │                            
                        └───────────────┬──────────────┘                            
                                        │                                           
                        ┌───────────────┴──────────────┐                            
                        │ SP-aided aggregation:        │                            
                        │  per (sector_code, period):  │                            
                        │  count / sum /               │                            
                        │  ratio-of-sums /             │                            
                        │  p25 / p50 / p75             │                            
                        │  (MPSICS-style reduction)    │                            
                        └───────────────┬──────────────┘                            
                                        │                                           
                                        ▼                                           
                        ┌──────────────────────────────┐                            
                        │ Disclosure control (at SP):  │                            
                        │  k-anon suppression          │                            
                        │  complementary suppression   │                            
                        │  dominance                   │                            
                        │  differencing tracker        │                            
                        │  optional DP                 │                            
                        └───────────────┬──────────────┘                            
                                        │                                           
                                        ▼                                           
                             sector-level rows (§22)                                
                             ─────────────────────────▶ RELEASE
                                                                                    
  GovTech:  out-of-band workflow orchestration; NEVER holds any share, handle,      
            payload, or match status; only receives the disclosure-controlled      
            release rows and version attestations (spec §22).                       
```

**No PSI on the wire.** Handle emission is server-aided blind OPRF: agency sends blinded
`x'`, SP returns `y' = OPRF(K_run, x')`, agency unblinds locally. SP sees only blinded
queries; agencies learn handles only for their own ids. All records (real + dummy) then
enter the client peer-mesh as additive shares. Alignment happens via SP-orchestrated OSN
sort + client-mesh secret-shared equality; membership stays a secret bit throughout.

**Internal grain (§10):** `protected_entity_handle` + `sector_code` + `reporting_period`
**External grain (§10):** `sector_code` + `reporting_period` (+ metric_name per §22)

---

## 4. Existing codebase inventory (with spec mapping)

| Existing module | Purpose | Spec section fits | Reusable? |
|---|---|---|---|
| `MpSecretShare` (SharedU64 additive) | Party-indexed additive shares over ℤ₂⁶⁴ | §8 payload protection, §11 join, §20 aggregation | YES |
| `MpBeaverTriple` (SPDZ-style) | Multiplication of shared values | §11 join, §13 ratios (via divide), §16 ranking | YES |
| `MpSecureCompare` (SharedU64Bin, `secureLessThan`) | Comparisons on XOR-shared bits | §16 rank, §17 percentile, §12 range checks | YES |
| `MpMpcArithmetic` (`secureAddU64Bin`, `secureSubU64Bin`, `secureDivideU64Bin`) | Bit-share arithmetic including division | §13 ratios (all 13 formulas divide), §16 normalisation | YES — primary vehicle for §13 |
| `MpMpcSort` (MPC bitonic sort on `(key, payload)` shares) | Fully SP-blind sort | §17 percentile, §16 rank | YES |
| `MpObliviousSort` | Structurally oblivious bitonic net | §17 backend when payload is public | YES |
| `MpMpcJoin` | Sort-based MPC join under composite key | §11 secure join | YES |
| `MpMpcWireOps`, `MpMpcWireDriver` | 2-party wire-level primitives (real-world MPC) | Any 2-party protocol variant | YES for 2-party; extend for 3-of-N |
| `MpOira` (MPSIC + MPSICS + k-anon + Laplace) | Sector aggregate output | §20 aggregation, §21 disclosure (partial) | PARTIAL — supports one aggregate release path but not the entity-level ratios upstream |
| `MpOiraBudget` | Composition guard across releases | §21 disclosure control (repeated releases) | YES |
| MPSICS / MPSIC (vendored) | Cardinality + sum over intersection | §20 aggregation for one code path if kept | NO for this deployment — reveals match structure, incompatible with the "alignment inside MPC" design |
| `MpsaDriver` / `MpShuffleDriver` (row-level cascade) | Anonymised row-level release | NONE for this deployment (spec §3 rules out per-entity release) | NO for vuln score |
| `MpPedersen`, `MpPedersenVector` | Commitments, vector commitments | §7 input consistency commit, §24 audit attest, §17 quantile commit | YES |
| `MpAuthCascade`, `MpMac` | Auth cascade primitives, MACs | §4 malicious path (SPDZ MAC extension), §21 attribution | YES for Phase 17 |
| `MpSpHandshake`, `MpHybridHandshake`, `MpKem`, `MpStarCrypto` | Authenticated key agreement, hybrid PQ | §4 comms auth, §7 OPRF session keys | YES |
| `MpStarChannel` | Peer-mesh channel | Any multi-party comms | YES |
| `MpTranscript` | Signed transcript record | §24 audit | YES |
| Set primitives: `RsMpsi`, `RsMpsiVole`, `RsSimpleHashPsi`, `RsCpsi` | Two-party PSI (VOLE-based) | **NOT as PSI.** VOLE-OPRF from `RsMpsiVole` may be reused as an OPRF backend for handle emission (Phase 2). The PSI-with-payload / PSI-AD path itself is rejected — reveals match status | PARTIAL — OPRF backend only |

**Prior design docs (still authoritative unless stated):**
`PROBLEM_STATEMENT.md`, `THEORY_TDR.md`, `PRIVATE_JOIN_DESIGN.md`, `MPC_WIRE_DESIGN.md`,
`COMPOSITE_SECURITY_THEOREM.md`, `OIRA_THREAT_MODEL.md`, `OIRA_CONSTRUCTION.md`,
`MALICIOUS_UPGRADE_ROADMAP.md`, `MALICIOUS_CASCADE_DESIGN.md`, `SECURITY_ANALYSIS.md`.

**Prior design docs superseded for vuln-score deployment:**
`DESIGN_VULN_SCORE.md` (session-2 revision), `DESIGN_VULN_SCORE_V2.md`, all session 10–23
per-file notes generated in the current conversation.

---

## 5. Gap analysis (what is NOT yet built)

Numbered against spec sections:

| Gap ID | Spec § | Description | Blocker for |
|---|---|---|---|
| G-A | §6 | Deterministic ID normalisation is not centrally specified; each agency must run the *same* function under an agreed pepper/salt | PSA phase |
| G-B | §7 | Server-aided blind-OPRF module (SP holds `K_run`; agencies blind-query). Not distributed-key MPC — this is the single-SP model. Existing MPSI code path reveals match to P₀ and is not reusable here. | Phase 2 |
| G-C | §7 | Per-run `K_run` generation at SP + Pedersen-commit publication + fresh session id + KDF context wiring | Phase 2, 3 |
| G-D | §8 | Fixed-length padded payload schema (per-source) not defined; must be indistinguishable across membership | Phase 1 |
| G-E | §8 | Secret-shared `membership_bit`, `validity_bit`, `non_missing_bit`, `inclusion_bit` machinery | Phase 5 |
| G-F | §9 | Protected-union alignment (bucket size, padding size) design; needed if intersection-count leakage is unacceptable | Phase 2 |
| G-G | §10 | Sector reconciliation rule under MPC (authoritative source / secure majority / mapping table / protected exception flag) | Phase 4 |
| G-H | §12 | Secure denominator-validity gate (zero / negative / missing / out-of-range) with protected exclusion | Phase 5 |
| G-I | §13 | Wiring of the 13 ratio formulas onto `MpMpcArithmetic` / `MpMpcDivide` with fixed-point semantics | Phase 6 |
| G-J | §14 | Correlation analysis pipeline before finalising component set | Phase 6/9 |
| G-K | §15 | Secure winsorisation | Phase 7 |
| G-L | §16 | Percentile-rank normalisation under MPC (sort + rank + inversion for inverse indicators) | Phase 8 |
| G-M | §17 | Secure percentile (p25/p50/p75) with linear interpolation and tie handling, using oblivious sort | Phase 10 |
| G-N | §18–19 | Weighted composite + missing-component policy under MPC; weight versioning | Phase 9 |
| G-O | §20 | Secure aggregation formatted to output schema; inclusion-bit-gated | Phase 11 |
| G-P | §21 | Disclosure-control layer with k-anon suppression, complementary suppression, dominance rules, differencing tracker; optional DP | Phase 12 |
| G-Q | §22 | Output schema serialiser with strict field allow-list | Phase 13 |
| G-R | §23 | Validation-rule harness | Phase 16 |
| G-S | §24 | Audit-log format and versioning glue | Phase 14 |
| G-T | §25 | Failure-handling policy: generic external errors, protected diagnostics | Phase 15 |
| G-U | §4 | Malicious upgrade wiring (auth-share, ZK, verifiable comp) | Phase 17 |
| G-V | §5 | **Single-SP server-aided topology** matching the PSA paper embodied in this codebase. No N-node MPC farm. Extensions: SP driver for entity-level ratio round (Phase 6), SP driver for percentile computation (Phase 10). See Phase 3. | Phase 3, 6, 10 |

---

## 6. Phased plan

### Phase 1 — Local Preparation & Payload Schema  *(spec §6, §8, §12 partial)*

**Goal.** Each agency (MAS, DOS, MOM) produces a locally-validated,
fixed-length, membership-hiding payload package ready for PSA input.

**Sub-tasks.**
1. Formal payload schema per source (structured type; all fields required; zero-value = valid;
   missingness encoded separately from numeric zero).
2. Deterministic ID normaliser: single function, versioned, MUST be identical across agencies;
   input = agency-native id, output = canonical byte string of fixed length.
3. Local validation: reporting period, sector code space, denominator range checks, duplicate
   removal (per entity+period), unit standardisation, annualisation.
4. Local encoding: pack payload into fixed-length record with:
   - `membership_bit` (real vs. dummy)
   - `non_missing_bit_field` (one bit per numeric attribute)
   - `validity_bit_field` (one bit per numeric attribute — passes range checks)
   - numeric attributes as fixed-point u64 (scale + max defined per attribute)
   - reporting_period canonical form
   - sector_code canonical form
5. Padding to indistinguishable length: pad with dummies to a per-run bucket size (see Phase 2).

**Existing code reused.** Nothing central; touch new module `MpsvsLocalPrep` (draft naming).

**Acceptance criteria.**
- [ ] Schema encoded as C++ struct + Python parser; sizes fixed.
- [ ] Two records with different membership status but identical field types produce
      byte-identical externally-visible envelopes.
- [ ] Same entity fed through the ID normaliser at MAS, DOS, MOM produces identical bytes.
- [ ] Range-invalid inputs produce `validity_bit = 0`, never runtime error, never zero
      substitution.
- [ ] Missing inputs produce `non_missing_bit = 0`, never zero substitution.

**Deps.** None. **Estimated sessions.** 2.

---

### Phase 2 — Protected Alignment (NO PSI)  *(spec §7, §9; Protocol §2 DKG + §3 VOPRF)*

**Design decision (this doc):** we do **NOT** use PSI-with-payload (PSI-AD) or any PSI
variant that reveals match status. PSI-AD is out because it leaks membership by design
(the receiver learns which entities matched). Full spec-§3 membership hiding requires that
alignment happen **entirely inside MPC on secret-shared records**, with no party ever
observing which handles overlap.

**Protocol reference.** Concrete construction: `PROTOCOL_PI_SECTORVULN.md`:
- §2 ThresholdDKG — two-server multiplicative DKG (S1: k1, S2: k2 = k1·k2 published as Y).
- §3 TagRecords — sequential DH-VOPRF with dual-tag (tag1, tag2), context-bound
  finalisation, DLEQ per hop, dummy padding, metering. Includes **PROOF OBLIGATION 3.A**
  (custom construction; one-more-gap-CDH in ROM; freeze blocker §17.1).
- H1 = RFC 9497 `ristretto255-SHA512`; H2 = SHA-256 with mandatory 16-byte domain prefix.

**Goal.** Produce a common `protected_entity_handle` per record such that same-entity
records across agencies collide on the same handle byte string, then push the entire
(handle, payload) universe into secret shares in the MPC domain. No PSI runs on the wire.

**Sub-tasks.**
1. **SP-held run-specific OPRF key `K_run`.**
   - SP generates `K_run` at start of each run; a Pedersen commitment to `K_run` is
     published to all agencies so `K_run` is bound (SP cannot swap it mid-run).
   - `K_run` is fresh per run so different runs produce unlinkable handles (spec §7).
2. **Server-aided OPRF (blind evaluation).** For each id at each agency:
   - Agency computes a blinded query `x' = OPRF_client_blind(id, r)` for fresh random `r`.
   - Agency sends `x'` to SP over an authenticated encrypted channel; SP evaluates
     `y' = OPRF_server(K_run, x')` and returns `y'`.
   - Agency unblinds: `handle = OPRF_client_unblind(y', r)`.
   - SP sees only blinded queries (statistically hides `id`); agency learns only its own
     handles.
   - Backend: 2HashDH / DDH-based OPRF (elliptic-curve, e.g., Ristretto255) or VOLE-OPRF
     from `RsMpsiVole` (both give the required blind-eval property).
3. **Client peer-mesh SPDZ upload.** Once agencies have their handles, they commit to their
   full record set in the star-topology mesh:
   - Additive shares of `(handle, payload, membership_bit=1)` split across the K clients
     (each client holds one share of every record from every other client).
   - Dummies fill each agency's contribution up to bucket size `B` so per-agency set sizes
     are hidden (spec §9).
   - SP receives NO shares of the record contents; SP only sees the OSN-cascade traffic
     in Phase 4 (which is masked).
4. **NO PSI wire step.** The alignment is not a PSI protocol between agencies; it's the
   OPRF determinism (same id → same handle across agencies) plus the fact that all
   records exist as client-side additive shares. Same-entity records will collide on
   handle values inside the shared representation; collision detection is done obliviously
   in Phase 4 via an SP-orchestrated OSN cascade + secret-shared adjacent-equality.
5. **Bucket / padding sizes (spec §9):** each agency uploads exactly `B` records per run,
   where `B` is a publicly agreed upper bound on any single agency's population for that
   period. Dummies fill the remainder. This hides exact per-agency set sizes and,
   downstream, exact intersection sizes.

**Existing code reused.** `MpSpHandshake` / `MpHybridHandshake` / `MpKem` / `MpStarCrypto`
(SP↔agency auth); `MpStarChannel` (agency peer-mesh); `MpPedersen` /
`MpPedersenVector` (commit-and-open for `K_run` binding + Phase 17 input consistency);
`RsMpsiVole` **only as OPRF backend** (VOLE-OPRF suits Phase 2's blind-eval requirement),
not as a PSI protocol. Existing OSN gear (`MpShuffleDriver`, `benes`, `OSNSender`,
`OSNReceiver`) is used by Phase 4, not by Phase 2 itself.

**Missing.**
- Server-aided blind-OPRF module (`MpOprfServerSide` — new).
- Client blind/unblind wrapper for the chosen OPRF backend.
- SP-side `K_run` generation + Pedersen-commit publication.
- Bucket-size orchestration and dummy generation on the client side.

**Acceptance criteria.**
- [ ] For a given (run_id, entity), all agencies that hold that entity locally derive the
      same handle bytes via SP-aided blind OPRF.
- [ ] The handle cannot be linked back to source id without `K_run`.
- [ ] Different runs of the same entity produce unlinkable handles.
- [ ] SP sees only blinded queries and encrypted transport; SP never sees an id, a
      payload, or an unblinded handle.
- [ ] GovTech never sees any handle, payload, share, match status, or query.
- [ ] No PSI protocol runs on the wire; only per-agency blind-OPRF round + share uploads
      in the client mesh.
- [ ] Each agency's upload size equals exactly `B` records regardless of its true set
      size.
- [ ] Documented threat sheet: for each party (agencies, SP, GovTech), what
      set-size / intersection-size / membership signals leak.

**Deps.** Phase 1 for schema, initial Phase 3 for SP process. **Estimated sessions.**
2–3 (backend selection + blind-OPRF wiring + commit-bind for `K_run`).

---

### Phase 3 — Compute Topology (aggregate: single-SP; SectorVuln: two-domain)  *(spec §4, §5; Protocol §0)*

**Design decision (this doc):** two topologies, applied per computation class:

- **Aggregate-only path (cardinality, sum, ratio-of-sums when denominator is public):**
  PSA-paper star — 1 SP + K clients + peer-mesh. Reuses `MpsaDriver`,
  `MpShuffleDriver`, MPSICS, OIRA, `MpStarChannel`.
- **SectorVuln entity-level path (all Π_SECTORVULN):** two computation domains S1 + S2
  as specified in `PROTOCOL_PI_SECTORVULN.md §0`. Two-of-two additive shares over
  Z_{2^k} with `(k, f, guard) = (128, 40, 8)` prototype defaults (Protocol §9).

**Neither path is a ≥3-node MPC farm.**

Rationale:
- The PSA paper's whole point is one SP + K clients — reusing it means no substrate
  rewrite; every existing module (`MpsaDriver`, `MpShuffleDriver`, OIRA, MPSICS,
  `MpStarChannel`, `MpStarCrypto`, cascade shuffles, A-sum/A-mset-row integrity) is
  directly applicable or extensible to the aggregate-only path.
- Three-plus-node MPC farms require operational separation of ≥3 independent compute
  operators — a governance overhead this deployment doesn't have.
- For SectorVuln entity-level (Protocol §7-§13), single-SP hits three utility limits
  documented in Protocol §0: (i) secure division under Beaver + Goldschmidt forces the
  SP into the reciprocal's error path; (ii) secure percentiles over secret n_valid need
  oblivious sort of shared (key, payload) pairs, cleaner across two separate domains;
  (iii) ratio-of-sums with secret denominator (Protocol §10) requires dividing shared sums
  by shared count. Two-domain (S1, S2) resolves all three at the cost of one added domain
  and the non-collusion assumption between them.

**Goal.** Wire the SP-aided topology so that:
- Every message SP receives is either encrypted, secret-shared, XOR-masked, OSN-shuffled,
  or Beaver-triple-opened as a public difference (revealing nothing about inputs).
- Clients hold their own inputs plus shares/masks exchanged via `MpStarChannel` peer mesh.
- SP's total view is (public parameters) + (masked messages) + (final disclosure-controlled
  output); nothing else.

**Sub-tasks.**
1. **Adopt the deployed topology as-is.** SP process + K sender/client processes, all
   started via a shared orchestration script (existing pattern: `tests/run_oira_probe.sh`,
   `tests/run_mpsa_smoke.sh`).
2. **Client peer-mesh via `MpStarChannel`.** Already present; K(K-1)/2 authenticated
   pairwise sockets for Phase 0 mask handoff, Beaver-triple share exchange, and any
   direct-peer step in the vulnerability pipeline.
3. **SP protocol role.** SP:
   - Runs the OPRF blind evaluator (Phase 2) using a run-specific key it holds. Blinding
     ensures SP sees only blinded queries, not client ids.
   - Orchestrates the OSN cascade for oblivious sort (Phase 4) using the deployed
     `MpShuffleDriver` pattern (post-A1-fix: sender-private routing seeds, SP never
     learns any dest_k).
   - Aggregates per-sector counts/sums (Phase 11) using MPSICS-style share reduction.
   - Executes disclosure-control gate (Phase 12).
   - **Never opens Beaver triples on its own; never reconstructs a share without
     concurrent client acknowledgement; never sees any client's plaintext id or payload.**
4. **Correlated randomness for entity-level compute** (Phase 6): Beaver triples generated
   in a client peer-mesh preprocessing step (existing `BeaverTriplesGen`), consumed in
   SP-orchestrated online phase. SP receives only the differences opened during Beaver
   multiplication (which reveal nothing about the operands).
5. **Malicious upgrade path (Phase 17):**
   - MACs on client→SP messages (`MpMac`).
   - Signed transcripts (`MpTranscript`) for post-hoc audit.
   - A-sum / A-mset-row style integrity checks around the OSN cascade (already deployed
     in `MpsaShuffleIntegrity`).
   - ZK on OPRF evaluation correctness.

**Existing code reused (directly applicable, minimal wiring).** `MpStarChannel` (client
peer-mesh), `MpStarCrypto` / `MpHybridHandshake` / `MpKem` (SP↔client authenticated
channels), `MpSpHandshake`, MPSIC / MPSICS (SP-aided aggregation), `MpShuffleDriver`
(SP-orchestrated OSN cascade), `MpsaShuffleIntegrity` (A-sum/A-mset-row integrity),
`MpAuthCascade` / `MpMac` (Phase 17), `MpTranscript` (Phase 17), `MpBeaverTriple`
(Phase 6 multiplication), `MpSecretShare` / `MpSecureCompare` / `MpMpcArithmetic` /
`MpMpcSort` / `MpMpcJoin` (all consumed inside SP-orchestrated online sessions).

**Missing.**
- SP-side OPRF blind evaluator wiring (Phase 2 subtask).
- SP orchestration for entity-level ratio (Phase 6): the deployed OIRA is aggregate-only;
  entity-level round needs a new SP driver that pipes shares through `MpMpcArithmetic` +
  `MpMpcSort` + winsorisation without any per-entity reveal.
- SP-side percentile driver (Phase 10) using `MpMpcSort` outputs.

**Acceptance criteria.**
- [ ] SP's transcript across a full run is auditable and shown to contain zero plaintext
      of any client id, payload, ratio, or entity-level intermediate.
- [ ] Removing SP breaks the protocol (no client-only completion path); removing any one
      client breaks that client's contribution but the others complete gracefully with a
      generic external abort per spec §25.
- [ ] Beaver triples per session are freshly generated in a client peer-mesh phase; no
      reuse across runs.
- [ ] GovTech (as workflow orchestrator, distinct from SP) verified to have no share of
      any protected value at any point.

**Deps.** None functionally, but pairs with Phase 2. **Estimated sessions.** 2 (much of
this is verifying existing SP-aided modules satisfy the new acceptance criteria).

---

### Phase 4 — Server-Aided Oblivious Alignment  *(spec §10, §11; Protocol §5 Union, §6 GrowthAlign)*

**Goal.** Given the three per-source client-side additive-shared record streams from
Phase 2 (each of size `B` including dummies), align records with the same `handle` and
`period` without SP ever seeing plaintext handles and without any party learning which
handles overlap. The output is a single stream of "aligned triples" (MAS + DOS + MOM
contribution per handle), still fully shared.

**No PSI on the wire.** Alignment uses an SP-orchestrated OSN cascade (the deployed
`MpShuffleDriver` pattern) to obliviously bring same-handle records adjacent, then
secret-shared adjacent-equality (in the client peer mesh) derives the `alignment_bit`.
SP sees only OSN-masked message traffic.

**Sub-tasks.**
1. **Compose the record stream.** Concatenate the `3B` records from Phase 2 into a single
   stream, ordered by public position (not by handle). Each record is a client-side
   additive-share tuple.
2. **SP-orchestrated OSN cascade sort.** Reuse `MpShuffleDriver`'s N-column cascade
   pattern to obliviously sort by `key = handle || period_tag || source_tag`. Sender-
   private routing seeds ensure SP never learns the sort permutation (A1-fix invariant).
   The MPC-sort variant `MpMpcSort` runs the comparator gates on client shares; SP sees
   only OSN routing traffic.
3. **Adjacent-equality detection in the client mesh.** For each triple of adjacent
   records at positions `(3i, 3i+1, 3i+2)`, clients compute `alignment_bit` via
   `secureAnd` on secret-shared bitwise equality of `handle || period`. Result is a
   client-shared secret bit per triple.
4. **Dummy propagation.** A Phase-2 record with `membership_bit=0` carries a random
   handle. Random handles collide with real handles only with negligible probability. Any
   `alignment_bit=1` triple with a dummy component still passes to Phase 5, where the
   source's `membership_bit` gates inclusion.
5. **Sector reconciliation (spec §10).** Default: authoritative source (e.g., MAS-first,
   fall back to DOS). Implement as a shared conditional select on per-source `sector_code`
   shares. Sector-conflict → shared boolean flag, never revealed per-entity.
6. **Duplicate-inflation guard (spec §11).** Within a single source, `(handle, period)`
   must be unique. Adjacent-equality within same-source runs after sort → abort with
   generic external error on collision (spec §25).
7. **Oblivious throughout.** SP's view: only OSN routing packets (bit-masked). Client
   mesh traffic: only Beaver-triple openings (public differences that reveal nothing).

**Existing code reused.** `MpShuffleDriver` (SP-orchestrated OSN cascade),
`MpsaShuffleIntegrity` (A-sum / A-mset-row integrity, useful for Phase 17 malicious SP),
`MpMpcSort` (comparator gates on shares), `MpSecretShare`, `MpBeaverTriple`
(adjacent-equality via `secureAnd`), `MpSecureCompare` (bitwise equality).

**Missing.**
- Adjacent-equality wrapper over triples, integrated with the OSN cascade output.
- Sector-reconciliation shared conditional-select subprotocol.
- Duplicate-detection routine + generic-abort path.

**Acceptance criteria.**
- [ ] SP transcript across the entire Phase 4 contains only OSN routing packets and
      timing; zero plaintext handles, zero plaintext bits about which triples are aligned.
- [ ] Message sizes and control flow depend only on `3B` (public), not on match status.
- [ ] Duplicate `(handle, period)` at any source triggers a generic external abort with
      no reveal of which source or entity duplicated.
- [ ] Sector conflicts across agencies do not leak per-entity (shared exception flag
      only).
- [ ] `alignment_bit` remains a client-side secret share throughout Phases 5–11; Phase 12
      disclosure control only sees aggregates gated by it.

**Deps.** Phases 2, 3. **Estimated sessions.** 2.

---

### Phase 5 — Validity, Missingness, and Inclusion Bits  *(spec §12; Protocol §7 inclusion masks)*

**Goal.** For every protected value in a joined record, maintain the secret bits that gate
inclusion in each downstream ratio.

**Sub-tasks.**
1. Per-source secret bits carried in payload (Phase 1) get promoted to MPC secret bits;
   the per-triple `alignment_bit` from Phase 4 is included.
2. `inclusion_bit_for_ratio_i = alignment_bit × MAS_membership × DOS_membership ×
   MOM_membership_iff_needed × validity_num_i × validity_denom_i × non_missing_num_i ×
   non_missing_denom_i × denominator_in_range_i`.
3. Denominator-in-range subprotocol: `secureLessThan(denom, min)` OR
   `secureLessThan(max, denom)` → `validity = 0`.
4. Missing → NEVER zero substitution. Excluded ratios contribute nothing (both to numerator
   and to sample count for percentiles).
5. Bits remain secret-shared throughout; inclusion status of any entity is never revealed.

**Existing code reused.** `MpSecureCompare::secureLessThan`, `MpBeaverTriple::secureAnd`,
`MpMpcArithmetic::secureAddU64Bin`.

**Missing.** Structured "ratio operand" record type (num_share, denom_share, inclusion_share);
range-check subprotocol against configurable min/max per attribute.

**Acceptance criteria.**
- [ ] For every ratio, a per-entity inclusion bit is produced under MPC and never revealed.
- [ ] Aggregate counts computed downstream match the count of `inclusion_bit=1` entities,
      not the count of members.
- [ ] Missing / zero / negative / out-of-range denominators are excluded, not sanitised.

**Deps.** Phase 4. **Estimated sessions.** 2.

---

### Phase 6 — Secure Entity-Level Ratio Computation  *(spec §13; Protocol §6 growth, §7 metrics, §8.1.1 Goldschmidt)*

**Goal.** For each entity (via `protected_entity_handle`), compute all approved ratios as
secret shares.

**Ratios (spec §13):**
1. `debt_to_income = total_outstanding_debt / annual_income`
2. `income_to_debt = annual_income / total_outstanding_debt` *(descriptive; not composed if 1 present)*
3. `debt_service_to_income = annual_debt_service / annual_income`
4. `debt_to_employment = Σ_sector debt / Σ_sector employment` *(sector-level formula)*
5. `income_per_worker = Σ_sector income / Σ_sector employment` *(sector-level)*
6. `employment_rate = employed / labour_force`
7. `unemployment_rate = unemployed / labour_force`
8. `delinquency_ratio = delinquent / total_debt`
9. `npl_ratio = nonperforming / total_debt`
10. `unsecured_debt_share = unsecured / total_debt`
11. `short_term_debt_share = due_12m / total_debt`
12. `employment_contraction = max(0, -(cur-prev)/prev)`
13. `income_contraction = max(0, -(cur-prev)/prev)`
14. `debt_income_growth_gap = debt_growth - income_growth`

**Sub-tasks.**
1. For each entity-level ratio (1-3, 6-13): wire `secureDivideU64Bin(num, denom, inclusion_bit)`.
2. For sector-level ratios (4, 5): compute at aggregation stage from secret-shared sums;
   distinguish "ratio-of-sums" (correct per spec §13) from "mean of per-entity ratios".
3. Fixed-point representation: choose (integer scale, fractional scale) per ratio range;
   document overflow guards.
4. Growth-rate handling: `previous_period` values require prior-run linkage; either
   pre-join at Phase 4 with `(handle, period-1)` fold, or run growth ratios as a separate
   pass with a prior-period shared table.
5. Compute-time correlation logging: hooks for secure correlation analysis (spec §14) to
   identify double-counting before Phase 9 weight assignment.

**Existing code reused.** `MpMpcArithmetic::secureDivideU64Bin` (**primary primitive**);
`MpSecretShare::SharedU64Bin` arithmetic; `MpBeaverTriple::secureAnd`.

**Missing.** Fixed-point convention + overflow-guard wrapper; growth-rate join with prior period;
correlation logger; ratio-domain metadata (higher = more vulnerable? inverse?).

**Acceptance criteria.**
- [ ] All computed ratios exist only as secret shares between the MPC nodes.
- [ ] No party (including any MPC node alone) sees any entity-level ratio value.
- [ ] Overflow-guarded fixed-point arithmetic passes bit-level parity vs. reference
      Python computation on 10 controlled input vectors.
- [ ] Excluded entities (`inclusion_bit=0`) contribute a zero-value + zero-inclusion pair
      and cannot be distinguished from included entities from the MPC transcript alone.

**Deps.** Phase 5. **Estimated sessions.** 3–4.

---

### Phase 7 — Secure Winsorisation  *(spec §15; NOT in Protocol Rev 6 — divergence)*

**Alignment gap noted.** `PROTOCOL_PI_SECTORVULN.md` Rev 6 does not include an explicit
winsorisation stage; secure clamping to [lo_pct, hi_pct] percentiles is not currently
in the protocol's pseudocode. Either (a) this Phase gets deferred until the protocol is
extended with a winsorisation block that wires into Protocol §8 (before rank), or
(b) the requirements spec §15 winsorisation requirement is downgraded / removed.
Escalate to protocol author for resolution before implementing this Phase.

**Goal.** Clamp unbounded ratios to configurable [lo_pct, hi_pct] range under MPC.

**Sub-tasks.**
1. Compute the lo_pct-th and hi_pct-th percentiles per (sector, period, metric) via Phase 10's
   percentile primitive.
2. Broadcast the shared percentile values (they remain shares) as bounds.
3. Clamp each entity ratio: `clamped = min(max(ratio, lo), hi)` via
   `secureLessThan` + conditional selection.
4. Distinguish `raw_ratio`, `winsorised_ratio` in downstream schema (spec §15).
5. Do NOT winsorise naturally-bounded official rates (e.g., `unemployment_rate`).

**Existing code reused.** `MpSecureCompare::secureLessThan`, `MpBeaverTriple::secureAnd` for
conditional swap.

**Missing.** Winsorisation opcode over shared values with shared bounds; per-ratio opt-out flag.

**Acceptance criteria.**
- [ ] Winsorised ratios lie within [lo_pct, hi_pct] bounds by construction.
- [ ] Both `raw_ratio` and `winsorised_ratio` remain shared through Phase 8+.
- [ ] Official rates are exempt.

**Deps.** Phase 6, needs Phase 10 primitive (percentile). Note the dependency loop: winsorisation
uses percentiles, and percentile of winsorised = percentile of raw for that ratio's endpoints.
Resolve by two-pass:
   - Pass 1: raw percentiles.
   - Pass 2: winsorised ratios + downstream stats.

**Estimated sessions.** 2.

---

### Phase 8 — Risk-Score Normalisation  *(spec §16; Protocol §8 RiskScores + §8.1 BucketIndex + §8.2 RankViaHistogram; Rev 7 §8.2.1 conditional radix sort per Φ.radix_enabled)*

**Goal.** Convert each selected indicator into a `risk_score ∈ [0, 100]` using
percentile-rank normalisation within the approved comparison population.

**Sub-tasks.**
1. Comparison population selection (spec §16 alternatives): decide one and record. Default:
   entities within the same sector and reporting period.
2. Secure rank computation: `MpMpcSort` on `(secret_ratio, entity_id_share, inclusion_share)`
   → position in sorted order for each entity, secret-shared.
3. Convert rank to percentile-rank: `pr = rank / (N_included - 1)` in fixed point.
4. Normalise to 0–100: `risk_score = 100 * pr` for direct indicators; `100 * (1-pr)` for
   inverse indicators (income_per_worker, employment_rate, income_to_debt if used).
5. Ties: use average rank (spec §16). Requires equality detection under MPC.

**Existing code reused.** `MpMpcSort`, `MpSecureCompare` (equality via double-inequality).

**Missing.** Rank extraction from sort output; tie-handling wrapper (average of tied ranks).

**Acceptance criteria.**
- [ ] Score for each entity/indicator is a secret share, never disclosed.
- [ ] Inverse indicators produce lower scores for high raw values.
- [ ] Tied inputs produce equal average ranks.
- [ ] Comparison population is documented per output row.

**Deps.** Phase 7. **Estimated sessions.** 2.

---

### Phase 9 — Weighted Composite + Missing-Component Policy  *(spec §14, §18, §19; Protocol §13 TwoScore)*

**Goal.** Combine per-entity risk scores into a per-entity composite `vulnerability_score ∈
[0, 100]`, with a documented missing-component policy.

**Sub-tasks.**
1. Weight registry: versioned config file; enforce sum-to-1 and non-negative.
2. Complete-case scoring (default): compute composite only when every mandatory component
   has `inclusion_bit=1`.
3. Optional controlled reweighting: require min_valid_components; redistribute missing
   weights proportionally under MPC; keep effective weights secret; report aggregate
   missingness rate.
4. Secure weighted sum: `Σ w_i · risk_score_i` where `w_i` is a public constant (or a
   configurable shared value if reweighting active) → free additive op on shares.
5. Correlation-analysis output (from Phase 6) informs indicator selection to avoid
   double-counting reciprocal/overlapping indicators (spec §14).

**Existing code reused.** `MpSecretShare` addition; `MpMpcArithmetic` for reweight
divisions.

**Missing.** Weight registry format + versioning; missing-component branch under MPC
without revealing which entity lacked which component.

**Acceptance criteria.**
- [ ] Vulnerability score is a secret share ∈ [0, 100] (checked by post-hoc range assertion
      in Phase 16).
- [ ] Reweighting policy version is recorded in the audit log.
- [ ] Individual entity's missing components are never revealed.

**Deps.** Phase 8. **Estimated sessions.** 1–2.

---

### Phase 10 — Secure Percentile (p25 / p50 / p75)  *(spec §17; Protocol §11 GroupPercentiles)*

**Goal.** For each (raw ratio, risk score, vulnerability score), compute per-sector p25, p50,
p75 under MPC using oblivious sort + selection.

**Sub-tasks.**
1. Sort included entities per sector by the target metric using `MpMpcSort` (or oblivious
   selection network for cost).
2. Select ranks: `⌊(n-1) × 0.25⌋`, `⌊(n-1) × 0.5⌋`, `⌊(n-1) × 0.75⌋` (using the declared
   rank formula and interpolation rule).
3. Linear interpolation between adjacent order statistics for non-integer ranks.
4. Tie handling per §16 (average rank convention).
5. Minimum valid observation count (spec §17): below threshold → distribution percentiles
   marked unavailable; single-value groups → return aggregate value.
6. Document quantile definition, rank formula, interpolation, tie handling per output row.

**Existing code reused.** `MpMpcSort` (bitonic), `MpSecureCompare` for equality.

**Missing.** Percentile-selection wrapper (index arithmetic + interpolation under MPC);
per-sector partitioning of the sort input.

**Acceptance criteria.**
- [ ] For deterministic input vectors of size ≥ 4, MPC-computed p25/p50/p75 match a
      reference plaintext computation to fixed-point precision.
- [ ] p25 ≤ p50 ≤ p75 always (spec §23).
- [ ] Sub-threshold groups return `unavailable` without leaking exact count.

**Deps.** Phase 8 (for score percentiles), Phase 9 (for vuln score percentiles), Phase 7
loop closure. **Estimated sessions.** 2.

---

### Phase 11 — Secure Sector Aggregation  *(spec §20; Protocol §10 SectorAggregate)*

**Goal.** Per `(sector_code, reporting_period)`, produce the aggregate outputs required by
the schema.

**Aggregates per §20:**
- `n_valid_observations` (secret-shared sum of inclusion bits)
- `sum` (shared)
- `mean` (secret divide of sum by count)
- `ratio_of_sums` (Σ num / Σ denom for the sector — the *correct* aggregate for spec §13
   ratios 4, 5)
- `p25, p50, p75` (Phase 10)
- `missing_data_rate` (1 − count/population, shared)
- `component_risk_score_percentiles` (Phase 10 applied to Phase 8 outputs)
- `vulnerability_score_percentiles` (Phase 10 applied to Phase 9 outputs)

**Sub-tasks.**
1. Inclusion-bit-gated additions everywhere.
2. Fixed-point aggregation rules (spec §20 requires explicit numeric representation, max
   magnitude, decimal precision, rounding mode, overflow, division protocol, comparison
   protocol, handling of negatives, handling of nulls). Document each.
3. Secret-shared aggregate is passed to Phase 12 (disclosure control) before any reveal.

**Existing code reused.** `MpSecretShare`, `MpMpcArithmetic::secureDivideU64Bin`,
`MpBeaverTriple::secureMultiply` for inclusion gating.

**Missing.** Aggregation runner with fixed-point convention frozen.

**Acceptance criteria.**
- [ ] Aggregates match plaintext reference on controlled inputs.
- [ ] Aggregates for excluded entities do NOT change when varying an excluded entity's
      value.
- [ ] Overflow does not silently truncate; either raises abort or saturates per documented
      rule.

**Deps.** Phases 5–10. **Estimated sessions.** 2.

---

### Phase 12 — Disclosure Control  *(spec §21; Protocol §12 Materialise+Disclose + §12.a DP + Rev 7 R26 CDF-monotonicity clamp)*

**Goal.** Apply k-anon suppression, complementary suppression, dominance/concentration rules,
and (optional, on approval) DP to secret-shared aggregates BEFORE any reveal.

**Sub-tasks.**
1. Reveal the *count* of included entities per sector to check k-anon threshold — this
   must itself be padded or noised if that count is leakage-sensitive (spec §9 padding
   choice affects this).
2. Suppression flag per (sector, period, metric): `suppress iff count < k_min`
   OR sector marked as highly sparse OR complementary suppression triggered from a
   related row.
3. Complementary suppression: if suppressing row X would allow row Y to be inferred by
   differencing across categories, mark Y for suppression too. Requires a suppression
   dependency graph over the release set.
4. Dominance / concentration rule: if one entity contributes > D_max fraction of an
   aggregate, suppress the aggregate.
5. Differencing-attack tracker across repeated releases (spec §21): store hash of prior
   released aggregates; refuse a new release that combined with prior enables per-entity
   inference. This can lean on `MpOiraBudget` for composition tracking.
6. Optional DP: applied to *aggregated* values AFTER secure aggregation, only if approved.
   Specify privacy unit, sensitivity, clipping, mechanism, budget, composition.

**Existing code reused.** `MpOira` k-anon logic, `MpOiraBudget`, `MpTranscript`.

**Missing.** Complementary-suppression graph; dominance rule under MPC; released-history
store; DP-quantile mechanism for percentiles if opted in.

**Acceptance criteria.**
- [ ] No released row can be traced back to an entity via any single-attribute lookup
      against the released rows.
- [ ] Suppression flag release does NOT reveal the exact reason (spec §21).
- [ ] Repeated-release simulation demonstrates differencing attack fails against 3 back-to-back
      releases with realistic parameter drift.

**Deps.** Phase 11. **Estimated sessions.** 2–3.

---

### Phase 13 — Output Schema & Release  *(spec §22; Protocol §12.1 OpenToGovTech)*

**Goal.** Emit exactly the fields spec §22 lists, in the exact shape, per
`(sector_code, reporting_period, metric_name)`.

**Sub-tasks.**
1. Serialiser with strict allow-list: reject any attempt to include entity handles, shares,
   membership bits, matched counts, or intermediate values.
2. Version fields wired: formula, weights, risk-score, MPC protocol, PSA protocol,
   disclosure-control versions.
3. Output format: CSV (default), JSON (alternative); one row per metric per sector-period.
4. Sign the release with GovTech key; archive to audit store.

**Existing code reused.** `MpTranscript` for signature; `MpsaDriver` CSV writer (only for
schema layout inspiration, not for data flow).

**Missing.** Schema class + validator; version-injection.

**Acceptance criteria.**
- [ ] Released file contains only the union of §22 field list.
- [ ] For every released row, all version fields are non-empty.
- [ ] Signed release verifies against the GovTech public key.

**Deps.** Phase 12. **Estimated sessions.** 1.

---

### Phase 14 — Audit & Governance  *(spec §24; Protocol §2 audit-only erasure)*

**Goal.** Produce and archive an audit record per computation.

**Sub-tasks.**
1. Audit record type with the exact §24 fields.
2. Hooks in each Phase to append attestation entries (software hash, protocol version, timings).
3. Exclusion filter: audit log MUST NOT contain entity-level values, identifiers, membership,
   secret shares, sensitive intermediates.
4. Approval workflow for formula/weight/schema/policy changes.

**Existing code reused.** `MpTranscript` (extend), `MpAuthCascade` (attestation), Ed25519 identity
via `MpIdentity`.

**Missing.** Audit-record schema; approval-workflow harness.

**Acceptance criteria.**
- [ ] Audit record for a run reproduces the exact release when replayed against archived shares.
- [ ] Audit record contains zero entity-level bytes (checked by structural inspection).

**Deps.** Phases 3, 13. **Estimated sessions.** 1.

---

### Phase 15 — Failure Handling  *(spec §25; Protocol §12.1 MAC-fail=abort)*

**Goal.** Failures do not leak which entity/party/ratio failed, or match counts, or partial
results.

**Sub-tasks.**
1. Generic external error: single opaque error id per failure class; no per-entity data.
2. Protected internal diagnostics: rich detail retained inside the MPC-node logs for audit,
   never shipped in the release.
3. Partial-result release policy: default = no partial releases unless explicitly approved.

**Existing code reused.** `MpTranscript`.

**Missing.** Error-classification enum; diagnostic-vs-external separator.

**Acceptance criteria.**
- [ ] External error surface reveals no data-dependent information (fuzz test).
- [ ] Internal diagnostics captured but never included in release.

**Deps.** Independent, integrates with every other Phase. **Estimated sessions.** 1.

---

### Phase 16 — Validation Tests  *(spec §23; Protocol §16 invariants)*

**Goal.** Automated harness covering every invariant listed in §23.

**Sub-tasks.**
1. Test suite (mirror §23 bullet list): handle uniqueness, duplicate handling, sector validity,
   period alignment, unit consistency, denominator validity, non-zero missing, membership secrecy,
   dummy indistinguishability, fixed payload length, control-flow independence, weight sum,
   score ranges, p25≤p50≤p75, comparison population documented, non-double-counting, suppression
   safety, reconciliation with source totals, non-reconstructability, GovTech-blind-to-loan-
   membership, differencing safety.
2. Test data: synthetic per-agency inputs with known ground truth.

**Existing code reused.** existing `tests/unit/*` harness pattern; add `tests/unit/mpsvs_*`.

**Missing.** All of this suite (does not exist yet).

**Acceptance criteria.**
- [ ] Every §23 rule has ≥1 red/green test.
- [ ] Suite runs under `-DVOLE_PSI_BUILD_TESTS=ON` in CI.

**Deps.** Whatever Phases have shipped. Ongoing. **Estimated sessions.** 2, incremental.

---

### Phase 17 — Malicious Upgrade  *(spec §4; Protocol §14 [MAL] hardening path)*

**Goal.** Upgrade from semi-honest to malicious-secure per §4's bullets.

**Sub-tasks.**
1. Input-consistency checks: commit-and-open for each source's payload set.
2. MACs over shares: extend `MpSecretShare` with MAC key + `MpMac` glue.
3. Zero-knowledge proofs for select gates (e.g., range proofs on denominators; correct
   winsorisation).
4. Verifiable computation for aggregation: succinct proof of correct MPC output for the
   release.
5. Transcript validation: cross-signed transcript hash from each MPC node.

**Existing code reused.** `MpMac`, `MpAuthCascade`, `MpTranscript`, `MpPedersen(Vector)`,
`MpIdentity`, `MpsaShuffleIntegrity` (A-sum / A-mset-row patterns).

**Missing.** Authenticated share type; SPDZ-style MAC verification loop; range-proof
integration.

**Acceptance criteria.**
- [ ] Any tampering with a share is detected with overwhelming probability.
- [ ] A malicious MPC node causes abort with attribution before any release.

**Deps.** All Phases functionally complete in semi-honest form.
**Estimated sessions.** 4–6.

---

## 7. Cross-cutting concerns

### 7.1 Fixed-point convention (Phase 6, 7, 10, 11)

Freeze once and use throughout:

- Numeric attributes: `u64` with per-attribute integer scale (documented in Phase 1 schema).
- Ratios: `u64` in scale `10^12` (12 decimal digits of fractional precision).
- Overflow: any multiply that could exceed `2^63` must use `u128` intermediates or fail
  with abort; document per operation.

### 7.2 Session identifiers and nonces (Phase 2, 3, 12)

Every run generates a fresh `session_id` (128-bit) at Phase 2, used as:

- KDF context for PSA handle derivation.
- Domain separator for Beaver-triple generation.
- Nonce base for all AEAD.
- Key rotation per run for the released-history store (Phase 12).

### 7.3 Weight and formula versioning (Phase 9, 13, 14)

- Weight registry: `docs/weights/vXX.yaml`.
- Formula registry: `docs/formulas/vXX.yaml`.
- Every release row carries the version tag of each registry used.
- Version bumps require approval via the workflow in Phase 14.

### 7.4 Sector taxonomy

- Canonical taxonomy authoritatively defined once (default: SSIC 2-digit).
- Cross-agency mapping tables version-controlled.
- Reconciliation rule (Phase 4) freezes per run.

### 7.5 Test data

- Synthetic multi-agency dataset generator with tunable overlap + attribute distributions.
- Do NOT reintroduce plaintext CSV pipelines for computing "ground truth" ratios in a way that
  looks like a PSA output (that was a Session 14/17 anti-pattern).
- Ground-truth reference remains in the test harness only; production release never touches
  it.

### 7.6 Topology decision matrix

| Computation | Path | Topology | Rationale |
|---|---|---|---|
| Cardinality of intersection | Aggregate-only | Single-SP (SP + K clients) | MPSICS-style secure sum with public denominator |
| Sum over intersection | Aggregate-only | Single-SP | Same as above |
| Public-denominator ratios | Aggregate-only | Single-SP | Division at output; SP handles it locally after aggregation |
| Entity-level ratios (all Protocol §7 ratios) | SectorVuln | **Two-domain (S1+S2)** | Protocol §0 rationale — Beaver + Goldschmidt needs both domains |
| Secure percentiles on secret n_valid | SectorVuln | **Two-domain** | Oblivious sort of shared (key, payload) cleaner across two |
| Ratio-of-sums with secret denominator | SectorVuln | **Two-domain** | Reciprocal error path incompatible with single-SP |
| Weighted composite score | SectorVuln | **Two-domain** | Runs inside the same S1+S2 substrate as its inputs |

**Rule:** if any output for a metric requires operations from the SectorVuln column,
that metric runs on the two-domain path end-to-end. Do not mix topologies within a
single metric's pipeline.

---

## 7.7 Protocol freeze blockers (from `PROTOCOL_PI_SECTORVULN.md §17`)

These block Π_SECTORVULN protocol freeze. All implementation Phases below must satisfy
their local acceptance criteria AND the 14 protocol-level items must be closed (Rev 6 items
1–10; Rev 7 additions 11–14):

1. **Custom sequential two-server VOPRF proof** — Protocol §3 PROOF OBLIGATION 3.A.
2. **Machine-checked numerical bound table → (k, f, guard)** — Protocol §9. Prototype
   defaults `(128, 40, 8)` published; formal proof required for freeze.
3. **Sector-combination policy sign-off** — agg_fn ∈ {median, mean, p75}, w_E, w_C
   — Protocol §13.
4. **Statistical-unit class tags per §13 indicator** — schema freeze; requirements R10.
5. **Malicious ComposedShuffle composition + proof** — Protocol §14.
6. **Implement + test segmented circuits** — Protocol §8.1 + §11 + fixed-grid §12.
7. **Output opening protocol tests** — Protocol §12.1 end-to-end share-open with
   MAC-fail=abort validation.
8. **DP mechanism concrete instantiation** — Protocol §12.a Gaussian + zCDP; clipping
   norms per metric published; accountant version pinned; share-split sampler tested.
9. **Goldschmidt convergence table regenerated after (k, f) freeze** — Protocol §8.1.1.
10. **Independent-audit erasure procedure signed off** — Protocol §2 audit-only; no TEE.
11. **[Rev 7] R27 break-even benchmark validation** — measured B_crit on target substrate
    confirms Φ.radix_enabled setting (theoretical B_crit ≈ 128 at n = 2^21; benchmark
    required before Φ freeze).
12. **[Rev 7] Exact discrete-Gaussian bias formula** — derived closed form for
    `E[max(0, η)]` for DGauss(σ²) over ℤ (Rev 7 uses continuous approximation
    `≈ σ/√(2π)`; needs exact form for utility-bias sign-off).
13. **[Rev 7] Full UC simulation proof of §8.2.1** — extend the Rev 7 sketch to a full
    UC proof in the F_PSA-hybrid model (applies only when Φ.radix_enabled = true).
14. **[Rev 7] Side-channel empirical benchmarking** — static analysis + profiling
    verifying identical instruction sequences and communication patterns for
    segmented scans + ObliviousPermute.

Every implementation session per the plan below must, at close, re-check the local
Phase acceptance criteria AND check that its work does not regress any of these 10
items.

## 8. Estimated timeline (semi-honest baseline)

| Phase | Sessions | Dependencies |
|---|---|---|
| 1 | 2 | — |
| 2 | 3–4 | 1, initial 3 (adds DKG + dual-tag DH-VOPRF from Protocol §2, §3) |
| 3 | 3 | (initial before 2; adds S1+S2 two-domain wiring on top of existing SP for SectorVuln path) |
| 4 | 2–3 | 2, 3 (adds Protocol §5 windowed merge + §5.6 ComposedShuffle explicit) |
| 5 | 2 | 4 |
| 6 | 3–4 | 5 |
| 7 | 1 or deferred | 6, 10 (loop). Rev 6 protocol doesn't include winsorisation — see Phase 7 escalation note. |
| 8 | 2–3 | 7 (adds Protocol §8.1 SegmentedRankScore + §8.1.1 Goldschmidt annex) |
| 9 | 1–2 | 8 |
| 10 | 2 | 8/9 |
| 11 | 2 | 5–10 |
| 12 | 3–4 | 11 (adds Protocol §12.a Gaussian + zCDP + share-split noise) |
| 13 | 1–2 | 12 (adds Protocol §12.1 output opening) |
| 14 | 1 | 3, 13 |
| 15 | 1 | (integrated) |
| 16 | 2 | ongoing |
| Total (semi-honest) | **30–36** | (bumped from 27-31 to reflect two-domain + DKG + explicit ComposedShuffle + Gaussian noise + output opening) |
| 17 (malicious upgrade: signed transcripts, MACs on SP messages, ZK-OPRF, A-sum/A-mset-row extensions, malicious-secure Gaussian DP) | 4–6 | 1–16 |
| **Grand total** | **34–42 sessions** | |

Sessions are wall-time-heavy where they touch vendored code, network topology, or new MPC
primitive definitions.

---

## 9. Explicit non-goals for this deployment

Restated from `PROBLEM_STATEMENT.md §8` and reinforced:

- Not a general MPC framework — the deliverable is specifically the SVS computation.
- Not a real-time system — quarterly releases with sub-hour compute is the target.
- Not a data-marketplace — releases are supervisory, not commercial.
- Not a substitute for regulatory review of the release itself.

---

## 10. Deviation log

*(Append entries in this section every time a session deviates from the phased plan or its
acceptance criteria. Format: date · phase · what deviated · why · what was updated in this doc.)*

- **2026-07-26 · Phase 2 · Approach revision.** Original v1 draft listed PSI-AD and PSU as
  candidate PSA primitives. User rejected — "cant do PSI with payload". PSI-AD reveals match
  status which violates spec §3. Phase 2 rewritten to: (a) OPRF-only handle emission
  (no PSI on the wire), (b) all records secret-shared to MPC nodes including dummies,
  (c) alignment happens entirely inside MPC in Phase 4. Bucket-size padding hides
  per-agency set sizes and intersection sizes. Estimated sessions bumped 3 → 3–4 to cover
  distributed OPRF-key DKG.
- **2026-07-26 · Phase 3 · Substrate revision.** Original v1 draft defaulted to 3-party
  replicated secret sharing. User rejected — "no replicated". Phase 3 rewritten to require
  SPDZ-style additive shares over ℤ₂⁶⁴ with MACs (dishonest-majority, N ≥ 3). Rationale:
  (a) matches spec §4 "tolerate ≥1 compromised or colluding MPC node" but stronger,
  (b) matches the substrate `MpSecretShare` / `MpBeaverTriple` / `MpMpcArithmetic` / `MpMpcSort`
  / `MpMpcJoin` are already built on. Missing item added: N-party (N≥3) extension of
  `MpMpcWire*` from 2-party.
- **2026-07-26 · Phase 4 · Wire semantics clarified.** Made explicit that the "join" is
  inside MPC on shares, with `alignment_bit` derived via secret-shared adjacent-equality
  after sort. Downstream `inclusion_bit` composition in Phase 5 updated to include
  `alignment_bit`.
- **2026-07-26 · Phase 3 · Topology revision.** v1.1 had "SPDZ additive+MAC over N ≥ 3
  MPC nodes". User rejected — "at most one server to perform server aided task like in
  my PSA paper". Rewritten as **single-SP server-aided topology** matching the deployed
  PSA-paper codebase (`MpsaDriver`, `MpShuffleDriver`, OIRA, MPSICS, `MpStarChannel`).
  SP holds `K_run`, orchestrates OSN cascade, aggregates; clients form peer mesh, hold
  additive shares, run Beaver-triple online phase; GovTech is out-of-band workflow
  orchestrator only. Trust model: SP semi-honest baseline, malicious-secure via
  transcript signing + MACs on SP messages + A-sum/A-mset-row extensions (all already
  present as deployed primitives). Phase 3 cost dropped from 3 sessions to 2 (most
  work is verifying existing modules meet acceptance criteria, not building new
  substrate).
- **2026-07-26 · Phase 2 · OPRF simplified to server-aided.** With single-SP model, the
  OPRF-key holder is just SP (with a Pedersen commit for binding). Distributed OPRF-key
  DKG dropped. Phase 2 cost 3-4 sessions → 2-3.
- **2026-07-26 · Phase 4 · Alignment via SP-orchestrated OSN cascade.** With single-SP
  model, the "oblivious sort inside MPC" becomes an SP-orchestrated OSN cascade
  (deployed `MpShuffleDriver` pattern) whose sender-private routing seeds keep SP blind
  to the sort permutation. Adjacent-equality happens in the client mesh via
  `secureAnd` on shared bits.
- **2026-07-26 · Global · Timeline dropped.** Semi-honest total 30-34 → 27-31 sessions
  (server-aided model reuses more deployed infrastructure). Malicious upgrade 4-6 → 3-5
  (uses existing `MpMac`, `MpAuthCascade`, `MpsaShuffleIntegrity`).
- **2026-07-26 · Phase 3 · Two-domain protocol variant introduced.**
  `docs/PROTOCOL_PI_SECTORVULN.md` (Rev 6) adopts a **two-domain** (S1+S2) MPC
  topology for the sector-vulnerability computation specifically, deviating from
  this plan's single-SP default (§Phase 3). Rationale in that doc's §0. The plan's
  Phase 3 remains valid for aggregate-only paths; SectorVuln is the exception.
- **2026-07-26 · Global · Plan resynced to Rev 6 protocol (v1.3).** All 17 phases
  cross-referenced to specific `PROTOCOL_PI_SECTORVULN.md` §s. Stakeholder table
  extended with S1, S2 rows. Topology decision matrix added as §7.6. Protocol freeze
  blockers added as §7.7. Timeline bumped 27-31 → 30-36 sessions to reflect DKG,
  dual-tag OPRF, explicit ComposedShuffle, Gaussian DP with share-split noise, and
  output-opening protocol overhead. **Phase 7 escalated** — Rev 6 protocol does not
  include winsorisation; either extend the protocol or drop the requirements spec
  §15 requirement before Phase 7 starts.

---

## Version history

- **v1** (2026-07-26). Initial plan derived from the "MAS/DOS/MOM/GovTech vulnerability
  score" spec (§1–§26). Codebase inventory current as of the same date. Supersedes all
  session 10–23 implementation work generated in the conversation immediately preceding
  this document.
- **v1.1** (2026-07-26). Two architectural corrections from user feedback: (a) no PSI-AD
  or any PSI-with-payload — alignment is inside MPC via OPRF handles + shared uploads
  + oblivious equality; (b) no 3-party replicated — substrate is SPDZ additive+MAC over
  ℤ₂⁶⁴, dishonest-majority. Phase 2 rewritten, Phase 3 rewritten, Phase 4 clarified,
  code inventory updated, anti-patterns extended, gap analysis updated, timeline bumped,
  deviations logged.
- **v1.2** (2026-07-26). Third correction from user: "at most one server to perform
  server aided task like in my PSA paper" — the multi-node MPC farm (v1.1 default) is
  rejected in favour of the deployed PSA-paper star topology (1 SP + K clients + peer
  mesh + GovTech out-of-band). Phase 3 rewritten as single-SP server-aided; Phase 2
  simplified from DKG'd OPRF to SP-held `K_run` with Pedersen-commit binding; Phase 4
  aligned to SP-orchestrated OSN cascade using the deployed `MpShuffleDriver` pattern;
  architecture diagram redrawn; stakeholder table updated to reflect SP + clients +
  GovTech; anti-patterns extended to reject multi-node MPC farms; gap analysis G-B /
  G-C / G-V updated; timeline dropped from 34-40 to 30-36 sessions (reuses more
  deployed infra); v1.2 deviation entries logged.
- **v1.3** (2026-07-26). Cross-sync with `PROTOCOL_PI_SECTORVULN.md` Rev 6.
  Two-domain (S1+S2) variant adopted for SectorVuln entity-level path (with
  aggregate-only path retaining single-SP). Header now names Rev 6 protocol as
  the authoritative protocol spec. All 17 phases cross-referenced to specific
  Protocol §s. Stakeholder table §1 adds S1 and S2 rows. Anti-patterns adjusted
  to allow the 2-domain exception. New §7.6 Topology decision matrix. New §7.7
  Protocol freeze blockers (10 items from Protocol §17). Phase 7 escalated —
  Rev 6 protocol lacks winsorisation. Timeline bumped 27-31 → 30-36 sessions
  (34-42 with malicious upgrade) to reflect DKG + dual-tag OPRF + explicit
  ComposedShuffle + Gaussian-DP-with-share-split-noise + output-opening.
- **v1.4** (2026-07-26). Sync with Rev 7 patches (`docs/PROTOCOL_PI_SECTORVULN_R7.md`).
  Header now cites Rev 6 + Rev 7 composed. Phase 8 (risk-score normalisation)
  updated to reference §8.2.1 R27 conditional radix sort (enabled iff
  Φ.radix_enabled per break-even table). Phase 12 (disclosure control)
  updated to reference §12 R26 CDF-monotonicity clamp (fixes Gap 11).
  §7.7 freeze blockers extended 10 → 14 (Rev 7 additions 11–14: R27 benchmark
  validation, exact discrete-Gaussian bias formula, full UC simulation proof
  of §8.2.1, side-channel empirical benchmarking). No phase count change;
  R26 is small (one clamp op in §12), R27 is conditional (both branches
  already proven).
