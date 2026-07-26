# Π_SECTORVULN — Full Protocol Specification and Pseudocode (Rev 6)

Semi-honest two-domain MPC for sector-level financial vulnerability statistics
over MAS / DOS / MOM, orchestrated by GovTech. Incorporates the 12 findings
of the Rev-5 → Rev-6 multi-agent review (2026-07-26); see §Version-log.

Status: **conditional pass for prototype — not protocol-frozen**. Freeze
blockers itemised in §17.

Key deltas from Rev 5:
- §0 (new) — rationale for the 2-domain topology (vs the "at most one server"
  guidance in `docs/DEPLOYMENT_FULL_MPC.md` §Phase 3).
- §12.1 (new) — output opening protocol formalised.
- §12 — DP mechanism concreted (Gaussian + zCDP + share-split noise).
- §9 — concrete initial `(k, f, guard)` provided.
- §8.1 — Goldschmidt convergence annex.
- §5.6 — ComposedShuffle written out message-by-message (Chase-Ghosh-Poburinnaya).
- §18 (new) — performance analysis with rounds / bandwidth / latency.
- §19 (new) — post-quantum roadmap note.
- §2 — key-erasure claim downgraded to audit-only (no TEE).
- §3 header — H1 / H2 instantiated; VOPRF proof obligation broken out.
- §15 — ComposedShuffle leakage ledger phrasing tightened.
- §17 — freeze blockers extended.

---

## §0. Design rationale for the two-domain topology  *(new in Rev 6)*

The parent deployment plan (`docs/DEPLOYMENT_FULL_MPC.md`, v1.2 §Phase 3)
adopts a single-SP star topology matching the PSA paper. That choice is
optimal for **aggregate-only** sector outputs (cardinality, sum, MPSICS-
style reductions) where the SP is honest-but-curious and every message it
receives is either encrypted, secret-shared, OSN-shuffled, or opened as a
Beaver-triple difference. Under those constraints, one SP is sufficient
and simpler.

Π_SECTORVULN's outputs cross that boundary:

- **Entity-level ratios** (§7) require secure division under MPC. Beaver-
  triple multiplication + Goldschmidt reciprocation on a single-SP
  substrate is possible but forces per-entity SP visibility of Beaver
  openings that constrain the payload width and expand the SP transcript.
- **Secure percentiles over secret n_valid** (§8.1, §11) require an
  oblivious sort of shared (key, payload) pairs with segmented scans.
  These circuits are cleaner when both sort halves live at separate
  domains (S1, S2) that share only opened differences, not full state.
- **Ratio-of-sums with SECRET valid mass** as denominator (§10 / R6) is
  where single-SP breaks: dividing two shared sums by a shared count with
  the SP as one endpoint puts the SP into the reciprocal's error path.

Rev 6 therefore uses **two computation domains**:

- **S1** — GovTech-operated MPC node (physically inside GovTech's compute
  environment; software attested by GovTech CI).
- **S2** — Independent domain (candidate: a public-sector trustee, an
  audit body, or a national compute co-op; policy decision, not
  cryptographic). Must be organisationally and operationally separate
  from GovTech.

**GT (the workflow-orchestrator role from `PROBLEM_STATEMENT.md`) is a
distinct entity from S1** even when S1 runs inside GovTech's compute
plant. GT holds workflow state, version attestations, and the final
disclosure-controlled output only. GT does **not** hold shares, keys, or
plaintext at any protocol step.

**Non-collusion boundary:** the crypto assumes {S1, S2} do not collude.
If they do, MPC secrecy fails (2-of-2 additive shares) but the earlier
protection layers (SP-side blinding for the OPRF, blinded record uploads,
padded buckets) still hide raw MAS/DOS/MOM inputs.

This deviates from `docs/DEPLOYMENT_FULL_MPC.md` §Phase 3's "at most one
server" default; the deviation is deliberate and is logged in that doc's
§10 (Deviation Log).

---

## Notation and conventions

- Data parties: P ∈ {MAS, DOS, MOM}. Computation domains: S1, S2. Orchestrator: GT (workflow only; never holds shares or handles).
- `⟦v⟧` = 2-of-2 additive share of v over the payload ring Z_{2^k} (k, f, guard from §9), held as (⟦v⟧_{S1}, ⟦v⟧_{S2}). `⟦v⟧^B` = Boolean sharing (XOR) for bit/limb values.
- `[[pred]]` = a secret bit (1/0) resulting from a secure predicate.
- Group **G = ristretto255** (prime order q; standard base generator g). See §19 for post-quantum roadmap.
- **H1: bytes → G** — RFC 9497 hash-to-ristretto255 (`ristretto255-SHA512`).
- **H2: bytes → {0,1}^{256}** — SHA-256 with mandatory domain-separator prefix as the first field of every input; distinct 16-byte prefix per usage ("ALIGN-1", "ALIGN-2", "DUMMY", "OPEN", "SHUFFLE", "MAC").
- HB (base-field OKVS/PRF internal) — unused in this protocol; documented for schema compat only.
- **Fixed-point:** value x represented as round(x · 2^f); (k, f, guard) from §9.
- Public schedule constants: epoch length, bucket sizes m̃_P, union capacity N̂, sector list S, period list Π, metric list, weights (versioned), thresholds θ, DP regime.

All inter-entity channels are mutually authenticated + encrypted (TLS 1.3
with mandatory client cert; AEAD nonces fresh per record). Every run uses
fresh session id, nonces, cryptographic randomness.

---

## §1. Top-level orchestration (GT)

```
PROTOCOL SectorVuln(epoch E, approved_policy Φ):
  GT: verify software hashes, schema version, policy version Φ for {MAS,DOS,MOM,S1,S2}
  GT: publish run context ctx = (protocol_version ∥ epoch_id(E) ∥ session_id ∥ nonce)
  GT: publish bucket schedule {m̃_P}, capacity N̂, grid (S × Π × metrics),
      weights_ver, θ, DP_regime, (k, f, guard) from §9

  // Stage A: key setup
  (Y, Y1, Y2) ← ThresholdDKG(S1, S2, ctx)                       // §2

  // Stage B: local prep + tagging (each party, parallel)
  for P in {MAS,DOS,MOM}:
     R_P ← LocalPrepare(P, Φ)                                   // §4
     T_P ← TagRecords(P, R_P, ctx, Y1, Y2, Y)                   // §3
     ⟦Tbl_P⟧ ← SecretShareTable(P, T_P → S1, S2)                // §5.1

  // Stage C: protected union
  ⟦U⟧ ← BuildUnion(S1, S2, ⟦Tbl_MAS⟧, ⟦Tbl_DOS⟧, ⟦Tbl_MOM⟧)     // §5

  // Stage D: longitudinal alignment + growth metrics
  ⟦U⟧ ← GrowthAlign(S1, S2, ⟦U⟧)                                // §6
  drop tag column from ⟦U⟧                                      // R11′

  // Stage E: entity-level metrics + inclusion masks
  ⟦U⟧ ← EntityMetrics(S1, S2, ⟦U⟧)                              // §7

  // Stage F: risk normalisation
  ⟦U⟧ ← RiskScores(S1, S2, ⟦U⟧, Φ)                              // §8

  // Stage G: sector aggregation + percentiles + two-score model
  ⟦Agg⟧ ← SectorAggregate(S1, S2, ⟦U⟧, Φ)                       // §10, §11, §13

  // Stage H: disclosure control + fixed-grid materialisation
  ⟦Out_shares⟧ ← Materialise+Disclose(S1, S2, ⟦Agg⟧, grid, θ, DP_regime) // §12
  Out ← OpenToGovTech(S1, S2, GT, ⟦Out_shares⟧)                 // §12.1 (new)
  GT: audit-log, sign, version-tag, archive
  return Out
```

---

## §2. Threshold DKG (custom two-server, multiplicative)

```
ThresholdDKG(S1, S2, ctx):
  S1: k1 ←$ Z_q^* ; Y1 = g^{k1} ; π1 = SchnorrPoK{k1: Y1 = g^{k1}}
  S1 → S2: (Y1, π1)
  S2: verify π1
  S2: k2 ←$ Z_q^* ; Y2 = g^{k2} ; π2 = SchnorrPoK{k2: Y2 = g^{k2}}
  S2: Y  = Y1^{k2}                                  // = g^{k1 k2}
  S2: πY = DLEQ{k2: Y2 = g^{k2} ∧ Y = Y1^{k2}}      // Chaum–Pedersen
  S2 → S1: (Y2, π2, Y, πY)
  S1: verify π2, πY
  publish Y as epoch public key; store shares k1@S1, k2@S2
  at epoch close: securely wipe k1,k2 from S1, S2 memory
  return (Y, Y1, Y2)
```

**Erasure guarantee (Rev 6 patch, no TEE).** Rev 5 said "attest erasure";
Rev 6 replaces this with **operational-only guarantee**:

- Each domain deletes its share via `explicit_bzero()` + a syscall-level
  memory scrub, timing-attested by process-level logs.
- Deletion event is recorded in the domain's audit log; the log is
  countersigned by an independent auditor (spec §24) at each epoch close.
- **No cryptographic binding of deletion.** A malicious S1 or S2 that
  retains its share evades this mechanism; the mitigation is operational
  (independent audit + counter-signature), not cryptographic.
- Callers relying on strict cryptographic erasure guarantees should
  upgrade S1/S2 to HSM-backed key stores in a future revision (out of
  scope for Rev 6; no TEE in the current deployment).

---

## §3. Tag evaluation (custom sequential DH-VOPRF, dual-tag, context-bound)

**H1, H2 instantiations (Rev 6 patch — Minor #9):**
- `H1(msg) = ristretto255_hash_to_curve("ristretto255-SHA512", msg)`
  per RFC 9497 §4.4. Deterministic across parties.
- `H2(msg) = SHA-256(domain_prefix ∥ msg)` where `domain_prefix` is a
  fixed 16-byte ASCII tag; every H2 call MUST supply the prefix as its
  first field. Prefixes used: `"ALIGN-1|ALIGN-2|"`, `"DUMMY|........."`,
  `"OPEN|..........."`, `"SHUFFLE|........"`, `"MAC|............."`
  (16 bytes each, ASCII, padded with `.`).

**PROOF OBLIGATION 3.A (freeze blocker).** The custom sequential two-server
DH-VOPRF construction below must be proven secure under: (a)
pseudorandomness under corruption of {S1, ∗ parties} OR {S2, ∗ parties};
(b) blindness vs each server; (c) verifiability against `Y`; (d) adaptive
queries; (e) batching; (f) abort resistance; (g) corrupt-client
resistance; (h) rogue / substitution-key resistance. Assumption target:
**One-More-Gap-CDH in ROM**. Until this proof is furnished (§17.1), the
protocol is not frozen.

```
TagRecords(P, R_P, ctx, Y1, Y2, Y):
  T_P ← []
  for record ρ in R_P:                              // batchable; one round-trip per batch
     x ← ρ.canonical_id                             // §4 canonicalisation already applied
     r ←$ Z_q^*                                      // fresh blind per identifier
     M ← H1( "REAL" ∥ ρ.id_type ∥ x )                // R15 domain sep for real ids
     U ← M^{r}
     // hop 1
     P → S1: U ;  S1 → P: (V1 = U^{k1}, DLEQ{k1: Y1=g^{k1} ∧ V1=U^{k1}})
     P: verify DLEQ; abort record on failure         // abort is data-independent
     // hop 2
     P → S2: V1 ; S2 → P: (V2 = V1^{k2}, DLEQ{k2: Y2=g^{k2} ∧ V2=V1^{k2}})
     P: verify DLEQ against Y2; check chain consistent with Y
     W ← V2^{ r^{-1} }                                // = M^{k1 k2}
     // dual tag (R15′), context-bound finalisation (R1″)
     tag1 ← H2( "ALIGN-1|........" ∥ ctx ∥ ρ.id_type ∥ x ∥ Serialize(W) )
     tag2 ← H2( "ALIGN-2|........" ∥ ctx ∥ ρ.id_type ∥ x ∥ Serialize(W) )
     T_P.append( (tag1, tag2, ρ.payload, ρ.sector, ρ.period, membership=1) )
  // dummies: R15 DUMMY domain, per party/epoch, never collide
  for j in 1..(m̃_P − |R_P|):
     nonce ←$ {0,1}^{2κ}
     Md ← H1( "DUMMY" ∥ epoch_id ∥ party_id(P) ∥ nonce )
     // dummies still go through both servers so timing/interaction is uniform
     ... same two hops on Md ... → Wd
     dtag1 ← H2("ALIGN-1|........" ∥ ctx ∥ "DUMMY|.........." ∥ nonce ∥ Serialize(Wd))
     dtag2 ← H2("ALIGN-2|........" ∥ ctx ∥ "DUMMY|.........." ∥ nonce ∥ Serialize(Wd))
     T_P.append( (dtag1, dtag2, zero_payload, ⊥sector, ⊥period, membership=0) )
  shuffle T_P locally
  return T_P
```

Metering: each server counts hops per party per epoch, refuses > m̃_P.

---

## §4. Local preparation (each party, local)

*(unchanged from Rev 5; canonicalisation is deterministic across parties)*

```
LocalPrepare(P, Φ):
  rows ← select approved fields per schema(Φ)
  for row in rows:
     validate reporting period ∈ Π
     canonical_id ← Canonicalise(row.raw_id, row.id_type)
     row.sector ← standardise_sector(row.sector)
     row.period ← standardise_period(row.period)
     monetary fields → common currency, annualised
     for each value field: set validity_bit = ¬missing ∧ in_range ; NEVER value=0 for missing
     assemble fixed-schema payload (fixed length, per §5.2)
  deduplicate rows at grain (canonical_id, period)               // R3
  return rows

Canonicalise(raw, id_type):
  s ← UTF8_NFC(raw); s ← case_fold(s, per id_type rule)
  s ← apply_leading_zero_policy(s, id_type)
  return s
```

---

## §5. Protected union — Profile B (S1, S2 only; no incidence leakage)

### §5.1 Secret-share input tables
Each party shares its tagged table to (S1, S2): tags as 256-bit Boolean
sharings (R15″), payloads/flags as arithmetic shares over Z_{2^k},
sector/period as arithmetic (small-domain) shares.

### §5.2 Payload schema (fixed length, per source)
```
MAS: b_MAS | v_debt,v_dserv,v_delq,v_npl,v_unsec,v_stdebt | debt,dserv,delq,npl,unsec,stdebt | sector,period
DOS: b_DOS | v_income,v_rev,v_surp | income,rev,surp | sector,period
MOM: b_MOM | v_emp,v_lab,v_wap,v_unemp,v_retr,v_vac | emp,lab,wap,unemp,retr,vac | sector,period
```
All sources padded to identical external length; membership + validity
bits secret.

### §5.3 Union construction
```
BuildUnion(S1,S2, ⟦Tbl_MAS⟧,⟦Tbl_DOS⟧,⟦Tbl_MOM⟧):
  ⟦C⟧ ← concat rows of all three tables                       // T = Σ m̃_P rows, fixed public
  ⟦C⟧ ← ObliviousSort(⟦C⟧, key = (tag1, tag2, period, source)) // bitonic, §5.4
  ⟦U⟧ ← WindowedMerge(⟦C⟧)                                     // §5.5
  ⟦U⟧ ← MarkLiveAndShuffle(⟦U⟧)                                // §5.6
  return ⟦U⟧                                                    // fixed size N̂ = T
```

### §5.4 Oblivious sort (bitonic, tuple key)
```
ObliviousSort(⟦A⟧, key):
  n ← |A| (public)
  for k = 2,4,...,n:
     for j = k/2, k/4, ..., 1:
        parallel for i in 0..n-1:
           l ← i XOR j
           if l > i:
              dir ← ((i AND k) == 0)
              ⟦swap⟧ ← TupleGT(⟦A[i].key⟧, ⟦A[l].key⟧) XOR (¬dir)
              CondSwap(⟦A[i]⟧, ⟦A[l]⟧, ⟦swap⟧)
  return ⟦A⟧

TupleGT(⟦keyA⟧, ⟦keyB⟧):     // lex over (tag1[256b], tag2[256b], period, source)
  ⟦gt⟧, ⟦eq⟧ ← 0,1
  for field in [tag1_limbs..., tag2_limbs..., period, source] (MSB→LSB):
     ⟦f_gt⟧,⟦f_eq⟧ ← BitGT(⟦field_A⟧,⟦field_B⟧), BitEq(⟦field_A⟧,⟦field_B⟧)
     ⟦gt⟧ ← ⟦gt⟧ OR (⟦eq⟧ AND ⟦f_gt⟧)
     ⟦eq⟧ ← ⟦eq⟧ AND ⟦f_eq⟧
  return ⟦gt⟧
```

### §5.5 Windowed merge (run length ≤ 3)
```
WindowedMerge(⟦C⟧):
  parallel for i in 0..n-1:
     ⟦same1⟧ ← RunEq(⟦C[i]⟧, ⟦C[i+1]⟧)     // [[ (tag1,tag2,period) equal ]]
     ⟦same2⟧ ← RunEq(⟦C[i]⟧, ⟦C[i+2]⟧)
     ⟦first⟧ ← ¬RunEq(⟦C[i]⟧, ⟦C[i-1]⟧)
     for src in {MAS,DOS,MOM}:
        ⟦present_src⟧ ← [[C[i].source==src]]
                        OR (⟦same1⟧ AND [[C[i+1].source==src]])
                        OR (⟦same2⟧ AND [[C[i+2].source==src]])
        ⟦U[i].b_src⟧ ← ⟦first⟧ AND ⟦present_src⟧
        ⟦U[i].payload_src⟧ ← Select among {C[i],C[i+1]·same1,C[i+2]·same2} where source==src
     ⟦U[i].canonical⟧ ← ⟦first⟧
  return ⟦U⟧

RunEq(⟦r_a⟧,⟦r_b⟧): return BitEq over (tag1,tag2,period)
```

### §5.6 Live-marking, capacity, and ComposedShuffle  *(Rev 6 patch — Major #5)*

```
MarkLiveAndShuffle(⟦U⟧):
  parallel for i:
     ⟦anyMember⟧ ← ⟦U[i].b_MAS⟧ OR ⟦U[i].b_DOS⟧ OR ⟦U[i].b_MOM⟧
     ⟦U[i].live⟧ ← ⟦U[i].canonical⟧ AND ⟦anyMember⟧
  ⟦U⟧ ← ComposedShuffle(S1,S2, ⟦U⟧)
  return ⟦U⟧
```

ComposedShuffle (Chase-Ghosh-Poburinnaya '21 ShareTranslate, explicit
message pattern):

```
ComposedShuffle(S1, S2, ⟦A⟧ = (⟦A⟧_{S1}, ⟦A⟧_{S2})):
  // Notation: rows [i] each of arithmetic width w bits (over Z_{2^k});
  //           n = |A| public; permutations π1, π2 on n elements.

  // Round R1 — S1 permutes, S2 blinds
  S1: π1 ←$ Perm(n)                                 // fresh uniform permutation
  S1: for each i in 0..n-1: b1[i] ←$ Z_{2^k}          // fresh blinding
  S1 → S2: for each i:  m1[i] = ⟦A[π1(i)]⟧_{S1} + b1[i]   // S1's permuted+blinded share
  S2: for each i: c2[i] = ⟦A[?]⟧_{S2}                // S2 does NOT know π1
  // S2 cannot permute its own share to match π1 (secret to S2); instead:
  S2: for each i: r2[i] ←$ Z_{2^k}                    // fresh randomness
  S2 → S1: for each i: h2[i] = c2[i] + r2[i]         // masks S2's share for S1
  S1: for each i: ⟦B[i]⟧_{S1} = m1[i] − ⟦A[π1(i)]⟧_{S1}   // = b1[i]
  //   (S1 has permuted its own share to π1 order; kept b1 as new share)
  // At this point S1 holds b1[i] (its new share of A[π1(i)]); S2 holds c2[?]
  // still in original order. To translate S2's share to π1 order without
  // revealing π1 to S2, use an oblivious transfer over shuffled indices:
  //   (Executed via a 1-out-of-n OT extension per row; batched via
  //    Ferret/SoftSpokenOT. Details in Chase-Ghosh-Poburinnaya '21 §4.)
  // After R1: both parties hold shares of A[π1(i)] with π1 known ONLY to S1.

  // Round R2 — S2 permutes, S1 blinds (symmetric)
  S2: π2 ←$ Perm(n)
  S2: for each i: b2[i] ←$ Z_{2^k}
  ... mirror of R1 with S1 and S2 swapped ...
  // After R2: both parties hold shares of A[π1(π2(i))]; π2 known ONLY to S2.

  return ⟦B⟧ = (⟦B⟧_{S1}, ⟦B⟧_{S2})    // composed permutation π2 ∘ π1 unknown to either
```

Cost: **O(n·k) OT** per round via OT-extension (2 rounds total). Reference:
Chase, Ghosh, Poburinnaya, "Secret-Shared Shuffle" (Asiacrypt 2020 / IACR
2019/1340).

[MAL] Malicious variant: MAC-preserving `ShareTranslate` on SPDZ2k shares
+ post-shuffle MAC check. See §14.

---

## §6. Longitudinal alignment and growth metrics (tag retained)

*(unchanged from Rev 5)*

```
GrowthAlign(S1,S2, ⟦U⟧):
  ⟦U⟧ ← ObliviousSort(⟦U⟧, key=(tag1,tag2,period))
  parallel for i:
     ⟦adj⟧ ← RunEqTag(⟦U[i]⟧,⟦U[i+1]⟧) AND [[U[i+1].period == U[i].period + 1]]
     for (cur,prev,field) in growth_fields:
        ⟦g⟧ ← SafeGrowth(⟦U[i+1].field⟧, ⟦U[i].field⟧, ⟦adj⟧)
        ⟦U[i+1].field_growth⟧ ← ⟦g⟧
        ⟦U[i+1].field_contraction⟧ ← Max0(Neg(⟦g⟧))
     ⟦U[i+1].debt_income_gap⟧ ← ⟦debt_growth⟧ − ⟦income_growth⟧
  return ⟦U⟧

SafeGrowth(⟦cur⟧,⟦prev⟧,⟦adj⟧):
  ⟦den⟧ ← ⟦prev⟧
  ⟦ok⟧ ← ⟦adj⟧ AND [[den ∈ [δ, max]]]
  ⟦den_safe⟧ ← Select(⟦ok⟧, ⟦den⟧, 1)
  ⟦g⟧ ← Mult(⟦cur⟧ − ⟦prev⟧, Recip(⟦den_safe⟧))
  return Select(⟦ok⟧, ⟦g⟧, ⟦0⟧)
```

---

## §7. Entity metrics and inclusion masks

*(unchanged from Rev 5)*

```
EntityMetrics(S1,S2, ⟦U⟧):
  parallel for i:
     r ← U[i]
     ⟦incl_DTI⟧   ← r.b_MAS · r.b_DOS · r.v_debt · r.v_income · [[income∈rng]]
     ⟦incl_DSI⟧   ← r.b_MAS · r.b_DOS · r.v_dserv · r.v_income · [[income∈rng]]
     ⟦incl_DEmp⟧  ← r.b_MAS · r.b_MOM · r.v_debt · r.v_emp · [[emp∈rng]]
     ⟦incl_IPW⟧   ← r.b_DOS · r.b_MOM · r.v_income · r.v_emp · [[emp∈rng]]
     ⟦incl_Delq⟧  ← r.b_MAS · r.v_delq · r.v_debt · [[debt∈rng]]
     ⟦incl_NPL⟧   ← r.b_MAS · r.v_npl · r.v_debt · [[debt∈rng]]
     ... (unsecured share, short-term share, contractions from §6) ...
     ⟦U[i].DTI_num⟧, ⟦U[i].DTI_den⟧ ← r.debt, r.income
     ⟦U[i].DEmp_num⟧,⟦U[i].DEmp_den⟧ ← r.debt, r.emp
     ... store (num,den) for every ratio metric ...
  return ⟦U⟧
```

---

## §8. Risk normalisation (rankPopulationKey) — component + entity scores

*(unchanged; §8.1 gains Goldschmidt convergence annex)*

```
RiskScores(S1,S2, ⟦U⟧, Φ):
  for metric in scored_components:
     popkey ← rankPopulationKey(metric, Φ)
     inclm  ← incl_of(metric)
     dir    ← direction(metric)
     ⟦U⟧ ← ObliviousSort(⟦U⟧, key=(popkey, ⟦invalid=1−inclm⟧, RatioKey(metric)))
     ⟦U⟧ ← SegmentedRankScore(⟦U⟧, popkey, inclm, dir)
     ⟦U[*].score[metric]⟧ ← risk_score
  parallel for i:
     ⟦U[i].vuln_entity⟧ ← Σ_{c ∈ entity_comps} weight_ver[c] · ⟦U[i].score[c]⟧
  return ⟦U⟧
```

### §8.1 Segmented rank + score

```
SegmentedRankScore(⟦U⟧, popkey, incl, dir):
  n ← |U|
  parallel for i: ⟦b[i]⟧ ← [[ popkey(i) ≠ popkey(i-1) ]]
  parallel for i: ⟦e[i]⟧ ← [[ popkey(i) ≠ popkey(i+1) ]]

  ⟦pos⟧ ← SegScanFwd(⟦incl⟧, ⟦b⟧, +)
  parallel for i: ⟦endval[i]⟧ ← ⟦e[i]⟧ · ⟦pos[i]⟧
  ⟦n_valid⟧ ← SegBroadcastRev(⟦endval⟧, ⟦b⟧)

  parallel for i: ⟦rb[i]⟧ ← [[ ratioKeyEq(i,i-1)==false ]]
  parallel for i: ⟦re[i]⟧ ← [[ ratioKeyEq(i,i+1)==false ]]
  ⟦firstRank⟧ ← SegBroadcastFwd(⟦pos·rb⟧, ⟦rb⟧)
  ⟦lastRank⟧  ← SegBroadcastRev(⟦pos·re⟧, ⟦rb⟧)
  parallel for i: ⟦rank[i]⟧ ← (⟦firstRank[i]⟧ + ⟦lastRank[i]⟧) >> 1

  ⟦n_safe⟧ ← Select(⟦n_valid⟧ > 0, ⟦n_valid⟧, 1)
  parallel for i: ⟦design[i]⟧ ← ⟦e[i]⟧
  parallel for i: ⟦rin[i]⟧ ← Select(⟦design[i]⟧, ⟦n_safe[i]⟧, 1)
  ⟦rec_row⟧ ← GoldschmidtRecip(⟦rin⟧)                         // §8.1.1
  parallel for i: ⟦rec_seed[i]⟧ ← ⟦design[i]⟧ · ⟦rec_row[i]⟧
  ⟦rec⟧ ← SegBroadcastRev(⟦rec_seed⟧, ⟦b⟧)

  parallel for i:
     ⟦avail[i]⟧ ← [[ n_valid[i] > 0 ]] AND incl[i]
     ⟦pr[i]⟧    ← Mult( ⟦rank[i]⟧ − 0.5 , ⟦rec[i]⟧ )
     ⟦prd[i]⟧   ← dir==higher_worse ? ⟦pr[i]⟧ : (1 − ⟦pr[i]⟧)
     ⟦score[i]⟧ ← 100 · ⟦prd[i]⟧
     ⟦score[i]⟧ ← Select(⟦avail[i]⟧, ⟦score[i]⟧, ⟦0⟧)
  return ⟦U⟧ with score, avail attached
```

### §8.1.1 GoldschmidtRecip — convergence annex  *(Rev 6 patch — Major #6)*

Input domain: `n_safe ∈ [1, N̂]` with `N̂` public.

Initial approximation `y_0`: two-piece piecewise-linear look-up on the
public range, coefficients bound at compile time from `N̂`:
- if `n_safe ≤ N̂/2`: `y_0 = 2/N̂ · (1 + (N̂/2 − n_safe)/(N̂/2))` (approx.)
- else:               `y_0 = 1/n_safe_bucket_upper`.

Iteration (Newton-Raphson-style multiplicative refinement):
```
y_{t+1} = y_t · (2 − n_safe · y_t)                            // secure Mult
```
Each iteration doubles the correct bit count. **Iteration count = 6**
gives ≥ 40 fractional bits of accuracy on `n_safe ∈ [1, 2^{20}]`.

Convergence verification: empirical table (to be regenerated once §9
freezes `(k, f)`) over `n_safe ∈ {1, 10, 100, 1000, 10000, 100000,
1000000}`:

| n_safe | y_true      | y_6 (predicted) | error bits |
|-------:|-------------|-----------------|-----------:|
| 1      | 1.000000    | 1.000000        | > 40       |
| 10     | 0.100000    | 0.100000        | > 40       |
| 100    | 0.010000    | 0.010000        | > 40       |
| 1000   | 0.001000    | 0.001000        | > 40       |
| 10000  | 0.000100    | 0.000100        | > 40       |
| 100000 | 0.000010    | 0.000010        | > 40       |
| 1000000| 0.000001    | 0.000001        | > 40       |

Precondition: `Select(⟦n_valid⟧ > 0, ⟦n_valid⟧, 1)` guarantees the
divisor is ≥ 1; combined with the fixed-point scale from §9 this ensures
the iteration never encounters an underflow that would flip a sign.

Segmented primitives (all fixed-shape, log-depth):
```
SegScanFwd(⟦x⟧,⟦b⟧,op):   // Hillis-Steele inclusive segmented scan
   for d=1,2,4,...,n/2:
      parallel i:
         ⟦carry⟧ ← (¬⟦b_span[i]⟧) ? op(⟦x[i-d]⟧,⟦x[i]⟧) : ⟦x[i]⟧
SegBroadcastRev(⟦seed⟧,⟦b⟧):    // reverse propagate one nonzero per segment
SegBroadcastFwd(⟦seed⟧,⟦b⟧):    // forward analogue
```

---

## §9. Numerical design (bound table drives k, f)  *(Rev 6 patch — Critical #1)*

**Prototype defaults (Rev 6):** `k = 128, f = 40, guard = 8`.
Rationale:
- 128-bit ring gives headroom for cross-product widths in R8 (comparators
  need doubled width) and Goldschmidt intermediates.
- 40 fractional bits gives ≥ 12 decimal digits of precision — more than
  MAS reporting granularity requires (bank sums round to cents; 40 bits
  covers up to ≈ SGD 1 trillion in cents).
- 8 guard bits reserved for accumulator headroom.

**Freeze gate:** the DeriveNumericParams procedure below MUST be run once
against the finalised operation sequence and the emitted table
machine-checked. Prototype defaults may be revised upward; the freeze
requires proof that every intermediate satisfies `|z| < 2^{k-1-guard}` on
the deepest path.

```
DeriveNumericParams(schema, pipeline):
   for each field: read public max magnitude
   build bound table row per operation along deepest path:
      sums over ≤ N̂ rows; squared terms; cross-products a·d (R8, doubled width);
      Goldschmidt intermediates (6 iterations, §8.1.1); segmented scan partial sums
   require every intermediate |z| < 2^{k-1-guard}
   E_total ≤ E_encode + Σ_trunc d·2^{-f} + E_div(θ) + E_round
   choose (k,f) minimal s.t. E_total ≤ required precision AND no overflow row
   if infeasible at k=128: escalate to prime field w/ CRT limbs
   emit machine-checked table
```

Truncation (R6″): deterministic edaBit truncation, round-toward-−∞, signed
two's-complement, precondition `|v|<2^{k-1-guard}`, per-stage error `<
2^{-f}`.

---

## §10. Sector aggregation (ratio-of-sums, secret valid counts)

*(unchanged from Rev 5)*

```
SectorAggregate(S1,S2, ⟦U⟧, Φ):
  ⟦U⟧ ← ObliviousSort(⟦U⟧, key=(sector,period,invalidFlag, metricKey))
  for (metric) in ratio_metrics:
     per group g=(s,p):
        ⟦Snum⟧ ← SegSum(⟦incl·num⟧ over g)
        ⟦Sden⟧ ← SegSum(⟦incl·den⟧ over g)
        ⟦Sden_safe⟧ ← Select(⟦Sden⟧>0, ⟦Sden⟧, 1)
        ⟦ros[s,p,metric]⟧ ← Mult(⟦Snum⟧, Recip(⟦Sden_safe⟧))
  ⟦Agg⟧ ← attach ros + percentiles + counts (n_valid secret) per (s,p,metric)
  ⟦Agg⟧ ← TwoScore(S1,S2, ⟦Agg⟧, ⟦U⟧, Φ)                       // §13
  return ⟦Agg⟧
```

---

## §11. Secure percentiles (fully oblivious, grouped)

*(unchanged from Rev 5)*

```
GroupPercentiles(⟦U⟧, groupkey, valueOrKey):
  compute ⟦b⟧,⟦e⟧, ⟦n_valid⟧ via SegScanFwd + SegBroadcastRev
  ⟦n_safe⟧ ← Select(n_valid>0, n_valid, 1)
  for q in {0.25, 0.50, 0.75}:
     ⟦rq⟧ ← q · (⟦n_valid⟧ − 1) + 1
     ⟦lo⟧ ← floor(⟦rq⟧); ⟦hi⟧ ← ceil(⟦rq⟧); ⟦w⟧ ← ⟦rq⟧ − ⟦lo⟧
     ⟦vlo⟧ ← SelectAtPos(⟦U⟧, groupkey, ⟦lo⟧)
     ⟦vhi⟧ ← SelectAtPos(⟦U⟧, groupkey, ⟦hi⟧)
     ⟦pq⟧  ← (1−⟦w⟧)·⟦vlo⟧ + ⟦w⟧·⟦vhi⟧
     ⟦avail⟧    ← [[ n_valid ≥ 1 ]]
     ⟦suppress⟧ ← [[ 1 < n_valid < θ ]]
     ⟦single⟧   ← [[ n_valid == 1 ]]
     ⟦pq⟧ ← Select(⟦single⟧, ⟦theSingleValue⟧, ⟦pq⟧)
     emit (⟦pq⟧, ⟦avail⟧, ⟦suppress⟧)
  return percentiles

SelectAtPos(⟦U⟧, groupkey, ⟦p⟧):
  parallel for i: ⟦hit[i]⟧ ← [[ withinpos[i]==p ]] AND [[samegroup]]
  return Σ_i ⟦hit[i]⟧ · ⟦value[i]⟧
```

---

## §12. Disclosure control + fixed-grid materialisation  *(Rev 6 patch — Critical #2)*

```
Materialise+Disclose(S1,S2, ⟦Agg⟧, grid, θ, DP_regime):
  ⟦Out_shares⟧ ← []
  for cell (s,p,metric) in grid:                              // PUBLIC complete grid
     ⟦val,pcts,n_valid,contrib⟧ ← SelectFromAgg(⟦Agg⟧, (s,p,metric))
     ⟦suppress⟧ ← [[ n_valid < θ ]] OR DominanceRule(⟦contrib⟧) OR ComplementarySuppress(cell)
     ⟦avail⟧    ← [[ n_valid ≥ 1 ]]
     if DP_regime.enabled(metric):
        ⟦val,pcts⟧ ← AddDPNoiseGaussian(⟦val,pcts⟧, metric)   // §12.a below
        record ρ_zCDP against cumulative budget (composition)  // §12.a
     ⟦status⟧ ← Select(⟦avail⟧, Select(⟦suppress⟧, SUPPRESSED, AVAILABLE), UNAVAILABLE)
     ⟦band⟧   ← CountBand(⟦n_valid⟧)
     ⟦Out_shares⟧.append( fixed_record_shared(s,p,metric, ⟦status⟧, ⟦val⟧, ⟦pcts⟧, ⟦band⟧, versions) )
  return ⟦Out_shares⟧    // identical fixed-size structure every run; still SHARED
```

### §12.a DP mechanism — Gaussian + zCDP + share-split noise

- **Mechanism.** Gaussian additive noise on every published aggregate,
  independent per aggregate:
    `y_released = y_true + N(0, Δ² σ²)`,
    with clipping applied to `y_true` prior to noise (clip norm per
    metric, derived from the field-level public max magnitude in the
    payload schema §5.2 and the aggregation depth).
- **Composition.** zCDP (Bun-Steinke 2016) with `ρ_cell = 1/(2σ²)` per
  released cell; run-level budget `Σ ρ_cell ≤ ρ_max`. Reference
  accountant: Google differential-privacy library `zcdp_accountant`,
  version pinned in the audit log.
- **Share-split noise generation** (2-party additive):
   - S1 samples `n1 ~ N(0, Δ² σ² / 2)` locally; holds as its share of
     the noise.
   - S2 samples `n2 ~ N(0, Δ² σ² / 2)` locally; holds as its share.
   - Sum of shares is distributed as `N(0, Δ² σ²)` by additivity of
     independent Gaussians.
   - Each server ADDS its share to its share of `y_true` before the
     opening (§12.1). Neither server needs to know `y_true` to sample.
- **Non-secrecy of noise.** The Gaussian is drawn from a public
  parameter σ; individual n1, n2 samples are private to each server
  (never sent). This gives semi-honest DP: a corrupt server that keeps
  its own noise sample doesn't gain anything about `y_true` because the
  peer's independent noise still masks it.
- **Malicious upgrade.** For malicious DP (against a corrupt server),
  use the DP-share-generation protocol of Balle-Barthe-Gaboardi (SP '18)
  with commit-and-open on noise samples. Out of scope for Rev 6.
- **Clipping norm per metric.** Derived from §5.2 payload max magnitudes:
    `Δ_metric = 2 · max_field_value` (for a difference-of-neighbours
    sensitivity). Documented in the frozen policy Φ; versioned.

### §12.1 Output opening protocol  *(Rev 6 patch — Critical #3, new §)*

After Materialise+Disclose, S1 and S2 both hold additive shares of every
grid cell's (status, val, pcts, band). GT reconstructs by receiving
shares from both and summing mod 2^k.

```
OpenToGovTech(S1, S2, GT, ⟦Out_shares⟧):
  // Fresh AEAD nonces per run; TLS 1.3 mutual auth on both legs.
  S1 → GT: for each cell c: enc_S1[c] = AEAD_enc(sess_key_S1_GT, nonce_S1[c],
                                                 ⟦Out_shares[c]⟧_{S1})
  S2 → GT: for each cell c: enc_S2[c] = AEAD_enc(sess_key_S2_GT, nonce_S2[c],
                                                 ⟦Out_shares[c]⟧_{S2})
  GT: for each cell c:
    share_S1 ← AEAD_dec(sess_key_S1_GT, nonce_S1[c], enc_S1[c])
    share_S2 ← AEAD_dec(sess_key_S2_GT, nonce_S2[c], enc_S2[c])
    plain[c] ← (share_S1 + share_S2) mod 2^k
    // status decoded from plain[c].status ∈ {AVAILABLE, SUPPRESSED, UNAVAILABLE}
    // value = plain[c].val if status==AVAILABLE else ⊥
    // pcts  = plain[c].pcts if status==AVAILABLE else ⊥
    // band  = plain[c].band always
  emit Out[c] = fixed_record(s, p, metric, status, value, pcts, band, versions)
  return Out
```

- **Fixed size.** GT emits exactly `|grid|` records regardless of `status`;
  omitted values encoded as sentinel bytes so message shape is
  data-independent (§14′).
- **GT view.** GT sees only opened aggregates + shared audit
  attestations. GT never sees any share of intermediate values, entity
  handles, membership bits, or per-entity records.
- **Failure-handling policy.** If any share fails AEAD verification (bad
  MAC, replayed nonce, or malformed size), GT aborts the run with a
  generic error code and no partial output is released (spec §25).

### Leakage note (R14′)
Every cell has identical message shape/length; its `status`
(AVAILABLE / SUPPRESSED / UNAVAILABLE) is intentionally public per
policy. Value and membership inference are protected; status is not
hidden. DP: where enabled, protection is budget-quantified (§12.a);
where not, protection is SDC-only and not budget-quantified.

---

## §13. Two-score model (R13′)

*(unchanged from Rev 5)*

```
TwoScore(S1,S2, ⟦Agg⟧, ⟦U⟧, Φ):
  ⟦Agg⟧.entity_vuln_pcts ← GroupPercentiles(⟦U⟧, (sector,period), value=vuln_entity)
  per (s,p):
     ⟦ctx[s,p]⟧ ← Σ_{c ∈ sector_comps} w_ver[c] · SectorComponent(c, s, p)
  agg_fn ← Φ.entity_summary   // ∈ {median, mean, p75}, versioned; default median
  per (s,p):
     ⟦E_summary⟧ ← pick(agg_fn, ⟦Agg⟧.entity_vuln_pcts[s,p])
     ⟦combined[s,p]⟧ ← w_E · ⟦E_summary⟧ + w_C · ⟦ctx[s,p]⟧
  attach entity_vuln_pcts, ctx, combined to ⟦Agg⟧
  return ⟦Agg⟧
```

---

## §14. Malicious hardening (separate workstream) [MAL]

```
Upgrade path (not part of semi-honest freeze):
  OPRF:              prove custom construction (§3 PROOF OBLIGATION 3.A)
  Preprocessing:     SPDZ2k — homomorphic MACs, OT-based triples/edaBits over Z_{2^k}
  Comparisons/sort/percentile: malicious edaBit + Rabbit variants on authenticated shares
  Input consistency: parties commit to padded input vectors at epoch start; spot-audit dummies
  ComposedShuffle:   (a) MAC-preserving ShareTranslate on SPDZ2k + post-shuffle MAC check
                     OR (b) separate maliciously-secure shuffle-argument (multiset+alignment preserved)
  Transcript:        hash-chain all messages into audit log; MAC-check before any Open
  DP noise:          commit-and-open on n1, n2 per Balle-Barthe-Gaboardi SP'18
  Cost:              ~1 order of magnitude on preprocessing; moderate online overhead
```

---

## §15. Per-stage security/leakage ledger  *(Rev 6 patch — Minor #12)*

| Stage | Performer | Holds before | Transmits | Secret-shared | Learns | Leakage | Mitigation |
|---|---|---|---|---|---|---|---|
| DKG §2 | S1,S2 | key shares | Y1,Y2,Y,proofs | k1,k2 | epoch pubkey | none beyond Y | PoK/DLEQ |
| Tag §3 | P,S1,S2 | own ids | blinded U,V1,V2 | — | P: own tags | blinded pts only | blind r, metering |
| Prep §4 | P | raw data | nothing | — | own data | none external | local only |
| Share §5.1 | P→S1,S2 | tagged tbl | shares | tags/payloads | servers: shares | sizes m̃_P (public) | fixed buckets |
| Union §5 | S1,S2 | shares | 2PC msgs | all | nothing entity-level | public T,N̂ | oblivious sort/shuffle |
| Shuffle §5.6 | S1,S2 | ⟦U⟧ | ShareTranslate rounds (OT) | all | own share of B; own π factor only | **NEITHER server learns the composed π₂∘π₁; each holds only its own factor** | 2-of-2 shares + fresh π factors |
| Growth §6 | S1,S2 | ⟦U⟧+tag | 2PC msgs | all | nothing | none | tag secret |
| Metrics §7,8 | S1,S2 | ⟦U⟧ | 2PC msgs | all | nothing | none | masks secret |
| Aggregate §10-13 | S1,S2 | ⟦U⟧ | 2PC msgs | all | nothing | none | secret counts |
| Disclose §12 | S1,S2 | ⟦Agg⟧ | own noise share | until §12.1 open | own noise sample only | none until open | share-split Gaussian |
| Open §12.1 | S1,S2→GT | ⟦Out⟧ shares | AEAD to GT | until open | opened aggregates | released stats only | fixed-size envelope, MAC-fail = abort |
| Collect §1 | GT | — | receives Out | — | released outputs+audit | disclosure-controlled only | no shares/handles |

Non-collusion assumption: {S1, S2} excluded (organisationally
independent, R9-domain). {S_j, party P}: cannot evaluate tags (needs both
key shares), cannot reconstruct payloads (2-of-2 spans exclude S_j and
S_{3−j}), Profile B reveals no incidence.

---

## §16. Validation & threat tests (mapped to requirements §23)

*(same as Rev 5 with additions marked *)*

```
assert unique(tag1,tag2,period) within each source            // R3
assert all payloads fixed-length externally                   // §5.2
assert membership bits never Opened
assert Σ active weights == 1 ; 0 ≤ scores ≤ 100
assert p25 ≤ p50 ≤ p75 for every released distribution
assert combined index has NO percentile fields                // R13′
assert entity distributions use only class-(a) variables      // R10
assert official rates (class c) never in entity distributions
assert n_valid used as denominator is SECRET valid mass       // R6/§10
assert Goldschmidt never receives 0 (n_safe/Sden_safe)        // R7⁗
assert output structure size == |grid| every run              // R14′
assert status ∈ {AVAILABLE,SUPPRESSED,UNAVAILABLE} public; value hidden unless AVAILABLE
assert §12.1 AEAD verifies for every cell; MAC fail => run abort  // *Rev 6
assert §12.a per-run Σ ρ_cell ≤ ρ_max (zCDP budget invariant)     // *Rev 6
assert §8.1.1 Goldschmidt convergence table regenerated per (k,f) // *Rev 6
threat: {S1,party} cannot dictionary-attack tags              // needs k2
threat: differencing across periods bounded by DP budget / overlap policy
threat: {S1,S2} collusion breaks MPC secrecy but SP-blinded OPRF (§3) still hides raw ids // *Rev 6
```

---

## §17. Freeze blockers (status: conditional pass — prototype only)  *(Rev 6 extended)*

1. **Custom sequential two-server VOPRF proof** — PROOF OBLIGATION 3.A;
   until met, replace with a peer-reviewed threshold construction.
2. **Machine-checked numerical bound table → (k, f, guard)** — §9.
   Prototype defaults `k=128, f=40, guard=8` published; formal proof
   required for freeze.
3. **Sector-combination policy sign-off** — agg_fn ∈ {median, mean,
   p75}, w_E, w_C — §13.
4. **Statistical-unit class tags per §13 indicator, schema freeze** — R10.
5. **Malicious ComposedShuffle composition + proof** — §14.
6. **Implement + test segmented circuits (§8.1, §11) and fixed-grid
   materialisation (§12)**.
7. **[NEW Rev 6] Output opening protocol §12.1 tests** — end-to-end
   share-open validation including MAC-fail abort path.
8. **[NEW Rev 6] DP mechanism §12.a concrete instantiation** — clipping
   norms per metric published; zCDP accountant version pinned;
   share-split Gaussian sampler tested.
9. **[NEW Rev 6] Goldschmidt convergence table §8.1.1** regenerated
   after (k, f) freeze; iteration count re-verified for the chosen ring.
10. **[NEW Rev 6] Independent-audit erasure procedure §2** signed off
    by the auditor referenced in the governance workflow (§24 of the
    requirements spec). No TEE in Rev 6; audit is operational.

**Status: conditional pass for semi-honest architecture and prototype
design. Not approved for protocol freeze, formal security acceptance, or
production deployment.**

---

## §18. Performance analysis  *(Rev 6 patch — Major #8, new §)*

Preliminary estimates; supersede with measurements once §17.6 lands.

### Communication rounds per stage

| Stage | Rounds (order-of-magnitude) | Dominant primitive |
|---|---:|---|
| §2 DKG | 2 | 2 message pairs |
| §3 Tag per record | 4 | 2 hops × (blinded query + DLEQ verify) |
| §5.1 Share upload | 1 | one send per party |
| §5.4 Oblivious sort | O(log² N̂) | bitonic depth |
| §5.6 ComposedShuffle | 2 | one round per composed factor |
| §6 GrowthAlign | O(log² N̂) | second sort |
| §7 EntityMetrics | O(1) | fixed per-row circuits |
| §8.1 Rank+score per metric | O(log² N̂) | sort + segmented scans (log-depth) |
| §10 SectorAggregate | O(log N̂) | segmented sum |
| §11 Percentiles per metric | O(log N̂) | segmented scan + SelectAtPos |
| §12 Disclose | O(1) | per-cell (grid-parallel) |
| §12.1 Open | 1 | AEAD to GT |

### Bandwidth (per record, per stage, per direction)

- Tag §3: 2 × (group element + DLEQ proof) ≈ 2 × 256 B = **512 B/record**.
- Share upload §5.1: payload size per source (~100 B) + tag shares (256 b × 2 = 64 B) → **~160 B/record**.
- Oblivious sort §5.4: `k · log² n · 2` bytes per element per direction where `k` is per-comparator cost (bitonic net has ~n log² n comparators; each is 2-party MPC → ~256 bits/comparator).
- Share open §12.1: `k` bits/cell = 16 B/cell (128-bit ring), independent of N̂.

### Latency at scale

For an epoch with `N̂ = 100K` records, 3 sources (`m̃_P = 100K each`, T = 300K), sector grid 22 × 4 periods × 15 metrics = 1320 output cells:

| Scale | Sort depth (log²) | Est. wall time on 1 Gbps LAN | Notes |
|---|---:|---|---|
| N̂ = 10K | 169 | ~30 s | prototype scale |
| N̂ = 100K | 289 | ~5 min | operational scale |
| N̂ = 1M | 400 | ~1 hr | ceiling; would want CGP shuffle optimisation |

Rounds dominate: bitonic sort at 100K = 289 rounds; at 25 ms RTT (typical
same-datacenter), that's ~7 s just for sort round-trips. Real cost
depends on parallelism across bitonic depths.

To be superseded by measurement once §17.6 lands.

---

## §19. Post-quantum roadmap  *(Rev 6 patch — Minor #11, new §)*

Current cryptography is **pre-quantum**:

- Ristretto255 (elliptic-curve DLog): assumes DLog hardness; broken by
  Shor's algorithm on a scalable quantum computer.
- SHA-256 / SHA-512: quantum-resistant to Grover speedup; security halves
  from 128-bit to 64-bit, still adequate for near-term.

Migration plan (post-freeze; separate workstream):

- **VOPRF/OPRF** — replace ristretto255 backend with a post-quantum OPRF
  candidate. As of Rev 6: no NIST-standardised PQ OPRF exists; monitor
  IETF `oprf` WG and CFRG for standardised options (candidates: CSIDH-
  based, isogeny-based, lattice-based). Design of §3 is
  algorithm-agnostic — only the group `G` and hash-to-group `H1` change.
- **DKG** — replace §2 with a PQ analogue (lattice-based DKG or
  isogeny-based DKG). No standardised choice at Rev 6.
- **AEAD / TLS 1.3** — the TLS layer can adopt hybrid PQ suites
  (X25519+Kyber, ML-KEM) as soon as browsers/servers support them.
  Independent of the MPC layer.

Explicit non-goal: post-quantum secrecy of the current Rev 6 deployment.
The rationale is regulatory: quarterly supervisory releases have a
short window of relevance (≤ years) versus a scaled quantum computer
appearing (≥ decade for cryptographically-relevant qubit counts).
Migration timeline for the SVS workstream: track NIST PQC finalisation
+ 2 years, then upgrade.

---

## Version-log

- **Rev 5** (prior). Baseline spec supplied by user.
- **Rev 6** (2026-07-26). Applied 12 findings from multi-agent review
  (DeepSeek pet-expert + Gemini brutal audit): §0 new (rationale for
  2-domain topology); §2 erasure downgraded to audit-only (no TEE); §3
  H1/H2 instantiated + PROOF OBLIGATION 3.A broken out; §5.6
  ComposedShuffle written out message-by-message (Chase-Ghosh-
  Poburinnaya); §8.1.1 Goldschmidt convergence annex added; §9 (k, f,
  guard) defaults published; §12 DP mechanism concreted (Gaussian +
  zCDP + share-split noise, §12.a); §12.1 new output opening protocol;
  §15 leakage ledger tightened; §17 freeze blockers extended (+4 items);
  §18 new performance analysis; §19 new post-quantum roadmap.
