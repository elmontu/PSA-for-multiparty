# Privacy audit — inputs and intermediates

Companion to `docs/AUDIT_R37.md`. That document verifies functional
correctness; this one verifies that **no party learns more than the
threat model allows** at any protocol step.

The audit method for each protocol layer:

1. **Threat model**: who is honest, who is honest-but-curious, who can collude.
2. **Inputs**: what each party privately holds at start.
3. **Wire messages**: exactly what bytes cross which socket, and whether they are random-masked, AEAD-sealed, or plain.
4. **Intermediates**: what each party holds mid-protocol and whether reconstruction leaks any raw input.
5. **Outputs**: what each party learns at the end.
6. **Test-witnesses**: which tests would fail if this claim were broken.

Layers audited below match the module structure in `volePSI/Mp*.h`.

---

## Layer 0 — CSV ingest (all protocols)

`parseCsv`, `parseCsvForJoin`, `parseCsvForMpcJoin`, and the
`readSet`+`gen_mpsa_dataset.py` path all operate on **files owned by
one party**. No cross-party leak in ingest itself; each party parses
its own CSV.

The one caveat is `readSet` uses a fixed `RandomOracle` (SHA-based)
hash for non-hex string IDs. This is **deterministic hashing**: two
parties with the same string ID get the same 128-bit hash. That's
required for intersection but means an offline dictionary attack
against a known small ID space is possible on any exposed hash.
Mitigated by T15 salted MPSI (`-salt-mpsi`) which XORs a per-session
salt into IDs before hashing.

Witness: `test_mpstar_crypto` covers AEAD invariants; salt is a
protocol-flag layer.

---

## Layer 1 — Base MPSA cascade (`frontend -mpsa`)

**Threat model**: semi-honest. SP is passive; senders are non-colluding.

**Inputs**:
- Each sender `i` holds `(id_i[], payload_i[])`.
- SP holds nothing initially.

**Wire messages** (per session; all sender→SP AEAD-sealed under
per-session X25519-derived keys):
- `sessionId` (32 B), broadcast by SP.
- Ephemeral DH pubkeys (X25519).
- Sender-set-size (uint64_t).
- MPSI VOLE / OPRF messages (private under the underlying VOLE-PSI
  construction).
- **`m_i = c_i XOR r_i`** — sender `i`'s masked payload column. `r_i`
  is a fresh uniform random from a per-sender local PRNG.
- Cascade OSN messages: per-round OSN A/B calls between SP and one
  sender, plus peer-mesh handoff of `R_{k+1}` shares between senders.
- Final reveal: last sender ships `R_final` (AEAD-sealed under SP
  key) so SP can XOR with `M_final`.

**What SP sees**:
- Masked payloads `m_i = c_i XOR r_i`. Since `r_i` is uniformly random
  and unknown to SP, `m_i` reveals nothing about `c_i` (perfect
  hiding for the OTP masking).
- Cascade OSN shares, which are also uniform random from SP's view
  (OSN outputs are half of a two-party random additive share).
- Final shuffled joined output (this is the INTENDED reveal).

**What each sender sees**:
- Own inputs.
- Own `r_i` (locally generated).
- Its share of the R-column being carried through the cascade until
  handoff to the next sender.
- Ephemeral DH shared secret with each other sender (via peer mesh
  `MpStarSetup`).

**Intermediates leaked to SP**: nothing beyond what MPSI itself
reveals (the intersection cardinality, unless suppressed by
`-cmax`/`-dp`/`-mink`).

**Sender-to-sender leaks**: sender 0 receives every other sender's
`r_j` in Phase 0 (needed to build the initial R state). Sender 0 can
therefore reconstruct any other sender's `c_j` from `m_j XOR r_j` IF
sender 0 also sees `m_j`. Sender 0 does **not** see `m_j` because
`m_j` goes only sender-j → SP under AEAD. So this leak requires
sender-0 + SP collusion. Documented in `docs/SECURITY_ANALYSIS.md`.

**Test-witnesses**: `run_mpsa_smoke.sh` end-to-end; per-primitive
tests in `test_mpstar_crypto` for AEAD tamper detection, `test_mac`
for MAC tag preservation across cascade rounds.

**Verdict**: inputs private under the stated threat model.

---

## Layer 2 — Wide-payload cascade (`-pw W`)

Identical structure to Layer 1 with `N × W` cascade columns instead
of `N`. Each column is a single-block additive share. The masking
`m_i[c] = payload_i[c] XOR r_i[c]` extends across all `W` blocks per
sender.

No new leak vectors. Verified by `run_mpsa_wide_smoke.sh`.

---

## Layer 3 — MAC-propagating cascade primitives (R25, in-memory)

**Modules**: `MpMac`, `MpAuthCascade`.

**Purpose**: detect tampering, not add privacy — the MAC layer sits
on top of an existing shared value.

**What crosses party boundaries**: tag shares that XOR to `α · data`.
Under the R25 threat model (α is per-round shared secret between SP
and the active sender), the tag shares are functions of the data
share and reveal no additional information beyond what the data
share already leaks.

**Test-witness**: `test_mac`, `test_auth_cascade`. The tamper-catch
test verifies that a data-only flip is detected, meaning the tag
carries binding-not-just-privacy properties.

**Verdict**: no new inputs or intermediates crossed; augments R1's
privacy claim with active-tamper detection.

---

## Layer 4 — R28 α-sharing, trusted-dealer variant (`MpOleAlpha`)

**Threat model**: SPDZ-style two-party. Neither party knows joint α;
no single-party corruption reveals data.

**Inputs**:
- Party A holds `α_A` (its own share of the joint MAC key).
- Party B holds `α_B`.
- One party ("input party") holds plaintext `x` to be authenticated.

**Trusted-dealer OLE step**: dealer picks `α_A`, `x_B` from party
inputs and generates a random mask `a` such that `α_A · x_B = a XOR c`.
Party A receives `(α_A, a)`; Party B receives `(x_B, c)`.

**INPUT LEAK POSITION**: the **dealer sees `α_A` and `x_B` in
plaintext**. This is the exact place where trusted-dealer semantics
break real security. Documented at the top of `MpOleAlpha.h`.

**Wire-level leak**: none in the trusted-dealer variant — no wire
sends. The dealer is a local function.

**What each party sees post-`authShareInput`**:
- Input party: `(data = plain, tag = α_own · plain XOR c)`. From
  Party A's view (if A is the input party), `α_own · plain` is
  computable, `c` was received from the dealer. Neither reveals `α_B`.
- Non-input party: `(data = 0, tag = a)`. `a` is uniform random from
  their view.

**INTERMEDIATE LEAK**: NONE beyond the documented dealer leak.

**Test-witness**: `test_ole_alpha` (6 checks) validates joint-tag
invariant, tamper-catch (data-only flip), and MacCheck under random
challenge.

**Verdict**: private against non-dealer parties. The dealer is the
documented gap.

---

## Layer 5 — R28 α-sharing, wire variant (`oleGf128OverWire`)

**Threat model**: same as Layer 4, plus a network attacker.

**Wire messages** (per call, LocalAsyncSocket or TCP):
1. 16 B random handshake contribution (each way).
2. **16 B input value** (`α_A` from party 0, `b` from party 1) — sent
   **in plaintext**.

**INPUT LEAK POSITION** — flagged during audit:

The wire scaffold currently sends `myInputValue` **in the clear** at
line 204 of `MpOleAlpha.cpp`:

```cpp
co_await sock.send(myInputBytes);  // sends alphaA or b in plaintext
```

This is the documented "shared-seed scaffold" pattern. It means the
peer learns:

- Party 1 sees Party 0's `α_A` (Party 0's α-share).
- Party 0 sees Party 1's `x` value being MAC'd.

Neither `α_A` nor `x` alone breaks joint α = `α_A XOR α_B` — Party 1
knowing `α_A` doesn't reveal `α_B`. But Party 0 knowing `x` **does**
defeat privacy of the input being authenticated.

**Severity**: HIGH for the specific case of "authenticate a private
value for later revelation". LOW if `x` is a value that's public to
both parties anyway (e.g., a session parameter).

**Documentation**: the header explicitly says
`This is scaffolding for the libOTe silent-OT substitution — the wire
structure is in place; the security-completing step is replacing`.

**Test-witness**: `ole_gf128_over_wire_invariant` verifies **correctness**
(`α · b == a XOR c`) but does NOT assert privacy — it can't, because
the current implementation intentionally lacks it.

**Substitution point**: replacing `oleGf128OverWire` internals with a
libOTe `SilentVole` call over GF(2^128) closes this gap. The
surrounding code (handshake framing, `AuthShareMine` construction)
does not change.

**Verdict**: **NOT PRIVATE in current form**. Use trusted-dealer
`dealerOleGf128` for security-critical paths until SilentVole
substitution lands.

---

## Layer 6 — CGP shuffle (in-memory, `MpCgpShuffle`)

**Threat model**: 2-party semi-honest. Correlation from trusted
dealer.

**Wire messages**: none in the pure-in-memory API.

**Party A view**: `(a, α)`. `α = π(a) XOR b`; `a` random.
**Party B view**: `(π, b)`. `b` random.

**Online phase message A → B**: `m = x_A XOR a`. `a` is uniform
random from B's view; `m` reveals nothing about `x_A`.

**Intermediates**: `y_B = π(m XOR x_B) XOR b`. From A's view, both `π`
and `b` are unknown, so `y_B` is uniform-random-looking.

**Reconstruction**: `y_A XOR y_B = π(x_A XOR x_B)`. Only revealed by
joint reconstruction.

**Verdict**: private under the trusted-dealer assumption. Tested by
9 checks in `test_cgp_shuffle` including a message-blinding check.

---

## Layer 7 — CGP preprocessing over the wire (`MpCgpPreprocess`, R26b/step2)

**Threat model**: same as Layer 6.

**Wire messages**:
1. 16 B random handshake contribution (each way).

**No further messages** — both parties derive the FULL correlation
from the shared seed via a locally-run `cgpDealerGenerate`.

**INPUT LEAK POSITION**: since both parties derive the same
correlation from the shared seed:

- Party A learns **Party B's** `π` and `b` (which it should not).
- Party B learns **Party A's** `a` and `α` (which it should not).

Effectively both parties know the full correlation. The subsequent
CGP `online` phase remains functionally correct but no longer hides
anything.

**Severity**: HIGH for privacy of the shuffled result. Any actual
shuffle following this preprocessing has BOTH parties knowing `π`,
so the "hides permutation from B, hides x_A from B" property of
CGP shuffle is void.

**Documentation**: `MpCgpPreprocess.h` header explicitly says
`This is NOT cryptographically secure — it demonstrates the wire
structure so the substitution to real silent-OT-derived correlation
is a targeted change`.

**Test-witness**: `test_cgp_preprocess` verifies the correlation
invariant end-to-end AND drives `cgpRunInMemory` correctly, but
does NOT assert privacy.

**Substitution point**: replace the seeded-PRNG derivation with a
libOTe `SilentOtExtSender/Receiver` protocol that produces per-party
shares WITHOUT either party seeing the other's half.

**Verdict**: **NOT PRIVATE in current form**. Placeholder for OT
substitution.

---

## Layer 8 — Plaintext oblivious sort / expand / filter (R29-R31)

**Modules**: `MpObliviousSort`, `MpJoinExpander`, `MpJoinFilter`.

**Threat model**: these operate on **plaintext**. They are the
"oracle" used by the plaintext driver `MpsaJoinDriver`.

**Privacy property claimed**: **structural obliviousness** — the
sequence of memory accesses depends only on input length, not
values. This means these modules can be embedded in a secure
enclave or converted to MPC by replacing plaintext operations with
their secure equivalents without changing the control flow.

**Test-witness**: `structural_obliviousness_constant_count` in
`test_oblivious_sort` — two random inputs of the same length yield
the identical number of compare-and-swap calls.

**Verdict**: **no privacy protection by themselves**. Composition
correctness verified. Used privately only inside `MpMpcJoin`
(bit-shared inputs) or under trusted-SP model.

---

## Layer 9 — Trusted-SP wire join (`MpsaJoinDriverWire`, `-mpsa-join`)

**Threat model**: **explicit trusted-SP**. SP is entrusted with
plaintext inputs.

**Wire messages**: sender-to-SP AEAD-sealed blobs containing full
plaintext table rows.

**INPUT LEAK POSITION**: **SP sees all sender plaintexts after
AEAD decrypt**. This is the intended threat model — not a bug.

**Test-witness**: `run_mpsa_join_smoke.sh` validates end-to-end
correctness. No privacy assertion because SP is trusted.

**Verdict**: private **from anyone but SP**. Documented threat model.

---

## Layer 10 — SP-blind MPC join, in-process (`MpsaJoinMpcDriver`, `-mpsa-join-mpc`)

**Threat model**: SP is honest-but-curious; SP holds NO plaintext
inputs. Uses XOR-secret-sharing throughout.

**Where inputs enter**: `buildSharedTables` at line 108 of
`MpsaJoinMpcDriver.cpp` takes plaintext `perPartyRaw` (parsed from
the CSVs — running in a single process, so all CSVs are loaded).
Each row is bit-shared via `shareU64Bin`/`shareBit`.

**Simulation caveat**: because this driver runs all parties in ONE
process, all plaintexts are momentarily co-located in memory
during `buildSharedTables`. This is a **simulation artifact** —
in a real deployment each party would parse its OWN CSV in ITS OWN
process and produce shares. The driver is a research tool proving
the MPC pipeline arithmetic is correct.

**Post-sharing wire messages** (across the wire MPC ops, though
this driver runs them in-process via LocalAsyncSocket):
- Opens of `d = x XOR u`, `e = y XOR v` where `u, v` are Beaver-triple
  shares.

**Are opens leaky?** `d` and `e` are uniformly random from either
party's view because `u, v` are freshly sampled random values known
only to their respective share holders. Confirmed by the SPDZ
security proof (Damgård-Pastro-Smart-Zakarias, §3.2).

**Beaver triples**: generated by trusted dealer
(`generateBeaverTripleBit`) in this driver. The dealer sees `u, v, w`
plaintext. In R34k (`oleGenerateTriples`) the trusted dealer is
replaced by libOTe silent-OT protocol where neither party learns
the peer's share.

**Test-witness**:
- `test_mpc_join` (7 checks) validates end-to-end correctness on
  cases including "no intersection", "partial intersection", and
  "cross-product with dummies".
- `test_secret_share::secureMultiply_shares_hidden` checks that
  no single share equals the plaintext result.
- `test_secure_compare::secureLessThan_share_privacy` verifies not
  all party shares equal the expected outcome (rules out trivial
  reconstruction).

**Verdict**: private under the stated threat model. Simulation-only
in-process co-location of plaintexts is a research artifact, not a
protocol flaw.

---

## Layer 11 — Wire MPC primitives (`MpMpcWire`, R34k-remain)

**Threat model**: 2-party semi-honest. Neither party can see the
other's shares (validated by API — each function takes ONLY the
caller's own share).

**Wire messages** (`wireOpenBit`, `wireSecureAnd`):

- `wireOpenBit(myShare)`: sends `myShare` (1 byte, either 0 or 1)
  and receives peer's share. The joint value is `mine ⊕ theirs`.
- `wireSecureAnd`: sends `(myD, myE)` (2 bytes: `myD = myX ⊕ myU`,
  `myE = myY ⊕ myV`) and receives peer's pair.

**Privacy of the messages**:
- `myShare` in `wireOpenBit`: if the value being opened is a
  RESULT share (Beaver output, freshly randomized), the share is
  uniform random. If it's a value being **revealed** (like final
  outputs), then by definition it's meant to be reconstructed —
  no leakage claim needed.
- `d = x ⊕ u`, `e = y ⊕ v`: `u, v` are uniform random from the peer's
  view (drawn from the Beaver triple). Therefore `d`, `e` are uniform
  from the peer's view. Standard SPDZ argument.

**Constraint**: **Beaver triples must be freshly generated per
multiplication.** Reusing a triple lets the peer correlate opens
and recover `x, y`. Verified indirectly: every call in the codebase
consumes triples via a `tripleIdx` counter that advances
monotonically. `test_secure_compare::triple_count_exact` asserts
the count matches the analytic formula, meaning no triple is
double-consumed.

**Test-witness**: 6 checks in `test_mpc_wire`, including
`ole_triples_drive_wire_and` which validates that **real OLE-generated
triples** (from libOTe silent OT) drive the wire ops correctly.

**Verdict**: private under the SPDZ threat model, PROVIDED triples
are from a secure OLE source (Layer 12 below).

---

## Layer 12 — libOTe SilentOtTriple (`MpOleTriple`, R34k)

**Threat model**: 2-party semi-honest by default;
`oleGenerateTriplesMalicious` covers a single active corruption.

**Wire messages**: internal to libOTe's silent OT extension. Uses
LPN-based correlated randomness. Neither party's share is
observable by the peer.

**Privacy claim**: neither party learns the other's triple share.
This is inherited directly from libOTe.

**Test-witness**:
- `ole_triple_shares_random` sanity: my share of each triple
  component is not trivially all-0 or all-1 (statistical check on
  256 triples).
- `ole_triple_malicious_invariant`: malicious variant still
  produces valid triples.

**Verdict**: private under LPN hardness (libOTe's assumption).

---

## Layer 13 — R34k N-party via pairwise (`oleGenerateTriplesNParty`)

**Threat model**: each pair (0, k) has 2-party semi-honest security
via libOTe. **Any two colluding parties can reconstruct triples
they weren't meant to.**

**Wire messages**: N-1 pairwise silent-OT protocols run between
party 0 (hub) and each other party.

**INPUT LEAK POSITION**: the pairwise folding at the hub gives
party 0 access to intermediates that in a native N-party protocol
would be split N-ways. Specifically, party 0's aggregate share is
the XOR of contributions from each pair; while none of the
individual pair-shares reveal a specific peer's contribution, the
aggregate can be COMBINED WITH ANOTHER PARTY'S SHARE to reveal
partial information about the third party.

**Severity**: MEDIUM. Semi-honest 2-party per pair. N-party
threshold not achieved.

**Documentation**: header comment explicitly says
`Not N-party threshold-secure. Native N-party silent OT is
documented as follow-up.`

**Test-witness**: none for privacy (only correctness). This is
scaffolding.

**Substitution point**: replace with a native N-party OT extension.

**Verdict**: NOT N-party private. Suitable for a 2-party MPC join
where party 0 acts as the always-present hub.

---

## Layer 14 — Shuffle NIZKs (R27, R27b, R27c)

**Threat model**: prover has secret messages, openings, and
permutation; verifier sees only commitments and the proof.

**R27**: verifier check is INCOMPLETE (documented in
`shuffleVerify` comment block: "prototype's verifier is COMPLETE
but NOT SOUND"). Attackers who forge products can pass. 10 tests in
`test_shuffle_nizk` including `known_soundness_gap_documented`.

**R27b**: adds cryptographic sum-of-commitments check. Catches:
- Message substitution (Σ mᵢ changes)
- Random commitment corruption
- FS transcript tamper

MISSES sum-preserving multiset tampering — documented by
`bg_random_msg_swap_documented_gap` which ASSERTS the current
prototype accepts a swap-with-shift attack.

**R27c/audit** (`shuffleProveAudit`, `shuffleVerifyAudit`):
- **PRIVACY property**: NOT zero-knowledge on shifted messages
  `mᵢ + y`. Verifier learns them.
- **SOUNDNESS property**: closed. The random-linear-combination
  binding check `Π cᵢ^{zⁱ} == commit(Σ zⁱ · shiftedᵢ − y · Σ zⁱ, wOpen)`
  catches sum-preserving multiset tampering. Verified by
  `audit_shuffle_message_swap_caught` — the same attack R27b
  documented as accepted, R27c rejects.

**Documentation**: `MpPedersenVector.h` header:
`TRADE-OFF: this variant is NOT zero-knowledge on the shifted
messages (they're revealed after the challenge y is committed). It
IS sound. Appropriate for AUDIT scenarios where correctness matters
but shifted-value confidentiality does not.`

**Verdict**:
- **R27**: not sound. Use only as a component reference.
- **R27b**: sound against non-multiset-preserving tampering. Zero-
  knowledge on messages.
- **R27c/audit**: fully sound. Reveals shifted messages (NOT ZK).
  Appropriate for compliance audit.
- **Zero-knowledge + full soundness**: requires recursive
  Pedersen-vector opening (Bulletproofs), scoped as follow-up.

---

## Layer 15 — VFL XGBoost double-blind demo

**Threat model**: SecureBoost / HeteroSecureBoost / FATE.

**Inputs**:
- Party A holds `X_A` (features only).
- Party B holds `X_B` and labels `y`.

**Wire messages** (mocked via `MockPaillier`; real deployment uses
Paillier or additive shares):
- Encrypted per-sample gradients and hessians (B → A).
- Encrypted aggregate `(G_L, H_L)` sums (A → B for decryption).

**What each party sees**:
- **Party A**: opaque ciphertext handles only. Never sees plaintext
  gradients, hessians, labels, or `X_B` values.
- **Party B**: per-node aggregate `(G_L, H_L)` after decryption. Never
  sees `X_A` values or which specific samples fell left of a Party-A
  split.

**Documented leak** (matches SecureBoost): Party B learns the
distribution of gradient sums across A's split candidates. This is
NOT a privacy bug — it's the accepted threat-model trade-off in the
VFL boosting literature.

**Test-witness**:
- `party_A_cannot_decrypt`: API discipline enforced — Party-A methods
  return opaque `int` handles, only `decrypt_B` returns plaintext.
- `paillier_addition_correctness`: homomorphic sum semantics work.
- `paillier_op_count_grows_with_rounds`: cost scales linearly with
  rounds (no accidental sub-linear caching leak).

**MockPaillier caveat**: uses a Python dictionary to emulate
ciphertexts. This is a DEVELOPMENT TOOL, not cryptographic. The real
deployment substitutes either Paillier (Pyfhel/Pypbc) or additive
shares over `MpMpcWire`. Documented in the demo header.

**Verdict**: privacy claim holds under the mock semantics; real
security requires the documented backend swap.

---

## Summary matrix

| Layer | Inputs private? | Intermediates private? | Documented gap | Test-witness |
|---|---|---|---|---|
| 1. Base MPSA cascade | YES from SP (masked); YES sender↔sender (AEAD) | YES | none | run_mpsa_smoke |
| 2. Wide-payload cascade | YES (same) | YES | none | run_mpsa_wide_smoke |
| 3. MAC-propagating cascade | YES (augments L1) | YES (tag shares uniform) | none | test_mac, test_auth_cascade |
| 4. R28 trusted-dealer OLE | YES from peer; dealer sees `α_A, x_B` | YES | dealer is trusted | test_ole_alpha |
| 5. R28 wire OLE scaffold | **NO — `α_A`, `x` sent plaintext** | mixed | **HIGH; SilentVole substitution** | correctness test only |
| 6. CGP shuffle (in-memory) | YES (message blinded by random `a`) | YES | dealer is trusted | test_cgp_shuffle |
| 7. CGP wire preprocessing scaffold | **NO — both parties learn full correlation** | **NO** | **HIGH; SilentOT substitution** | correctness test only |
| 8. Plaintext sort/expand/filter | plaintext (by design) | plaintext | not privacy layer | structural_obliviousness |
| 9. Trusted-SP join | **NO from SP (intended)** | plaintext at SP | intended | run_mpsa_join_smoke |
| 10. SP-blind MPC join (in-process) | YES (bit-shared) | YES (opens random) | simulation co-locates in one process | test_mpc_join |
| 11. Wire MPC primitives | YES (only shares held; opens random) | YES | triples must be from secure OLE | test_mpc_wire |
| 12. libOTe SilentOtTriple | YES (LPN-secure) | YES | none | test_ole_triple |
| 13. N-party pairwise triples | 2-party only per pair | 2-party only | **MEDIUM; native N-party OT** | correctness only |
| 14. R27 NIZK | proof reveals nothing about π (weak soundness) | — | R27 not sound; R27b partial; R27c reveals shifted | test_shuffle_nizk_bg, test_pedersen_vector |
| 15. VFL XGBoost demo | YES (mock enforced) | aggregate leaked (SecureBoost model) | mock backend | test_vfl_xgboost_demo |

## Two things that MUST be fixed before deployment

1. **`oleGf128OverWire`** (Layer 5) sends the input `α_A` and `x` on
   the wire in plaintext. Any deployment using this to authenticate
   private values will leak them to the peer. **Use trusted-dealer
   `dealerOleGf128` for now, or replace with libOTe SilentVole.**

2. **`cgpPreprocessOverWire`** (Layer 7) makes the CGP correlation
   known to both parties by shared-seed derivation. Any shuffle
   downstream then no longer hides the permutation. **Use the
   in-memory `cgpDealerGenerate` for research, or replace with a
   real SilentOT-based OPP for deployment.**

Both are structurally documented; both have the callable API
positioned so the substitution is a targeted one-function change.

## Layers that ARE deployment-safe today

- Base MPSA cascade (Layer 1) — the ORIGINAL PSA design; unchanged.
- Wide-payload cascade (Layer 2) — same threat model as Layer 1.
- Wire MPC ops (Layer 11) — as long as triples come from libOTe
  `oleGenerateTriples` (Layer 12), not from the trusted dealer.
- R27c/audit NIZK (Layer 14) — for audit workflows where shifted
  messages can be revealed.

## Layers that ARE research-scaffolding

- L4/L5 trusted-dealer OLE: OK for cascade research.
- L6/L7 CGP with trusted dealer: OK for cascade research.
- L10 in-process MPC join: OK for pipeline validation.
- L13 N-party pairwise: OK for 2-party-per-pair experiments.
- L14 R27 base prototype: reference only.
- L15 VFL demo mock: reference implementation.

None of these are recommended for production without the
substitutions noted.
