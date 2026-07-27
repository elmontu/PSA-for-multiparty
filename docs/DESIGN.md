# MPSVS Crypto Primitive Designs

**Scope.** Consolidates the primitive-level design docs
(`MPC_WIRE_DESIGN.md`, `SHUFFLE_NIZK_DESIGN.md`,
`MALICIOUS_UPGRADE_ROADMAP.md`, `MALICIOUS_CASCADE_DESIGN.md`,
`DP_THRESHOLD_TRANSCRIPT_DESIGN.md`, `AUTHENTICATED_HANDSHAKE_DESIGN.md`,
`CGP_SHUFFLE_DESIGN.md`, `CARDINALITY_HIDING_DESIGN.md`,
`PQ_HYBRID_HANDSHAKE_DESIGN.md`) into a single design reference. Historical
text recoverable via `git log --follow` on commits before `2026-07-27`.

Organised by primitive family; each section explains what the primitive
does, why it's the right shape for MPSVS, and where to find the code.

---

## 1. SPDZ MAC-authenticated shares

**Purpose.** Every intermediate share carries a MAC `[α·x]` so that
any tampering by ≤ 1 corrupt compute node is caught on open.

### 1.1 Plaintext-α (semi-honest / single-verifier)

```
struct AuthSharedU64 {
    SharedU64 value;  // additive share of x
    SharedU64 mac;    // additive share of α·x
};

bool openWithMacCheck(x, alpha /* u64 plaintext */, out) {
    x_rec = x.value.reconstruct();
    mac_rec = x.mac.reconstruct();
    return alpha * x_rec == mac_rec;
}
```

Kept for legacy single-verifier ceremonies (auditor holds α at
release time). **NOT** the standard SPDZ malicious model.

Modules: `MpsvsAuthShare.{h,cpp}`, `MpsvsAuthShareProd.{h,cpp}`
(the `Prod` retrofit wraps α in `SecureAlpha` — RAII / CSPRNG /
memzero-on-scope-exit — but still holds α as a u64).

### 1.2 DPSZ shared-α (malicious S1 vs S2)

Per Damgård-Pastro-Smart-Zakarias 2012 §3.3. α = α₁ + α₂ split across
S1 and S2 for the entire session; neither party ever reconstructs α.

**Open + MAC check** — `openWithMacCheckShared`:

```
Phase A: reconstruct x publicly
Phase B: each party i locally computes σ_i = α_i·x - m_i
Phase C: each party i publishes commit_i = H(party ‖ σ_i ‖ salt_i)
         [broadcast — no reveal yet]
Phase D: each party i reveals (σ_i, salt_i);
         each verifies peer's reveal matches earlier commit
Phase E: valid iff σ_1 + σ_2 = 0
```

The commit-then-reveal ordering (post-audit-cycle-2 fix) prevents a
party from choosing σ_i adversarially after seeing peer's σ. In the
in-process semantic reference, the ordering is enforced by structuring
the code so the commit-snapshot is taken before either reveal — a
wire-level impl replicates this byte-for-byte via two-round message
exchange.

Correctness:
```
σ_1 + σ_2 = (α_1 + α_2)·x - (m_1 + m_2) = α·x - m
```
which is 0 iff `m = α·x` (honest MAC).

**Batched Ω-check** — `batchOpenWithMacCheckShared`:

Per-element r_j MUST be unpredictable to any adversary who has not
yet committed shares. Post-audit fix: r_j is Fiat-Shamir-derived:
```
tr = SHA-256(concat share bytes over all elements)
r_j = SHA-256("mpsvs.omega.r" ‖ j ‖ tr) [first 8 bytes as u64]
```
An adversary who wants to game r_j would need a SHA-256 preimage
attack — negligible under the collision-resistance assumption.

**Beaver mult** — `authSecureMultiplyShared`:

The α·d·e MAC term must be split sharewise: party i adds
α_i · d · e to its own MAC share of z. Reconstruction:
```
Σ_i MAC_i(z) = Σ_i (MAC_i(w) + d·MAC_i(v) + e·MAC_i(u) + α_i·d·e)
             = α·w + d·α·v + e·α·u + α·d·e
             = α · (w + d·v + e·u + d·e) = α · z ✓
```
So a valid `AuthSharedU64` is produced with α remaining split.

Modules: `MpsvsAuthShare::openWithMacCheckShared` +
`authSecureMultiplyShared` + `sacrificeCheckTripleShared` +
`batchOpenWithMacCheckShared`; `MpsvsReciprocalVerify::verifyReciprocalAuthShared`.

### 1.3 Sacrifice check

Per SPDZ, verifies a Beaver triple `(u, v, w = u·v)` by sacrificing an
auxiliary triple `(u', v', w' = u'·v')`:

```
r ← public random challenge (CSPRNG)
ρ = r·u - u'    (open + MAC-check)
σ = v - v'      (open + MAC-check)
τ = r·w - w' - σ·u' - ρ·v'  (open + MAC-check)
valid iff τ == ρ·σ
```

Any malformed triple caught with probability 1 - 1/2^k.

Modules: `MpsvsAuthShare::sacrificeCheckTriple` (plaintext-α) and
`sacrificeCheckTripleShared` (DPSZ).

## 2. OLE-based Beaver preprocessing

**Purpose.** Remove the trusted-dealer assumption for Beaver triples.
Instead, S1 and S2 jointly generate triples via oblivious linear
evaluation (OLE) using libOTe's `SilentOtTriple` under LPN.

For MPSVS's N=2 fixed topology, this is a direct 2-party OLE.
N > 2 is explicitly guarded (throws) because pairwise composition
misses the cross-terms in `(⨁ Uᵢ)·(⨁ Vⱼ)`.

Modules: `MpOleAlpha.{h,cpp}` (α-generation), `MpOleTriple.{h,cpp}`
(triple generation).

## 3. Threshold-DH-OPRF + DLEQ + bias-frozen DKG

**Purpose.** Derive per-firm "entity keys" W = OPRF(canonical_id) via
a 2-server protocol where neither server learns W and every hop is
proved-correct.

### 3.1 Bias-frozen DKG (Rev 7 §2)

Standard 2-party DKG has S1 send Y₁ = g^{k₁} first, letting S2 bias
the joint Y by choosing k₂ based on Y₁. Rev 7 fixes this:

```
S2:   sample k₂;  Y₂ = g^{k₂};  commit = H(Y₂ ‖ pi_Y₂)
S2 → S1:  commit
S1:   sample k₁;  Y₁ = g^{k₁};  pi_Y₁ = Schnorr(k₁; Y₁)
S1 → S2:  Y₁, pi_Y₁
S2:   verify pi_Y₁; compute Y = Y₁^{k₂}; pi_DLEQ(k₂; Y₂, Y₁, Y)
S2 → S1:  Y₂, pi_Y₂, Y, pi_DLEQ
S1:   verify commit-open of Y₂; verify pi_Y₂ and pi_DLEQ
```

S2 commits before seeing Y₁ → no bias. Schnorr + DLEQ soundness under
DLog.

### 3.2 Per-hop DLEQ

Each OPRF hop from client to S1 (or S2) is proved via
Chaum-Pedersen DLEQ:
```
Prove: ∃ k such that Y = g^k AND V = U^k
Fiat-Shamir over (g, Y, U, V, A, B) with A = g^r, B = U^r.
```

`schnorrVerify` and `dleqVerify` (post-audit fix) now
`isValidPoint(R)`-guard the FS-recovered point before hashing —
defence-in-depth against a compromised libsodium sub returning
invalid points.

Modules: `MpsvsOprf.{h,cpp}`.

## 4. Bayer-Groth shuffle NIZK (sound-with-reveal)

**Purpose.** Publicly-verifiable proof that a shuffled commitment
vector `C' = (c'_1, ..., c'_n)` is a permutation of the original
`C = (c_1, ..., c_n)`.

### 4.1 History — R27b residual gap (now closed)

The R27b prototype (`MpShuffleNizkBg`) originally had the verifier
compare prover-supplied `productOrig == productShuf`. A malicious
prover could set both to any equal value; the check was tautological.
Post-audit fix ("sound-with-reveal"):

```
Prover reveals: (m_1..m_n), (r_1..r_n), (m'_1..m'_n), (r'_1..r'_n)
Verifier:
  Phase 1 (binding): for each i, check
    c_i  == pedersenCommit(m_i,  r_i)
    c'_i == pedersenCommit(m'_i, r'_i)
  Phase 2 (soundness): derive FS challenges (y, x); recompute both
    P  = Π (x - (m_i  + y))
    P' = Π (x - (m'_i + y))
  Reject iff P ≠ P'.
```

Under Schwartz-Zippel over ~2²⁵² field, `P = P'` iff `{m_i} = {m'_i}`
as multisets. Trade: no longer zero-knowledge over messages — the
prover reveals them. Acceptable for MPSVS Phase 4 where bin contents
are public post-alignment.

Full hiding-with-secrecy Bayer-Groth requires the recursive §5
partial-product argument (larger construction, out of Rev 7 scope).

Modules: `MpShuffleNizkBg.{h,cpp}`, `MpsvsShuffleWire.{h,cpp}`.

### 4.2 CGP composed shuffle

The actual permutation is joint π = π₂ ∘ π₁ — S1 contributes π₁,
S2 contributes π₂, neither party knows the joint. Standard CGP
construction; the BG NIZK above proves the composed output is a valid
permutation of the input.

Modules: `MpCgpShuffle.{h,cpp}`, `MpShuffleDriver.{h,cpp}`.

## 5. Chaum-Pedersen OR bit proof

**Purpose.** Prove that a Pedersen commitment `C = g^b · h^r` opens to
`b ∈ {0, 1}` without revealing which.

Standard OR-proof structure:
- Real branch: prove DLog of `T_b w.r.t. h` (real witness r)
- Simulated branch: pick (c_{1-b}, s_{1-b}) uniform; back-compute A
- Fiat-Shamir combines: `c_combined = c_0 + c_1`

**Post-audit hardening**: `commitBit(b, r)` now throws
`std::invalid_argument` for `b ∉ {0, 1}` at construction time. This
eliminates the earlier API tension where `commitBit` accepted any b
but `proveBit` rejected. Test C7 exercises 100/100 non-boolean commit
attempts, all rejected.

Modules: `MpsvsBitProof.{h,cpp}`.

## 6. Reciprocal algebraic verification

**Purpose.** After Goldschmidt reciprocal produces `y_fp ≈ 2^f / x`,
verify by opening `[y_fp · x]` via authenticated Beaver mult and
checking `|z - 2^f| ≤ tolerance`.

Catches malicious server that returns wrong reciprocal (would defeat
downstream ratio computation).

Both plaintext-α (`verifyReciprocalAuth`) and DPSZ shared-α
(`verifyReciprocalAuthShared`) versions available.

Modules: `MpsvsReciprocalVerify.{h,cpp}`.

## 7. Differential privacy — joint noise transcript

**Purpose.** Two-party joint Gaussian noise where neither party can
bias the release.

### 7.1 Protocol

```
S1:   η_1 ~ N(0, σ²/2) sampled from CSPRNG
      salt_1 ← CSPRNG
      commit_1 = H(party=1 ‖ η_1 ‖ salt_1)
S2:   η_2 ~ N(0, σ²/2), salt_2, commit_2 similarly

Both broadcast commits;
Then both reveal (η, salt);
Both verify peer's commit matches revealed value.

If commits verify:
   final noise η = η_1 + η_2 ~ N(0, σ²)
   apply to opened aggregate; k-anonymity gate; publish.
Else:
   ABORT (audit log entry). No partial release.
```

Post-audit fix in `MpsvsDpProd.cpp`: `addJointNoiseImpl` throws if
either commit verification fails — replaces earlier code path that
silently returned un-noised data.

### 7.2 zCDP + budget tracking

σ derived from ρ + Δ₂ per zCDP: `σ = √(Δ₂² / (2ρ))`, with Δ₂ = √2 for
count histograms (each entity affects at most 2 bins with unit weight).

`BudgetTracker` accumulates ρ across sessions; releases beyond
`ρ_budget` are refused. `(ρ, δ)` → `ε` conversion at release time
via `epsilonFromRho`.

### 7.3 Contribution clip

`C_max` (from `MpsvsConfig`) bounds any single entity's contribution
to a sum query; prevents an outlier from swamping the DP noise.

### 7.4 k-anonymity gate

Suppress any cell with `n_valid < k_threshold` (default 5). Enforced
in `MpsvsKAnonGate`.

Modules: `MpsvsDp.{h,cpp}`, `MpsvsDpProd.{h,cpp}`, `MpsvsDpWire.{h,cpp}`,
`MpsvsKAnonGate.{h,cpp}`.

**Note on `MpsvsDpWire`**: this is the semantic-reference / test-only
path that uses `std::mt19937_64`. Post-audit fix: guarded by
`MPSVS_PRODUCTION_MODE=1` env var → throws. Production path is
`MpsvsDpProd::addJointNoiseImpl` (CSPRNG-backed).

## 8. Authenticated encrypted channel

**Purpose.** Mutually-authenticated confidential byte channel between
MPSVS parties, replacing the plaintext in-process `coproto::LocalAsyncSocket`
for real network deployment.

### 8.1 Handshake

```
Both parties simultaneously send HELLO:
  { party_name_len, party_name, X25519_public_key(32) }

Each side:
  1. Verify received public_key matches expected_peer.public_key
     (sodium_memcmp — CT)
  2. Derive session keys via crypto_kx_client_session_keys
     (initiator) or crypto_kx_server_session_keys (responder)
  3. Bootstrap two secretstream_xchacha20poly1305 sessions,
     exchanging per-direction headers
```

Role assignment (initiator vs responder) is deterministic —
lexicographically smaller party_name is initiator. Breaks the "who
talks first" symmetry without out-of-band coordination.

### 8.2 Bulk data

`crypto_secretstream_xchacha20poly1305` per direction — per-frame
authenticated encryption, automatic nonce management, built-in
ordering + replay protection, `TAG_FINAL` sentinel for clean
shutdown detection.

### 8.3 Threat model

- ✓ passive eavesdropping
- ✓ active MITM (rejected: mutual identity check)
- ✓ message tampering (Poly1305 tag)
- ✓ replay (secretstream nonce state)
- ✓ reordering (secretstream nonce state)
- ~ traffic analysis (frame lengths visible)
- ✗ physical side-channel (out of scope)
- ✗ post-compromise recovery (no forward secrecy beyond session)

For X.509 mTLS: swap the handshake with OpenSSL
`SSL_do_handshake` under `SSL_VERIFY_PEER |
SSL_VERIFY_FAIL_IF_NO_PEER_CERT` and pinned CA. The `ISecureChannel`
interface is designed so this substitution is a single-file swap.

### 8.4 Post-quantum hybrid (`-pq`)

Legacy 2-party PSA supports a hybrid X25519 + KEM handshake
(currently `StubKem`; ML-KEM-768 attachment point documented in
`docs/history/PQ_HYBRID_HANDSHAKE_DESIGN.md` before consolidation).
Not yet ported into MPSVS's `MpsvsSecureChannel`; use only via
`-pq` flag on the legacy MPSA cascade for now.

Modules: `MpsvsSecureChannel.{h,cpp}` (MPSVS), `MpStarSetup.{h,cpp}`
(legacy MPSA).

## 9. Encrypted-at-rest key store

**Purpose.** Persist long-term identity keys (party X25519), SPDZ α
per session, DKG partial keys, audit HMAC keys across process restarts.

### 9.1 FileKeyStore format

```
magic(8)  version(4)  argon2_salt(16)
secretstream_header(24)
ciphertext body (single frame with TAG_FINAL)
```

Body decrypts to a length-prefixed binary encoding of records. Master
key derived once from passphrase via `crypto_pwhash` (Argon2id,
INTERACTIVE cost — ~250ms/derive; bump to SENSITIVE for high-value
stores at ~1s cost). Salt cached as member; no redundant reads.

### 9.2 Threat model

- ✓ Full-disk-encrypted at rest
- ✓ Per-record authenticated encryption (Poly1305 MAC)
- ✓ Tampering caught on read
- ✓ Concurrent access safe (`std::mutex` on records + flushes;
  post-audit fix)
- ✓ chmod BEFORE rename (no world-readable window; post-audit fix)
- ✗ Not replicated (caller arranges backup)
- ~ Passphrase strength — Argon2id costs ~1 GB RAM / ~1s CPU; weak
  passphrases still weak

### 9.3 HSM stub

`HsmKeyStore` throws `std::logic_error` documenting the PKCS#11
attachment point:
- `C_GetFunctionList`, `C_Initialize`, `C_OpenSession`
- Map `key_id` → `CKA_LABEL`
- `putKey` → `C_GenerateKey` (never returns secret for identity keys)
- Sign / kx operations become HSM calls

Modules: `MpsvsKeyStore.{h,cpp}`.

## 10. Cardinality hiding / cover firms

**Purpose.** Prevent an observer from learning the exact intersection
size (which itself leaks e.g. how many licensed borrowers exist).

Two mechanisms:

- **Cover firms** — `K ∈ [K_min, K_max]` synthetic firms injected
  during F_PSA (`MpsvsCoverFirms`). Each cover firm is randomly-keyed
  and marked `memb=0` externally; downstream inclusion gates
  suppress them from real aggregates.
- **Padded release** (legacy `-cmax N`) — pad output to ≥ N rows
  with PRNG dummies for observers of the raw output file.

## 11. Additional operational primitives

- **`MpsvsConfig`** — regulator-editable operational params; zero-dep
  key=value parser; SHA-256 canonical hash for change-control audit
- **`MpsvsCryptoParams`** — security-proof params (λ, σ_stat, MAC
  field, batch sizes, LPN regime); cross-parameter validation tied to
  `math_rev7_r27_break_even`; `paramsHash` also logged to audit chain
- **`MpsvsConstTime`** — branch-free `ctEq`, `ctLt`, `ctMux` + libsodium
  byte compare; used in MUX for secret-dependent comparators
- **`MpsvsAuditPersist`** — append-only tamper-evident file with
  SHA-256 hash chain, `flock`-protected, atomic rename, chmod-before-rename
- **`MpsvsMetrics`** — Prometheus text-format exposition; standard
  metric names for observability
