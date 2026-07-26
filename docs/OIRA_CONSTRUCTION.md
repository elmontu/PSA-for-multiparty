# OIRA construction — algorithm spec

The construction that realizes the OIRA threat model
(`OIRA_THREAT_MODEL.md`). Two-stage composition of vendored primitives
(MPSIC + MPSICS) + k-anonymity gate at aggregator + Laplace noise on
both released scalars.

## 1. High-level protocol

```
Π_OIRA(𝒢=g_agg, k_anon, ε):
    Phase 1 (Cardinality):
        All parties run MPSIC              → P_0 learns |I|
    Phase 2 (Aggregate):
        All parties run MPSICS             → P_0 learns Σ_{id∈I} val(id)
    Phase 3 (SP-local, non-interactive):
        if |I| < k_anon:
            output (released=false, reason="k_anon_fail")
            return
        ĉ = |I|     + Laplace(1/ε)         // noised cardinality
        â = Σ val   + Laplace(Δ/ε)         // noised aggregate
        output (released=true, ĉ, â)
```

The first two phases are cryptographic (real MPC over sockets); phase
3 is SP-local computation.

## 2. Value encoding — value-separate-from-key (LANDED)

The vendored MPSO's `MPSICardSumParty` was patched in-place (marked
`[LOCAL PATCH — OIRA]` in comments) to accept an OPTIONAL per-item
values array alongside the key set:

```cpp
u64 MPSICardSumParty(u32 idx, u32 numParties, u32 numElements,
                     std::vector<block>& set,
                     u32 numThreads,
                     const std::vector<u64>* values = nullptr);
```

Semantics:
- `values == nullptr` (default): upstream behavior preserved — the
  summed value equals the id (low 64 bits of each block). Useful for
  the `test_mpsics` probe; backward compatible.
- `values != nullptr`: non-P_0 senders contribute `values[i]` as the
  per-item value. P_0 does not contribute (it's the receiver). The
  MPSICS aggregate is then Σ Σ_{j > 0} values[i]_j over
  intersection items.

Patch is minimal: two lines in `PMT.cpp` (added optional
`simHashValues` parameter to `opprfSendPSICS64`; substituted for
`hyj.mData[1]` when non-null), plus population of a parallel value
table in `MPSICS.cpp` before the opprf call. See the LOCAL PATCH
comments in `volePSI/upstream/mpso/mpso/{PMT,MPSICS}.{h,cpp}` for the
exact diffs.

**OIRA aggregate under this encoding:** Σ_{id ∈ I} Σ_{party j > 0}
value_j(id). For 3 banks contributing loan_ij for company i and P_0
being the regulator: `outSum` after dividing by (N-1) equals Σ_{id ∈ I}
(average loan across contributing banks for that company). If all
non-P_0 banks contribute the same value per id (e.g., loan_ij =
loan_i is bank-independent), aggregate is exactly Σ loan_i for
intersection companies.

## 3. Wire format & phase ordering

Since MPSIC and MPSICS both open their own N-party meshes at ports
`PORT + max(i,j)*100 + min(i,j)` (upstream MPSO hardcoded), the two
phases run SEQUENTIALLY with a barrier between them. Sockets are torn
down between phases (upstream's `chl.close()` after each protocol).

Wire schema per party per session:

```
Phase 1 (MPSIC):
    - Each party makes N-1 socket connections per MPSIC's internal setup.
    - Runs opprfRecvPSI64 / opprfSendPSI64.
    - Beaver-triple-multiplication for indicator computation.
    - MShuffleParty64.runXOR.
    - P_0 collects shares from others and reconstructs cardinality.
    - Sockets torn down.

Phase 2 (MPSICS):
    - Same mesh setup at same ports (fresh sockets).
    - Runs opprfRecvPSICS64 in addition to opprfRecvPSI64.
    - Two MShuffleParty64 rounds (runXOR + runADD).
    - P_0 receives sum.
    - Sockets torn down.

Phase 3 (SP-local):
    - Zero wire messages.
    - SP applies threshold check + noise, produces output.
```

**Total online communication:** dominated by MPSICS at ~`O(N * n * λ)`
per party where `n` is per-party set size. Doubling to add MPSIC is
~1.5× total.

## 4. Laplace noise mechanism

Standard Laplace mechanism: `noise ~ Lap(0, scale)`, sampled inline
without external library dependency using inverse-CDF from uniform
random:

```
u ← UniformReal(-0.5, 0.5)                // fresh CSPRNG randomness
sign = (u ≥ 0) ? +1 : -1
noise = -sign * scale * ln(1 - 2*|u|)
```

Bounded-magnitude precaution to prevent overflow: cap `|u|` at
0.999999 before the log.

**Scale settings:**
- For cardinality: `scale = 1/ε`. Sensitivity of cardinality is 1
  (adding one item to any party's set changes |I| by at most 1).
- For aggregate: `scale = Δ/ε` where `Δ` is caller-specified maximum
  per-item value. For MPSICS with value=key encoding, `Δ = 2^63` (u64
  bound), but for practical calls the caller will bound to something
  much smaller (e.g., 10^9 for financial amounts in cents).

**Randomness source:** libsodium `randombytes_buf` into 8 bytes,
convert to uniform double in (0, 1), shift to (-0.5, 0.5). Same
pattern already used in `MpsaDriver.cpp` for the DP cardinality
release (T8).

## 5. k-anonymity gate

At SP after Phase 1 completes:

```
if cardinality < k_anon:
    log "OIRA: k-anon failed, cardinality=... < threshold=..."
    output (released = false, reason = "k_anon_fail")
    // Skip Phase 2 entirely -- no need to run MPSICS if we're not going
    // to release the aggregate. Saves communication.
    return
```

**Note:** skipping Phase 2 on suppression IS a side channel — other
parties observe that SP did not initiate Phase 2. They learn "SP
suppressed this session" which reveals `|I| < k_anon` binarily.
This is accepted per `OIRA_THREAT_MODEL.md` §4 point 4.

To harden: SP could ALWAYS run Phase 2 and discard the result if the
threshold check failed. This costs bandwidth but removes the binary
side channel. Configurable via `alwaysRunPhase2` flag (default OFF for
the reference implementation; ON for stricter deployments).

## 6. API sketch

```cpp
// volePSI/MpOira.h

namespace volePSI {
namespace mpstar {

struct OIRAConfig {
    uint32_t kAnon       = 20;     // suppress if |I| < kAnon
    double   epsilon     = 1.0;    // DP budget (shared across card + agg)
    uint64_t valueBound  = 1ULL << 40;  // sensitivity Δ for aggregate DP
    bool     alwaysRunPhase2 = false;   // hardening; see §5
};

struct OIRAResult {
    bool     released       = false;
    uint64_t noisyCardinality = 0;   // = |I| + Lap(1/ε)  (rounded to u64)
    int64_t  noisyAggregate = 0;     // = Σ + Lap(Δ/ε)   (signed after noise)
    std::string reason;              // set iff !released
};

// Party idx runs OIRA. Returns meaningful result at idx=0, empty at others.
// `set` is the party's input (low 64 of each block treated as id in this
// reference implementation).
// Requires that MPSICSpreGen + MPSICpreGen have already run for
// (N, log2(numElements)) and produced offline files.
OIRAResult oiraAggregate(uint32_t idx,
                         uint32_t N,
                         uint32_t numElements,
                         std::vector<oc::block>& set,
                         const OIRAConfig& config,
                         uint32_t numThreads = 1);

}} // namespace
```

## 7. What this session's implementation will NOT do (explicit)

- Value-separate-from-key encoding (see §2). Requires vendored code
  refactor to `PMT.cpp:opprfSendPSICS64` and `MPSICS.cpp:65-66,84-85`.
  Deferred to follow-on.
- BOIRA (bucketed histogram). Deferred.
- Wire-protocol port. MPSICS opens its own mesh; wrapping in MPSA's
  star topology + AEAD-wrapping messages is a separate integration.
- Malicious integrity.
- Adaptive-query DP composition analysis.

## 8. Test plan

`tests/unit/oira_probe.cpp` — extends the MPSICS probe from Session 2:

1. **Baseline correctness (N=3, k_anon=1, ε=1.0):**
   Run OIRA with |I|=100 companies. Verify `noisyAggregate` is within
   `±10 * scale` of ground truth (10× Laplace scale covers > 99.9%
   of noise mass by Chebyshev).
2. **k-anonymity refusal:** shrink intersection to |I|=5 with
   k_anon=20. Verify `released == false` and `reason` contains
   `"k_anon"`.
3. **DP noise magnitude:** empirical distribution over 30 runs at
   ε=1.0 vs ε=0.1. Verify variance ratio approximately (1/0.1)²/(1)²
   = 100×.
4. **Multi-party (N=4, 5, 6):** cardinality-only correctness check.

`tests/run_oira_probe.sh`:
- Phase 0: run MPSICpreGen + MPSICSpreGen for each party.
- Phase 1: launch N parties running `oira_probe` in subprocesses.
- Phase 2: collect party-0 output, compare to synthetic ground truth,
  report PASS/FAIL.

## 9. Files to add this session

| Path | Role |
|---|---|
| `docs/OIRA_THREAT_MODEL.md` | ✓ done |
| `docs/OIRA_CONSTRUCTION.md` | ✓ this doc |
| `volePSI/MpOira.h` | API |
| `volePSI/MpOira.cpp` | Implementation of `oiraAggregate` |
| `volePSI/CMakeLists.txt` | Register `MpOira.cpp` |
| `tests/unit/oira_probe.cpp` | Standalone probe binary |
| `tests/unit/CMakeLists.txt` | Register probe |
| `tests/run_oira_probe.sh` | End-to-end orchestration |

## 10. Expected end-to-end result

After all files land:

```
$ bash tests/run_oira_probe.sh
=== Phase 0: pregen MPSIC + MPSICS for 3 parties ===
=== Phase 1: online OIRA (k_anon=20, ε=1.0, |I|=100) ===
=== Party 0 result ===
PASS: OIRA released=1, ĉ=99 (true=100, noise ~ Lap(1)),
      â=4998 (true=5050, noise ~ Lap(Δ/ε))

=== Suppression test (k_anon=200, |I|=100) ===
PASS: OIRA released=0, reason=k_anon_fail
```

Then the module + smoke join the repository's regression suite.
