#pragma once

// OIRA — Output-Inference-Resistant Aggregation.
//
// See docs/HISTORY.md and docs/HISTORY.md for the
// threat model + protocol spec. In brief:
//
//   Π_OIRA = MPSIC (cardinality) + MPSICS (aggregate) + k-anon gate
//            + Laplace DP noise on both released scalars.
//
// This module composes the vendored MPSO primitives (MPSIC, MPSICS,
// under volePSI/upstream/mpso/) and does not modify them. Value-vs-key
// separation is deferred: the current reference implementation uses
// the upstream MPSICS encoding where the summed value == the intersection
// key (low 64 bits of each block). Semantics: the aggregate is a
// distinctive fingerprint of the intersection multiset. Follow-on
// session refactors PMT.cpp to accept a per-item value alongside the key.

#include "MpOiraBudget.h"

#include "cryptoTools/Common/Defines.h"

#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpstar {

struct OIRAConfig {
    uint32_t kAnon           = 20;             // suppress if |I| < kAnon
    double   epsilon         = 1.0;            // DP privacy budget PER QUERY
    uint64_t valueBound      = 1ULL << 40;     // sensitivity Δ for aggregate
    bool     alwaysRunPhase2 = false;          // hardening (see construction doc §5)

    // Optional multi-session DP-budget accountant. If non-null, checked+
    // reserved atomically before Phase 1 runs; refuses the session if the
    // cumulative budget for this scope would exceed the cap. See
    // MpOiraBudget.h. Every party that consults its own OIRAConfig with
    // budget != nullptr enforces its own budget file; the FIRST party to
    // refuse causes protocol abort (all N parties must agree to run).
    const OIRABudgetConfig* budget = nullptr;
};

struct OIRAResult {
    bool        released         = false;
    uint64_t    noisyCardinality = 0;
    int64_t     noisyAggregate   = 0;
    uint64_t    trueCardinality  = 0;   // for testing; would be redacted in prod
    uint64_t    trueAggregate    = 0;   // for testing; would be redacted in prod
    std::string reason;                 // set iff !released

    // Fix B — S_0 attestation (populated at P_0 before Phase 1 runs).
    // 32-byte hex-encoded Pedersen commitment to Σ hashToScalar(id) for
    // id in P_0's set. Committed at protocol start, published to all
    // parties (via log or a side channel). P_0 can later be challenged
    // to open (revealing S_0 hash-sum + opening scalar); other parties
    // verify against this recorded commitment.
    //
    // Purpose: prevents an adaptive SP from changing its S_0 between
    // sessions to run subtractive attacks — the committed set is bound
    // at the moment of publication. Composition attacks across
    // sessions still require DP budget accounting (deferred).
    std::string s0CommitmentHex;
};

// Party `idx` runs OIRA. Returns meaningful result at idx=0, empty at
// others. `set` is the party's input (low 64 of each block treated as
// id).
//
// `values` (OPTIONAL, per-item aligned with `set`): the value each
// non-P_0 party contributes for its own items. If nullptr, the
// upstream fallback is used where the summed value equals the id
// itself (aggregate = sum of intersection IDs — useful only for
// smoke-testing). For real vulnerability-score deployments, pass real
// per-item values (loan amounts, EBITDA figures, risk indicators, etc.).
// P_0 ignores `values` — it doesn't contribute to the aggregate,
// only receives it.
//
// PRECONDITION: MPSICpreGen(idx, N, log2(numElements)) AND
//               MPSICSpreGen(idx, N, log2(numElements)) have already
//               been run, producing offline files under ./offline/.
OIRAResult oiraAggregate(uint32_t idx,
                         uint32_t N,
                         uint32_t numElements,
                         std::vector<oc::block>& set,
                         const OIRAConfig& config,
                         uint32_t numThreads = 1,
                         const std::vector<uint64_t>* values = nullptr);

// Convenience: same DP-noise helper the internal code uses, exported
// for the test harness so it can compute the expected noise scale
// without duplicating the formula.
double sampleLaplaceNoise(double scale);

} // namespace mpstar
} // namespace volePSI
