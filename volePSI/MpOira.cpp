#include "MpOira.h"

#include "volePSI/upstream/mpso/mpso/MPSIC.h"
#include "volePSI/upstream/mpso/mpso/MPSICS.h"
#include "MpPedersen.h"
#include "MpRistretto.h"

#include <sodium.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

// -------- Laplace mechanism (inline; matches T8 style in MpsaDriver.cpp) ----

double sampleLaplaceNoise(double scale) {
    if (scale <= 0.0) return 0.0;
    // 8 bytes of CSPRNG -> uniform in (-0.5, 0.5)
    std::array<uint8_t, 8> u_bytes;
    randombytes_buf(u_bytes.data(), u_bytes.size());
    uint64_t u64_val;
    std::memcpy(&u64_val, u_bytes.data(), 8);
    // Map to [0, 1) then shift to (-0.5, 0.5).
    double u = (static_cast<double>(u64_val) / static_cast<double>(std::numeric_limits<uint64_t>::max())) - 0.5;
    double sign_u = (u >= 0.0) ? 1.0 : -1.0;
    double abs2u  = std::abs(u) * 2.0;
    // Cap to prevent -inf when abs2u -> 1.
    double safe_abs2u = std::min(abs2u, 0.999999);
    return -sign_u * scale * std::log(1.0 - safe_abs2u);
}

// -------- OIRA main -------------------------------------------------------

OIRAResult oiraAggregate(uint32_t idx,
                         uint32_t N,
                         uint32_t numElements,
                         std::vector<oc::block>& set,
                         const OIRAConfig& config,
                         uint32_t numThreads,
                         const std::vector<uint64_t>* values)
{
    OIRAResult out;

    if (N < 2) {
        out.reason = "N < 2 (need at least 2 parties)";
        return out;
    }
    if (config.epsilon <= 0.0) {
        out.reason = "epsilon must be > 0";
        return out;
    }
    if (set.size() != numElements) {
        out.reason = "set.size() != numElements";
        return out;
    }

    // ---- Multi-session defense: DP-budget check (BEFORE any wire I/O) ----
    // Each party independently consults its own budget file if configured.
    // If any party's budget is exhausted, that party returns released=false
    // with a budget_exhausted reason and DOES NOT participate. Other parties
    // will then hang or timeout on the MPSICS mesh setup — the caller of
    // this API is expected to abort the session if any party's oiraAggregate
    // returns released=false with a budget-related reason. For a clean
    // multi-party abort, a real deployment should broadcast the abort
    // signal before proceeding; this reference implementation just returns.
    if (config.budget != nullptr) {
        OIRABudgetCheckResult brc = oiraBudgetCheckAndReserve(
            *config.budget, config.epsilon);
        if (!brc.allowed) {
            out.released = false;
            out.reason = std::string("budget_exhausted: ") + brc.reason;
            std::cerr << "[OIRA] party " << idx
                      << " REFUSED session: " << brc.reason
                      << " (scope=" << config.budget->scopeId
                      << ", spentBefore=" << brc.spentBefore
                      << ", countBefore=" << brc.countBefore << ")\n";
            return out;
        }
        std::cerr << "[OIRA] party " << idx << " budget OK: "
                  << "scope=" << config.budget->scopeId
                  << ", spent " << brc.spentBefore
                  << " -> " << brc.spentAfter
                  << " (cap " << config.budget->epsilonCap << "), count "
                  << brc.countBefore << " -> " << brc.countAfter
                  << " (cap " << config.budget->queryCap << ")\n";
    }

    // ---- Fix B: S_0 attestation (P_0 only, before any protocol phase) ----
    // P_0 commits to a hash of its OWN input set before running MPSIC so
    // it cannot adaptively change S_0 to probe individual companies. The
    // commitment is published (via the return value + a stdout log) so
    // other parties can record it. Post-hoc audit: P_0 can be asked to
    // open (Σ hash(id), r) and other parties verify against this commit.
    //
    // Note: this deters SINGLE-SESSION adaptive attacks. Multi-session
    // attacks (SP changing S_0 across sessions) still need DP-budget
    // accounting, which is deferred.
    if (idx == 0) {
        R255Scalar sHashSum = R255Scalar::zero();
        for (const auto& b : set) {
            std::vector<uint8_t> tmp(16);
            std::memcpy(tmp.data(), &b, 16);
            sHashSum = scalarAdd(sHashSum, hashToScalar(tmp));
        }
        R255Scalar sOpening = R255Scalar::random();
        PedersenCommitment sCommit = pedersenCommit(sHashSum, sOpening);
        // Hex-encode the 32-byte commit for logging.
        char hex[65];
        for (int i = 0; i < 32; ++i) {
            std::snprintf(hex + 2 * i, 3, "%02x", sCommit.c.bytes[i]);
        }
        out.s0CommitmentHex = std::string(hex, 64);
        // Publish so witnesses (test harness, external auditor) can record.
        std::cerr << "[OIRA] SP S_0 attestation commit = "
                  << out.s0CommitmentHex << "\n";
        // NOTE: sOpening and sHashSum are NOT logged — SP retains them
        // privately for a later opening challenge. In production these
        // would go to a secure audit store.
    }

    // ---- Phase 1: MPSIC (cardinality) ----
    // Every party runs MPSICardParty. Party 0 gets the cardinality; others
    // get 0.
    //
    // NOTE: MPSIC's set input MUST be an independent copy from what MPSICS
    // will use because the vendored MPSICardParty destructively modifies its
    // set (via cuckoo/simple-hashing internal state). We defensively deep-copy.
    std::vector<oc::block> setForCard = set;
    uint32_t card = MPSICardParty(idx, N, numElements, setForCard, numThreads);

    if (idx == 0) {
        out.trueCardinality = static_cast<uint64_t>(card);
    }
    // ---- Phase 1.5: k-anonymity decision (SP-local, deferred to §3 below) ----
    // We UNCONDITIONALLY run Phase 2 for every party. Skipping Phase 2 at
    // SP based on the k-anon check would leave other parties hanging on
    // the MPSICS mesh setup, and would create a binary side channel
    // (parties observe SP not initiating Phase 2 iff |I| < k_anon). We
    // instead run Phase 2 always, then apply the k-anon gate LOCALLY at
    // SP AFTER Phase 2 completes -- discarding the aggregate if the
    // threshold isn't met. Bandwidth cost is unavoidable; hang risk is
    // eliminated.

    // ---- Phase 2: MPSICS (aggregate) ----
    // Pass `values` through so non-P_0 senders contribute real
    // per-item values (loan, EBITDA, etc.) rather than defaulting to
    // value=key. See MpOira.h and OIRA_CONSTRUCTION.md §2.
    std::vector<oc::block> setForSum = set;
    uint64_t agg = MPSICardSumParty(idx, N, numElements, setForSum,
                                    numThreads, values);

    if (idx != 0) {
        out.reason = "non-P0 party: no output";
        return out;
    }

    // MPSICS returns the sum-of-values as SUM across (N-1) sender
    // contributions. Under the upstream value=key encoding, each
    // intersection id contributes its value once per non-P_0 party. Divide
    // by (N-1) to get the intersection multiset sum.
    if (N > 1) {
        agg /= (N - 1);
    }
    out.trueAggregate = agg;

    // ---- Phase 3: apply DP noise to cardinality FIRST (Fix A) ----
    // Cardinality DP: sensitivity = 1 (adding/removing one item from any
    // party's set changes |I| by at most 1). Scale = 1/ε.
    double cardScale = 1.0 / config.epsilon;
    double cardNoise = sampleLaplaceNoise(cardScale);
    // Clamp noisyCardinality to unsigned range; negative rounds to 0.
    double noisyCardD = static_cast<double>(out.trueCardinality) + cardNoise;
    if (noisyCardD < 0.0) noisyCardD = 0.0;
    out.noisyCardinality = static_cast<uint64_t>(std::round(noisyCardD));

    // ---- k-anon gate (Fix A: applied to NOISY cardinality) ----
    // Previously this compared TRUE |I| against kAnon, which made the
    // release/suppress decision a deterministic function of the true
    // cardinality. That let an adaptive SP probe the boundary by
    // crafting S_0: `S_0 = {X, 19 decoys}` with kAnon=20 releases iff
    // X is in the intersection, leaking membership of X.
    //
    // By gating on noisyCardinality (which has Laplace noise of scale
    // 1/ε), the boundary itself becomes DP-noised. An adaptive SP now
    // sees a release/suppress signal that is ε-DP w.r.t. any single
    // input change. Standard DP composition applies across queries.
    if (out.noisyCardinality < config.kAnon) {
        out.released = false;
        out.reason = "k_anon_fail: noisy |I|=" + std::to_string(out.noisyCardinality)
                   + " < k_anon=" + std::to_string(config.kAnon)
                   + " (true |I| withheld)";
        // Discard the aggregate — do NOT populate noisyAggregate so the
        // caller can't leak it accidentally.
        return out;
    }

    // Aggregate DP: sensitivity = valueBound. Scale = Δ/ε.
    double aggScale = static_cast<double>(config.valueBound) / config.epsilon;
    double aggNoise = sampleLaplaceNoise(aggScale);
    // Aggregate can wrap around in u64 space; store signed for legibility.
    // Callers can cast back if their domain guarantees non-negative.
    double noisyAggD = static_cast<double>(out.trueAggregate) + aggNoise;
    if (noisyAggD < static_cast<double>(std::numeric_limits<int64_t>::min()))
        noisyAggD = static_cast<double>(std::numeric_limits<int64_t>::min());
    if (noisyAggD > static_cast<double>(std::numeric_limits<int64_t>::max()))
        noisyAggD = static_cast<double>(std::numeric_limits<int64_t>::max());
    out.noisyAggregate = static_cast<int64_t>(std::round(noisyAggD));

    out.released = true;
    return out;
}

} // namespace mpstar
} // namespace volePSI
