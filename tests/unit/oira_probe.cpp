// Multi-process probe for OIRA (Output-Inference-Resistant Aggregation).
// Runs the full construction (MPSIC + k-anon gate + MPSICS + DP noise)
// against a synthetic party idx. Party 0 prints PASS/FAIL against
// cleartext ground truth. Other parties silently contribute.
//
// Orchestration: tests/run_oira_probe.sh (preGen for each party across
// both MPSIC and MPSICS, then online run of this binary).

#include "volePSI/MpOira.h"
#include "volePSI/MpOiraBudget.h"
#include "volePSI/upstream/mpso/offlineGen/PreGen.h"

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace mp = volePSI::mpstar;

int main(int argc, char** argv) {
    oc::CLP cmd;
    cmd.parse(argc, argv);
    if (cmd.isSet("h") || cmd.isSet("help")) {
        std::cout <<
            "OIRA probe: exercises MpOira::oiraAggregate end-to-end.\n"
            "  -nn <lg>       log2 of per-party set size (default 6)\n"
            "  -k  <k>        number of parties (default 3)\n"
            "  -nt <nt>       threads (default 1)\n"
            "  -r  <idx>      this party index (0..k-1)\n"
            "  -kAnon <int>   k-anonymity threshold (default 20)\n"
            "  -eps <d>       DP epsilon (default 1.0)\n"
            "  -delta <int>   value bound (sensitivity) (default 1<<40)\n"
            "  -preGen        run offline pregen (both MPSIC + MPSICS)\n";
        return 0;
    }

    uint32_t nn    = cmd.getOr<uint32_t>("nn", 6);
    uint32_t n     = cmd.getOr<uint32_t>("n", 1u << nn);
    uint32_t k     = cmd.getOr<uint32_t>("k", 3);
    uint32_t nt    = cmd.getOr<uint32_t>("nt", 1);
    uint32_t idx   = cmd.getOr<uint32_t>("r", static_cast<uint32_t>(-1));
    uint32_t kAnon = cmd.getOr<uint32_t>("kAnon", 20);
    double   eps   = cmd.getOr<double>("eps", 1.0);
    uint64_t delta = cmd.getOr<uint64_t>("delta", 1ULL << 40);
    // If -useValues is set, the probe passes an explicit per-item values
    // array to oiraAggregate (each item's value = 100 * (i + 1) so the
    // aggregate is easily verified: Σ 100*(item+1) over intersection).
    // Otherwise it falls back to the upstream value=key encoding.
    bool useValues = cmd.isSet("useValues");
    // Optional DP-budget accountant knobs. When -budgetFile is set, the
    // probe consults the file to check + reserve budget for this query.
    std::string budgetFile  = cmd.getOr<std::string>("budgetFile", "");
    std::string budgetScope = cmd.getOr<std::string>("budgetScope", "");
    double      budgetCap   = cmd.getOr<double>("budgetCap", 10.0);
    uint32_t    budgetQCap  = cmd.getOr<uint32_t>("budgetQCap", 100);
    bool        budgetReset = cmd.isSet("budgetReset");
    // Sector-filter mode: assign each item to a sector deterministically
    // via sector(id) = id % numSectors. `-sectorFilter s` zeros the values
    // for items where sector(id) != s, so the aggregate covers only sector s.
    // Ground truth is recomputed accordingly. When -sectorFilter is UNSET,
    // no sector masking applies (aggregate covers whole intersection).
    // -numSectors <K> controls the sector modulus; default 5.
    uint32_t numSectors  = cmd.getOr<uint32_t>("numSectors", 5);
    int32_t  sectorFilter = cmd.getOr<int32_t>("sectorFilter", -1);
    bool sectorFilterOn = (sectorFilter >= 0);
    bool preGenMpsic  = cmd.isSet("preGen-mpsic");
    bool preGenMpsics = cmd.isSet("preGen-mpsics");

    if (idx >= k) {
        std::cerr << "invalid -r " << idx << " (must be < k=" << k << ")\n";
        return 2;
    }

    if (preGenMpsic) {
        MPSICpreGen(idx, k, nn, nt);
        return 0;
    }
    if (preGenMpsics) {
        MPSICSpreGen(idx, k, nn, nt);
        return 0;
    }

    // Same synthetic sets the MPSICS probe uses: party i contributes
    // {i+1, i+2, ..., i+n}. Intersection over k parties: {k, ..., n}.
    std::vector<oc::block> set(n);
    for (uint32_t i = 0; i < n; ++i) {
        set[i] = oc::toBlock(idx + i + 1);
    }
    uint64_t trueCard = (n >= k) ? (n - k + 1) : 0;

    // Ground-truth aggregate depends on which mode we're in.
    // - Default (upstream value=key): aggregate = Σ id for id in intersection
    //   times (N-1) contributions (each non-P0 sender contributes once).
    //   The oiraAggregate call divides by (N-1) internally.
    // - useValues: caller passes values[i] = 100 * (id_i) where
    //   id_i = idx + i + 1. Aggregate summed by non-P0 senders:
    //   Σ_{intersection id} Σ_{party j > 0} 100 * (j + item_idx_in_j + 1).
    //   For each intersection value v (i.e., ids v = k..n), party j has this
    //   at position i = v - j - 1, so its contribution is 100 * v (since
    //   j + (v - j - 1) + 1 = v). Total = Σ_{j=1..N-1} 100 v = (N-1) * 100 * v
    //   per intersection element. oiraAggregate divides by (N-1) => 100 * v.
    //   Summed over intersection: 100 * Σ v.
    uint64_t trueAgg = 0;
    uint64_t trueCardSector = 0;  // for sector mode; how many intersection ids fall in sector
    std::vector<uint64_t> values;

    if (sectorFilterOn && !useValues) {
        std::cerr << "sectorFilter requires -useValues (need real per-item values)\n";
        return 2;
    }

    if (useValues) {
        values.resize(n);
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t my_id = idx + i + 1;
            uint64_t v = 100ULL * my_id;
            if (sectorFilterOn) {
                // sector(id) = id % numSectors. Mask value to 0 if item is
                // not in the targeted sector.
                uint32_t s = static_cast<uint32_t>(my_id % numSectors);
                if (s != static_cast<uint32_t>(sectorFilter)) {
                    v = 0;
                }
            }
            values[i] = v;
        }
        // Ground-truth aggregate: intersection = {v : v ∈ [k, n]}.
        //   - Non-sector mode: sum over all intersection ids.
        //   - Sector mode: sum only intersection ids where v % numSectors == sectorFilter.
        for (uint32_t v = k; v <= n; ++v) {
            if (sectorFilterOn &&
                static_cast<uint32_t>(v % numSectors) != static_cast<uint32_t>(sectorFilter)) {
                continue;
            }
            trueAgg += 100ULL * v;
            ++trueCardSector;
        }
    } else {
        for (uint32_t v = k; v <= n; ++v) trueAgg += v;
    }

    mp::OIRAConfig cfg;
    cfg.kAnon           = kAnon;
    cfg.epsilon         = eps;
    cfg.valueBound      = delta;
    cfg.alwaysRunPhase2 = false;

    // Optional DP-budget accountant.
    mp::OIRABudgetConfig budgetCfg;
    if (!budgetFile.empty() && !budgetScope.empty()) {
        budgetCfg.scopeId     = budgetScope;
        budgetCfg.budgetFile  = budgetFile;
        budgetCfg.epsilonCap  = budgetCap;
        budgetCfg.queryCap    = budgetQCap;
        if (budgetReset && idx == 0) {
            mp::oiraBudgetReset(budgetCfg);
        }
        cfg.budget = &budgetCfg;
    }

    const std::vector<uint64_t>* valuesPtr = useValues ? &values : nullptr;
    mp::OIRAResult res = mp::oiraAggregate(idx, k, n, set, cfg, nt, valuesPtr);

    if (idx != 0) {
        // Non-P0: silent participation, exit 0.
        return 0;
    }

    // Party 0 emits result summary.
    if (!res.released) {
        // Distinguish suppression (k-anon fail) from budget exhaustion
        // so the shell orchestrator can tell them apart.
        const char* tag = "SUPPRESSED";
        if (res.reason.rfind("budget_exhausted", 0) == 0) {
            tag = "BUDGET_EXHAUSTED";
        }
        std::cout << tag << ": " << res.reason
                  << " (trueCard=" << res.trueCardinality
                  << ", kAnon=" << kAnon << ")\n";
        // For "expected suppression / expected budget exhaustion" test cases
        // this is a PASS scenario. The shell script wraps this check.
        return 0;
    }

    // Correctness bounds:
    //  - trueCard should match the analytical value we computed above
    //  - noisyCard should be within ~10 * (1/eps) of trueCard (Laplace
    //    tail cover > 99.99% by Chebyshev)
    //  - noisyAgg  should be within ~10 * (delta/eps) of trueAgg
    double cardScale = 1.0 / eps;
    double aggScale  = static_cast<double>(delta) / eps;
    double cardWindow = 10.0 * cardScale;
    double aggWindow  = 10.0 * aggScale;

    bool cardOK = (res.trueCardinality == trueCard);
    bool cardNoiseOK =
        std::llabs(static_cast<long long>(res.noisyCardinality) -
                   static_cast<long long>(res.trueCardinality)) <= cardWindow;
    bool aggOK = (res.trueAggregate == trueAgg);
    bool aggNoiseOK =
        std::llabs(res.noisyAggregate - static_cast<int64_t>(res.trueAggregate))
        <= static_cast<long long>(aggWindow);

    std::cout << "released=1"
              << " trueCard=" << res.trueCardinality
              << " (expected " << trueCard << ")"
              << " noisyCard=" << res.noisyCardinality
              << " trueAgg=" << res.trueAggregate
              << " (expected " << trueAgg << ")"
              << " noisyAgg=" << res.noisyAggregate
              << "\n";

    // Structured single-line summary for the all-sectors driver to parse.
    // In sector-filter mode, `trueCardSector` is the count of intersection
    // ids whose sector matches the filter. `noisyCard` is still the FULL
    // intersection cardinality (MPSICS computes it that way). The driver
    // uses expectedSectorCard to sanity-check the aggregate.
    std::cout << "SECTOR_RESULT sector="
              << (sectorFilterOn ? std::to_string(sectorFilter) : std::string("ALL"))
              << " numSectors=" << numSectors
              << " trueCardTotal=" << res.trueCardinality
              << " trueCardSector=" << (sectorFilterOn ? trueCardSector : res.trueCardinality)
              << " noisyCardTotal=" << res.noisyCardinality
              << " trueAgg=" << res.trueAggregate
              << " noisyAgg=" << res.noisyAggregate
              << "\n";

    if (!cardOK)      { std::cerr << "FAIL: cardinality mismatch\n"; return 1; }
    if (!cardNoiseOK) { std::cerr << "FAIL: noisyCard beyond 10*scale window\n"; return 1; }
    if (!aggOK)       { std::cerr << "FAIL: aggregate mismatch\n"; return 1; }
    if (!aggNoiseOK)  { std::cerr << "FAIL: noisyAgg beyond 10*scale window\n"; return 1; }
    std::cout << "PASS: OIRA end-to-end (k=" << k
              << ", n=" << n << ", kAnon=" << kAnon
              << ", eps=" << eps << ", delta=" << delta << ")\n";
    return 0;
}
