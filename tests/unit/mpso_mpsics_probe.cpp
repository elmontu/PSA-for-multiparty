// Standalone probe of the vendored MPSO MPSICS (MPSI-Cardinality-Sum)
// protocol. Adapted from upstream test/test_mpsics.cpp — same test logic,
// includes rewritten for our vendored layout.
//
// Purpose: prove the vendored 2025/640 MPSO code (which we linked into
// libvolePSI.a during Stage B) actually runs end-to-end. If this probe
// passes, we know MPSICS is the primitive to build the double-blind
// vulnerability-score protocol on.
//
// Usage (multi-process):
//   ./mpso_mpsics_probe -preGen -r 0 -nn 6 -k 3
//   ./mpso_mpsics_probe -preGen -r 1 -nn 6 -k 3
//   ./mpso_mpsics_probe -preGen -r 2 -nn 6 -k 3
// then online:
//   ./mpso_mpsics_probe -r 0 -nn 6 -k 3
//   ./mpso_mpsics_probe -r 1 -nn 6 -k 3
//   ./mpso_mpsics_probe -r 2 -nn 6 -k 3
//
// Party 0 prints "MPSI Card Sum success!" iff the aggregate matches
// cleartext Σ i over the intersection. Other parties silently
// contribute. See tests/run_mpso_mpsics_probe.sh for the orchestration.

#include <algorithm>
#include "volePSI/upstream/mpso/offlineGen/PreGen.h"
#include "volePSI/upstream/mpso/mpso/MPSICS.h"

void MPSICardSum_test(u32 idx, u32 numElements, u32 numParties, u32 numThreads) {
    oc::CuckooParam params = oc::CuckooIndex<>::selectParams(numElements, ssp, 0, 3);
    u32 numBins = params.numBins();

    // Correlations produced by MPSICSpreGen.
    ShareCorrelationXor sc1(numParties, numBins);
    ShareCorrelationAdd sc2(numParties, numBins);
    if (!sc1.exist("psics1")) {
        std::cerr << "psics1 correlation file missing; run with -preGen first\n";
        return;
    }
    if (!sc2.exist("psics2")) {
        std::cerr << "psics2 correlation file missing; run with -preGen first\n";
        return;
    }

    // Same synthetic set the upstream test uses: party idx contributes
    // {idx+1, idx+2, ..., idx+numElements}. Intersection over k parties:
    // {k, k+1, ..., numElements}. In this MPSICS variant the summed
    // "value" IS the item's low64 (see PMT.cpp:492: uses hyj.mData[1]
    // which is set[b].mData[0]). So the expected aggregate is
    // Σ i for i in [numParties, numElements+1), times (numParties-1)
    // because each of the N-1 senders contributes the same value per bin.
    std::vector<block> set(numElements);
    for (u32 i = 0; i < numElements; ++i) {
        set[i] = oc::toBlock(idx + i + 1);
    }

    u64 realSum = 0;
    for (u32 i = numParties; i < numElements + 1; ++i) realSum += i;

    if (idx == 0) {
        u64 outSum = MPSICardSumParty(idx, numParties, numElements, set, numThreads);
        outSum /= (numParties - 1);
        if (outSum == realSum) {
            u32 nn = oc::log2ceil(numElements);
            std::cout << "PASS: MPSICS k=" << numParties << " n=" << numElements
                      << " (log " << nn << ") sum=" << outSum << "\n";
        } else {
            std::cout << "FAIL: got sum=" << outSum
                      << " expected=" << realSum << "\n";
            std::exit(1);
        }
    } else {
        MPSICardSumParty(idx, numParties, numElements, set, numThreads);
    }
    sc1.release();
    sc2.release();
}

int main(int argc, char** argv) {
    oc::CLP cmd;
    cmd.parse(argc, argv);
    u32 nn = cmd.getOr<u32>("nn", 6);
    u32 n  = cmd.getOr<u32>("n", 1u << nn);
    u32 k  = cmd.getOr<u32>("k", 3);
    u32 nt = cmd.getOr<u32>("nt", 1);
    u32 idx = cmd.getOr<u32>("r", static_cast<u32>(-1));
    bool preGen = cmd.isSet("preGen");
    bool help = cmd.isSet("h") || cmd.isSet("help");
    if (help) {
        std::cout <<
            "MPSO MPSICS probe.\n"
            "  -nn <lg>    log2 of element count per party (default 6)\n"
            "  -n  <n>     element count per party (overrides -nn)\n"
            "  -k  <k>     number of parties (default 3)\n"
            "  -nt <nt>    threads (default 1)\n"
            "  -r  <idx>   party index (0..k-1)\n"
            "  -preGen     run offline pregen phase\n";
        return 0;
    }
    if (idx >= k) {
        std::cerr << "invalid -r " << idx << " (must be < k=" << k << ")\n";
        return 2;
    }
    if (preGen) {
        MPSICSpreGen(idx, k, nn, nt);
    } else {
        MPSICardSum_test(idx, n, k, nt);
    }
    return 0;
}
