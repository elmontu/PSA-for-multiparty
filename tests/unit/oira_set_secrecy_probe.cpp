// Output-level set-secrecy probe for MPSICS (adversarial test).
//
// Threat model: MAS is honest-but-curious. Bank A's submission set S may
// change across sessions. This probe asks: can MAS distinguish two runs
// where Bank A's set differs by ONE firm, from the OUTPUT (noisyCard,
// noisyAgg) alone?
//
//   Variant A: Bank A submits {1..64}      (intersects with {3..66} to give 62)
//   Variant B: Bank A submits {1..63, 999} (drops firm 64, adds firm 999
//                                          which no other party has)
//              → intersects with {3..66} to give 61
//
// Party 2 (Bank B) submits {2..65}, unchanged across variants.
// Party 0 (MAS)   submits {3..66}, unchanged across variants.
//
// If the two variants produce identical output to MAS → set-secrecy holds
// at the output tier for this specific 1-firm perturbation.
// If they differ → set-secrecy FAILS, MAS can distinguish.
//
// DP is effectively disabled by using a HUGE epsilon (Laplace scale ≈ 0)
// so trueCard/trueAgg are the effective observations. Real deployment
// would re-enable DP; this test isolates the output-signal channel.
//
// Invocation contract (see tests/run_oira_set_secrecy_smoke.sh):
//   1) Pregen once per party (mpsic + mpsics)
//   2) Run variant A (K=3 parties in parallel, party 1 with -bankA-set A)
//   3) Wait for ports to drain
//   4) Run variant B (party 1 with -bankA-set B)
//   5) Diff the two SETSECRECY_RESULT lines from party 0

#include "volePSI/MpOira.h"
#include "volePSI/upstream/mpso/offlineGen/PreGen.h"

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace mp = volePSI::mpstar;

int main(int argc, char** argv) {
    oc::CLP cmd;
    cmd.parse(argc, argv);
    if (cmd.isSet("h") || cmd.isSet("help")) {
        std::cout <<
            "oira_set_secrecy_probe: two-variant MPSICS run where Bank A's set differs\n"
            "  -r <idx>          party index (0..2)  [0=MAS, 1=BankA, 2=BankB]\n"
            "  -bankA-set <A|B>  Bank A's variant (party 1 only). Default A.\n"
            "  -preGen-mpsic     offline pregen (MPSIC)\n"
            "  -preGen-mpsics    offline pregen (MPSICS)\n";
        return 0;
    }

    // Fixed constants — hardcoded to match this specific 3-party test.
    constexpr uint32_t K  = 3;
    constexpr uint32_t nn = 6;   // log2(numElements)
    constexpr uint32_t n  = 64;  // numElements per party
    constexpr uint32_t nt = 1;

    uint32_t idx      = cmd.getOr<uint32_t>("r", static_cast<uint32_t>(-1));
    std::string variant = cmd.getOr<std::string>("bankA-set", std::string("A"));
    bool preGenMpsic  = cmd.isSet("preGen-mpsic");
    bool preGenMpsics = cmd.isSet("preGen-mpsics");

    if (idx >= K) {
        std::cerr << "invalid -r " << idx << " (need < " << K << ")\n";
        return 2;
    }
    if (variant != "A" && variant != "B") {
        std::cerr << "invalid -bankA-set '" << variant << "' (want A or B)\n";
        return 2;
    }

    if (preGenMpsic)  { MPSICpreGen(idx, K, nn, nt);  return 0; }
    if (preGenMpsics) { MPSICSpreGen(idx, K, nn, nt); return 0; }

    // Build this party's set. All ids in the LOW 64 bits of the block
    // (oc::block ctor is (high, low) so use block(0, id)).
    std::vector<oc::block> set(n);
    if (idx == 0) {
        // MAS: {3..66}
        for (uint32_t i = 0; i < n; ++i) set[i] = oc::toBlock(3 + i);
    } else if (idx == 1) {
        // Bank A: {1..64}  (variant A)   or  {1..63, 999}  (variant B)
        if (variant == "A") {
            for (uint32_t i = 0; i < n; ++i) set[i] = oc::toBlock(1 + i);
        } else {
            for (uint32_t i = 0; i < 63; ++i) set[i] = oc::toBlock(1 + i);
            set[63] = oc::toBlock(999);   // the perturbation
        }
    } else {
        // Bank B: {2..65}
        for (uint32_t i = 0; i < n; ++i) set[i] = oc::toBlock(2 + i);
    }

    // Values (non-P_0 parties only): value_i = 100 * id_i for each own item.
    // Matches the -useValues scenario in oira_probe.cpp so the aggregate
    // is easy to sanity-check.
    std::vector<uint64_t> values;
    if (idx != 0) {
        values.resize(n);
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t id;
            std::memcpy(&id, &set[i], 8);   // low 64 bits
            values[i] = 100ULL * id;
        }
    }
    const std::vector<uint64_t>* valuesPtr = (idx != 0) ? &values : nullptr;

    // OIRA config with DP effectively DISABLED for exact output comparison.
    // MpOira asserts epsilon > 0, so we use a very large value: Laplace scale
    // = delta/eps ≈ 0. Round-to-int in the noisy fields will collapse to
    // trueCard / trueAgg. Test-only choice; production restores DP.
    mp::OIRAConfig cfg;
    cfg.kAnon           = 1;
    cfg.epsilon         = 1e18;    // huge → scale ≈ 0 → noise ≈ 0
    cfg.valueBound      = 1024;    // sensitivity; irrelevant when scale≈0
    cfg.alwaysRunPhase2 = false;
    cfg.budget          = nullptr;

    mp::OIRAResult res = mp::oiraAggregate(idx, K, n, set, cfg, nt, valuesPtr);

    if (idx != 0) return 0;   // non-P_0 parties emit nothing

    // Party 0 emits the parseable observation line. The shell orchestrator
    // greps for SETSECRECY_RESULT and diffs across two variants.
    // If the same values appear for variant A and variant B, MAS cannot
    // distinguish them from output alone → output-tier set-secrecy holds
    // FOR THIS PERTURBATION.
    std::cout << "SETSECRECY_RESULT variant=" << variant
              << " trueCard=" << res.trueCardinality
              << " trueAgg="  << res.trueAggregate
              << " noisyCard=" << res.noisyCardinality
              << " noisyAgg=" << res.noisyAggregate
              << " released=" << (res.released ? 1 : 0)
              << "\n";
    return 0;
}
