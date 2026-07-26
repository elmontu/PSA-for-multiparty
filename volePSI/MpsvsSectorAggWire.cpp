#include "MpsvsSectorAggWire.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {
// Forward-decl of the arith triple type + generator (see MpBeaverTriple.h).
} // namespace mpstar
} // namespace volePSI

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleU64;
using mpstar::secureAnd;
using mpstar::secureMultiply;
using mpstar::shareU64;
using mpstar::addShared;
using mpstar::subShared;
using mpstar::mulConst;
using mpstar::addConst;
using mpstar::generateBeaverTriple;
using mpstar::generateBeaverTriples;
using mpstar::xorShared;

// ---------------------------------------------------------------------------
// Bit-shared → Arithmetic-shared conversion (proper B2A).
// ---------------------------------------------------------------------------
//
// b = b_0 XOR b_1 = b_0 + b_1 - 2·(b_0 · b_1)   (as integers)
// We compute b_0·b_1 as an arithmetic share via ONE arith Beaver triple.
// Party 0's private input is b_0 ∈ {0,1}, party 1's is b_1.
//
// Protocol (input phase then multiply):
//   1. Party 0 arithmetic-shares b_0: distribute (b_0 - r, r) for random r.
//   2. Party 1 arithmetic-shares b_1 similarly.
//   3. Beaver-multiply the two arithmetic shares.
//   4. Combine: arith(b) = arith(b_0) + arith(b_1) - 2 · arith(b_0·b_1).
//
// Cost: 1 arith Beaver triple per bit + 1 arith mult (which is what the
// triple is for). Two openings.
static SharedU64 bitToArithProper(const SharedBit& b, oc::PRNG& prng,
                                    const std::vector<BeaverTripleU64>& atriples,
                                    size_t& atrIdx) {
    if (atrIdx >= atriples.size())
        throw std::runtime_error("arith triple bag exhausted (B2A)");
    const uint32_t N = b.N();

    // Party 0 arith-shares its bit share b_0. In the 2-party in-memory sim
    // we generate a fresh sharing directly.
    SharedU64 a0 = shareU64(N, static_cast<uint64_t>(b.shares[0] & 1), prng);
    SharedU64 a1 = shareU64(N, static_cast<uint64_t>(b.shares[1] & 1), prng);

    // Compute a_prod = a0 · a1 via Beaver mult.
    SharedU64 a_prod = secureMultiply(a0, a1, atriples[atrIdx++]);

    // arith(b) = a0 + a1 - 2·a_prod  (all local now)
    SharedU64 sum = addShared(a0, a1);
    SharedU64 two_prod = mulConst(a_prod, 2);
    return subShared(sum, two_prod);
}

size_t sectorAggTripleBudgetPerRow() {
    // Per metric:
    //   B2A of incl bit: 1 arith triple
    //   B2A of num (64 bit-shares): 64 arith triples
    //   B2A of den: 64 arith triples
    //   mult incl_arith · num_arith: 1 arith triple
    //   mult incl_arith · den_arith: 1 arith triple
    // Total per metric: 131 arith triples
    // 9 metrics: 1179 arith triples per row
    return 9 * (1 + 64 + 64 + 1 + 1) + 100;
}

// ---------------------------------------------------------------------------
// B2A of a full SharedU64Bin — 64 B2A calls, then weighted sum.
// ---------------------------------------------------------------------------
static SharedU64 sharedU64BinToArith(const SharedU64Bin& v, oc::PRNG& prng,
                                      const std::vector<BeaverTripleU64>& atr,
                                      size_t& idx) {
    const uint32_t N = v.N();
    SharedU64 acc(N);
    for (int i = 0; i < 64; ++i) {
        SharedU64 bit_arith = bitToArithProper(v.bits[i], prng, atr, idx);
        SharedU64 weighted = mulConst(bit_arith, 1ULL << i);
        acc = addShared(acc, weighted);
    }
    return acc;
}

// ---------------------------------------------------------------------------
// aggregateHistogramsWire — proper B2A + arithmetic Beaver mult.
// ---------------------------------------------------------------------------

std::vector<SharedSectorHistogram>
aggregateHistogramsWire(const std::vector<SharedEntityMetricRow>& rows,
                        Metric m,
                        const std::vector<BeaverTripleBit>& /*btriples*/,
                        size_t& /*btrIdx*/,
                        oc::PRNG& prng) {
    // Pre-generate the arith triple bag sized to our budget.
    // Budget = per-row triple count × #rows.
    size_t need = rows.size() * (1 + 64 + 64 + 1 + 1);
    auto atriples = generateBeaverTriples(rows.empty() ? 2 : rows[0].live.N(),
                                           need, prng);
    size_t aidx = 0;

    std::map<SectorKey, SharedSectorHistogram> agg;

    for (const auto& r : rows) {
        SectorKey k{static_cast<uint16_t>(r.sector), r.period};
        auto it = agg.find(k);
        if (it == agg.end()) {
            SharedSectorHistogram sh;
            sh.key = k;
            sh.metric = m;
            sh.sum_num = shareU64(r.live.N(), 0, prng);
            sh.sum_den = shareU64(r.live.N(), 0, prng);
            sh.n_valid = shareU64(r.live.N(), 0, prng);
            it = agg.emplace(k, std::move(sh)).first;
        }
        const SharedMetricPair& mp = r.metrics[static_cast<size_t>(m)];
        // B2A: incl bit → arith share
        SharedU64 incl_arith = bitToArithProper(mp.incl, prng, atriples, aidx);
        // B2A: num, den bit-decomposition → arith share
        SharedU64 num_arith = sharedU64BinToArith(mp.num, prng, atriples, aidx);
        SharedU64 den_arith = sharedU64BinToArith(mp.den, prng, atriples, aidx);
        // gated_num = incl_arith · num_arith
        SharedU64 gated_num = secureMultiply(incl_arith, num_arith, atriples[aidx++]);
        SharedU64 gated_den = secureMultiply(incl_arith, den_arith, atriples[aidx++]);
        it->second.sum_num = addShared(it->second.sum_num, gated_num);
        it->second.sum_den = addShared(it->second.sum_den, gated_den);
        it->second.n_valid = addShared(it->second.n_valid, incl_arith);
    }

    std::vector<SharedSectorHistogram> out;
    out.reserve(agg.size());
    for (auto& kv : agg) out.push_back(std::move(kv.second));
    return out;
}

PlainCellReconstructed reconstructCell(const SharedSectorHistogram& s) {
    return {s.key, s.metric,
            s.sum_num.reconstruct(),
            s.sum_den.reconstruct(),
            s.n_valid.reconstruct()};
}

} // namespace mpsvs
} // namespace volePSI
