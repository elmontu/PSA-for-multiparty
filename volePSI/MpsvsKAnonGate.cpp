#include "MpsvsKAnonGate.h"

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::generateBeaverTriple;
using mpstar::generateBeaverTriples;
using mpstar::secureAnd;
using mpstar::secureLessThan;
using mpstar::secureLessThanTripleCost;
using mpstar::secureMultiply;
using mpstar::shareBit;
using mpstar::shareU64;
using mpstar::shareU64Bin;
using mpstar::addShared;
using mpstar::subShared;
using mpstar::mulConst;

size_t kAnonTripleBudgetPerCell() {
    // 1 secureLessThan + slack
    return secureLessThanTripleCost() + 100;
}

// Convert arithmetic-shared to bit-shared. Prototype approach: reconstruct
// (leaks the value), then re-share bit-wise. This is a KNOWN COMPROMISE —
// production must use a proper A2B conversion (Toft prefix-tree adder).
// Documented as a semantic-simplification for this prototype.
SharedU64Bin arithToBit(const SharedU64& x, oc::PRNG& prng) {
    uint64_t v = x.reconstruct();
    return shareU64Bin(x.N(), v, prng);
}

// Bit-share → arith-share conversion (proper, using arith Beaver triple).
static SharedU64 bitToArithSingle(const SharedBit& b, oc::PRNG& prng,
                                    const BeaverTripleU64& triple) {
    const uint32_t N = b.N();
    // Party 0 arith-shares its bit share; party 1 arith-shares its bit share.
    SharedU64 a0 = shareU64(N, static_cast<uint64_t>(b.shares[0] & 1), prng);
    SharedU64 a1 = shareU64(N, static_cast<uint64_t>(b.shares[1] & 1), prng);
    SharedU64 prod = secureMultiply(a0, a1, triple);
    // arith(b) = a0 + a1 - 2 · prod
    return subShared(addShared(a0, a1), mulConst(prod, 2));
}

// Public constant shared as arith (only party 0 holds the value).
static SharedU64 shareConstArith(uint32_t N, uint64_t v) {
    SharedU64 out(N);
    out.shares[0] = v;
    return out;
}

GatedCell
applyKAnonGate(const SharedSectorHistogram& cell,
                const KAnonConfig& cfg,
                const std::vector<BeaverTripleBit>& bit_triples,
                size_t& idx,
                oc::PRNG& prng) {
    GatedCell g;
    g.key = cell.key;
    g.metric = cell.metric;
    const uint32_t N = cell.n_valid.N();

    // 1. Convert arith-shared n_valid to bit-shared for comparison.
    //    (Prototype: uses "reveal + reshare" A2B — see header note.)
    SharedU64Bin n_valid_bin = arithToBit(cell.n_valid, prng);

    // 2. Threshold as bit-shared public constant.
    // pass_bit = (k_thresh - 1 < n_valid)
    //          = secureLessThan(k_thresh - 1, n_valid_bin)
    uint64_t thresh_minus_one = (cfg.k_thresh == 0) ? 0 : (cfg.k_thresh - 1);
    SharedU64Bin thresh_bin = shareU64Bin(N, thresh_minus_one, prng);
    g.pass = secureLessThan(thresh_bin, n_valid_bin, bit_triples, idx);

    // 3. B2A the pass bit — generate fresh arith Beaver triple.
    BeaverTripleU64 triple_b2a = generateBeaverTriple(N, prng);
    SharedU64 pass_arith = bitToArithSingle(g.pass, prng, triple_b2a);

    // 4. MUX each field: output = pass · field   (arith Beaver mult).
    BeaverTripleU64 triple_mux_num = generateBeaverTriple(N, prng);
    BeaverTripleU64 triple_mux_den = generateBeaverTriple(N, prng);
    BeaverTripleU64 triple_mux_n   = generateBeaverTriple(N, prng);
    g.sum_num_gated = secureMultiply(pass_arith, cell.sum_num, triple_mux_num);
    g.sum_den_gated = secureMultiply(pass_arith, cell.sum_den, triple_mux_den);
    g.n_valid_gated = secureMultiply(pass_arith, cell.n_valid, triple_mux_n);
    return g;
}

std::vector<GatedCell>
applyKAnonGateBatch(const std::vector<SharedSectorHistogram>& cells,
                      const KAnonConfig& cfg,
                      const std::vector<BeaverTripleBit>& bit_triples,
                      size_t& idx,
                      oc::PRNG& prng) {
    std::vector<GatedCell> out;
    out.reserve(cells.size());
    for (const auto& c : cells) out.push_back(applyKAnonGate(c, cfg, bit_triples, idx, prng));
    return out;
}

PlainGatedCell reconstructGatedCell(const GatedCell& g) {
    return {g.key, g.metric,
             g.sum_num_gated.reconstruct(),
             g.sum_den_gated.reconstruct(),
             g.n_valid_gated.reconstruct(),
             g.pass.reconstruct()};
}

} // namespace mpsvs
} // namespace volePSI
