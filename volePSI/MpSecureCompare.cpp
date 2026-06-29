#include "MpSecureCompare.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Consume one triple from the bag, bumping the index.
const BeaverTripleBit& takeTriple(
    const std::vector<BeaverTripleBit>& triples, size_t& idx)
{
    if (idx >= triples.size())
        throw std::runtime_error("takeTriple: triple bag exhausted");
    return triples[idx++];
}

// NOT for XOR-shared bit: party 0 flips its share. Local.
SharedBit notShared(const SharedBit& a)
{
    return xorConst(a, 1);
}

// OR of two shared bits via De Morgan: a OR b = NOT (NOT a AND NOT b).
SharedBit secureOr(const SharedBit& a, const SharedBit& b,
                   const std::vector<BeaverTripleBit>& triples,
                   size_t& tripleIndex)
{
    auto na = notShared(a);
    auto nb = notShared(b);
    auto naAndNb = secureAnd(na, nb, takeTriple(triples, tripleIndex));
    return notShared(naAndNb);
}

} // namespace

SharedU64Bin shareU64Bin(uint32_t N, uint64_t value, oc::PRNG& prng)
{
    SharedU64Bin out;
    for (uint32_t i = 0; i < 64; ++i) {
        uint8_t bit = (value >> i) & 1;
        out.bits[i] = shareBit(N, bit, prng);
    }
    return out;
}

size_t secureLessThanTripleCost()
{
    // Per bit (i = 0..63):
    //   diff   = x_i XOR y_i               (free)
    //   first  = diff AND (NOT decided)    (1 secureAnd)
    //   contrib = first AND y_i            (1 secureAnd)
    //   new_result = result OR contrib     (1 secureOr = 1 secureAnd via De Morgan)
    //   new_decided = decided OR first     (1 secureOr = 1 secureAnd)
    // Total per bit: 4 triples. Across 64 bits: 256 triples.
    return 64 * 4;
}

SharedBit secureLessThan(const SharedU64Bin& x,
                         const SharedU64Bin& y,
                         const std::vector<BeaverTripleBit>& triples,
                         size_t& tripleIndex)
{
    if (x.N() != y.N())
        throw std::runtime_error("secureLessThan: N mismatch");
    const uint32_t N = x.N();

    // result = 0, decided = 0 (all-zero shares).
    SharedBit result(N);
    SharedBit decided(N);

    // Walk bits MSB → LSB. The first position where x_i != y_i decides
    // the outcome: x < y iff that bit has x_i=0, y_i=1, i.e., y_i = 1.
    for (int i = 63; i >= 0; --i) {
        SharedBit diff = xorShared(x.bits[i], y.bits[i]);
        SharedBit notDecided = notShared(decided);
        SharedBit first = secureAnd(diff, notDecided,
                                    takeTriple(triples, tripleIndex));
        SharedBit contrib = secureAnd(first, y.bits[i],
                                      takeTriple(triples, tripleIndex));
        result   = secureOr(result, contrib, triples, tripleIndex);
        decided  = secureOr(decided, first, triples, tripleIndex);
    }
    return result;
}

size_t secureEqualTripleCost()
{
    // For each bit: diff_i = x_i XOR y_i (free). Then we need
    // eq = NOT (OR over all diff_i) = AND over all (NOT diff_i).
    //
    // AND-tree over 64 leaves: 63 ANDs.
    return 63;
}

SharedBit secureEqual(const SharedU64Bin& x,
                      const SharedU64Bin& y,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& tripleIndex)
{
    if (x.N() != y.N())
        throw std::runtime_error("secureEqual: N mismatch");
    const uint32_t N = x.N();

    // eq_i = NOT diff_i = NOT (x_i XOR y_i)
    std::vector<SharedBit> eqBits(64);
    for (uint32_t i = 0; i < 64; ++i) {
        SharedBit diff = xorShared(x.bits[i], y.bits[i]);
        eqBits[i] = notShared(diff);
    }

    // AND-tree: pairwise AND until one bit remains.
    std::vector<SharedBit> level = std::move(eqBits);
    while (level.size() > 1) {
        std::vector<SharedBit> next;
        next.reserve((level.size() + 1) / 2);
        size_t i = 0;
        for (; i + 1 < level.size(); i += 2) {
            next.push_back(secureAnd(level[i], level[i + 1],
                                     takeTriple(triples, tripleIndex)));
        }
        if (i < level.size()) next.push_back(level[i]);
        level = std::move(next);
    }
    if (level.empty()) {
        // Degenerate: all-equal trivially.
        SharedBit one(N);
        one.shares[0] = 1;
        return one;
    }
    return level[0];
}

} // namespace mpstar
} // namespace volePSI
