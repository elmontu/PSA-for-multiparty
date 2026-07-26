#include "MpsvsRatioBucketWire.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::secureAnd;
using mpstar::secureLessThan;
using mpstar::secureLessThanTripleCost;
using mpstar::xorConst;
using mpstar::xorShared;

// ---------------------------------------------------------------------------
// Bit-shared u64 add — 64-bit ripple-carry adder using secureAnd.
// Each full-adder: 3 ANDs per bit → 192 triples per add.
// ---------------------------------------------------------------------------
static SharedU64Bin bitSharedAdd(const SharedU64Bin& x, const SharedU64Bin& y,
                                   const std::vector<BeaverTripleBit>& triples,
                                   size_t& idx) {
    SharedU64Bin out;
    const uint32_t N = x.N();
    SharedBit carry(N);   // shared zero
    for (int i = 0; i < 64; ++i) {
        if (idx + 3 > triples.size())
            throw std::runtime_error("triple bag exhausted (bitSharedAdd)");
        // full-adder: sum = a XOR b XOR cin; cout = (a AND b) OR (cin AND (a XOR b))
        SharedBit ab = xorShared(x.bits[i], y.bits[i]);
        SharedBit sum = xorShared(ab, carry);
        SharedBit and_ab = secureAnd(x.bits[i], y.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(carry, ab, triples[idx++]);
        SharedBit or_a = xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        SharedBit new_carry = xorShared(or_a, or_b);
        out.bits[i] = sum;
        carry = new_carry;
    }
    return out;
}

// ---------------------------------------------------------------------------
// mulPublicConstBitShared — shift-and-add.
// ---------------------------------------------------------------------------
SharedU64Bin mulPublicConstBitShared(const SharedU64Bin& x, uint64_t c,
                                      const std::vector<BeaverTripleBit>& triples,
                                      size_t& idx) {
    const uint32_t N = x.N();
    SharedU64Bin acc;
    for (int i = 0; i < 64; ++i) acc.bits[i] = SharedBit(N);   // zero

    for (int bit = 0; bit < 64; ++bit) {
        if (!((c >> bit) & 1)) continue;
        // acc += (x << bit)
        SharedU64Bin shifted;
        for (int i = 0; i < 64; ++i) shifted.bits[i] = SharedBit(N);
        for (int i = 0; i < 64 - bit; ++i) shifted.bits[i + bit] = x.bits[i];
        acc = bitSharedAdd(acc, shifted, triples, idx);
    }
    return acc;
}

size_t bucketWireTripleBudget(uint32_t B) {
    // Per bucket lookup:
    //   - 1 initial mulPublicConstBitShared for lhs = num · ratio_scale
    //     (up to 14 set bits × 192 = 2688 triples)
    //   - Per edge (B+1 edges):
    //       1 mulPublicConstBitShared for rhs = e · den (edges up to ~2^17,
    //         so up to 17 set bits × 192 = 3264)
    //       1 secureLessThan × secureLessThanTripleCost()
    //   - B one-hot AND (2 per bucket: sel + incl gate)
    return 14 * 192                                          // lhs mul
         + (B + 1) * (17 * 192 + secureLessThanTripleCost()) // per-edge mul + LT
         + 2 * B                                              // one-hot ANDs
         + 500;                                               // slack
}

// ---------------------------------------------------------------------------
// bucketIndexWire
// ---------------------------------------------------------------------------

SharedBucketResult
bucketIndexWire(const SharedU64Bin& num,
                 const SharedU64Bin& den,
                 const std::vector<uint64_t>& edges,
                 const SharedBit& incl,
                 uint64_t ratio_scale,
                 const std::vector<BeaverTripleBit>& triples,
                 size_t& idx) {
    if (edges.size() < 2)
        throw std::invalid_argument("bucketIndexWire: too few edges");
    const uint32_t B = static_cast<uint32_t>(edges.size() - 1);
    const uint32_t N = num.N();

    SharedBucketResult r;
    r.one_hot.assign(B, SharedBit(N));

    // Compute lhs = num · ratio_scale once.
    SharedU64Bin lhs = mulPublicConstBitShared(num, ratio_scale, triples, idx);

    // For each edge, compute lt[b] = SecureLessThan(lhs, edges[b] · den).
    // Bucket b is selected iff (lt[b] == 0) AND (lt[b+1] == 1).
    // Edge b = 0 lower bound: bucket 0 selected iff (lt[1] == 1).
    // Last bucket: selected iff (lt[B] == 0).
    // For convenience compute lt[0..B]: lt[0] represents "lhs < edges[0]·den"
    // which for edges[0]=0 is false (u64 unsigned); lt[B] represents "lhs <
    // edges[B]·den" which is TRUE if lhs is within the range.
    std::vector<SharedBit> lt(edges.size(), SharedBit(N));
    for (uint32_t b = 0; b < edges.size(); ++b) {
        SharedU64Bin rhs = mulPublicConstBitShared(den, edges[b], triples, idx);
        lt[b] = secureLessThan(lhs, rhs, triples, idx);
    }

    // one_hot[b] = NOT lt[b] AND lt[b+1]  (i.e., we're past edge b but not past b+1)
    for (uint32_t b = 0; b < B; ++b) {
        SharedBit not_lt_b = xorConst(lt[b], 1);
        if (idx >= triples.size())
            throw std::runtime_error("triple bag exhausted (one-hot AND)");
        SharedBit sel = secureAnd(not_lt_b, lt[b + 1], triples[idx++]);
        // Gate by inclusion: sel AND incl.
        if (idx >= triples.size())
            throw std::runtime_error("triple bag exhausted (incl gate)");
        r.one_hot[b] = secureAnd(sel, incl, triples[idx++]);
    }

    // bucket_index: for each bit position log2(B), OR of one_hot[b] where bit b has that bit set.
    // Since B ≤ 128 (7 bits), sum over bits 0..6.
    for (int i = 0; i < 64; ++i) r.bucket_index.bits[i] = SharedBit(N);
    for (uint32_t b = 0; b < B; ++b) {
        for (int i = 0; i < 7; ++i) {
            if ((b >> i) & 1) {
                r.bucket_index.bits[i] = xorShared(r.bucket_index.bits[i], r.one_hot[b]);
            }
        }
    }

    return r;
}

uint32_t reconstructBucket(const SharedBucketResult& r) {
    for (uint32_t b = 0; b < r.one_hot.size(); ++b) {
        if (r.one_hot[b].reconstruct()) return b;
    }
    return 0;   // no bucket set → default to 0 (means incl=0 upstream)
}

} // namespace mpsvs
} // namespace volePSI
