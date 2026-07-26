#include "MpsvsPercentilesWire.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::secureAnd;
using mpstar::secureLessThan;
using mpstar::secureLessThanTripleCost;
using mpstar::xorConst;
using mpstar::xorShared;

// ---------------------------------------------------------------------------
// 64-bit ripple-carry add on SharedU64Bin (mirror of Phase 6 wire helper).
// ---------------------------------------------------------------------------
static SharedU64Bin
bitAdd64(const SharedU64Bin& x, const SharedU64Bin& y,
          const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    SharedU64Bin out;
    const uint32_t N = x.N();
    SharedBit carry(N);
    for (int i = 0; i < 64; ++i) {
        SharedBit ab = xorShared(x.bits[i], y.bits[i]);
        SharedBit sum = xorShared(ab, carry);
        if (idx + 3 > triples.size())
            throw std::runtime_error("triple bag exhausted (bitAdd64)");
        SharedBit and_ab = secureAnd(x.bits[i], y.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(carry, ab, triples[idx++]);
        SharedBit or_a = xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        carry = xorShared(or_a, or_b);
        out.bits[i] = sum;
    }
    return out;
}

// ---------------------------------------------------------------------------
// sharedPrefixSum
// ---------------------------------------------------------------------------

std::vector<SharedU64Bin>
sharedPrefixSum(const std::vector<SharedU64Bin>& bins,
                  const std::vector<BeaverTripleBit>& triples,
                  size_t& idx) {
    std::vector<SharedU64Bin> cum;
    cum.reserve(bins.size());
    for (size_t b = 0; b < bins.size(); ++b) {
        if (b == 0) cum.push_back(bins[0]);
        else cum.push_back(bitAdd64(cum[b - 1], bins[b], triples, idx));
    }
    return cum;
}

// ---------------------------------------------------------------------------
// percentileBucketWire
// ---------------------------------------------------------------------------

size_t percentileWireTripleBudget(uint32_t B) {
    // Prefix sum: (B-1) × 192.
    // Target compute: 1 × mulPublicConst (on 64-bit N, up to 64 adds × 192 = ~12K).
    // Linear scan: B × secureLessThan + B × secureAnd ≈ B × 193.
    return (B - 1) * 192            // prefix sums
         + 64 * 192                  // target (public multiply on shared N)
         + B * (secureLessThanTripleCost() + 1)
         + 500;
}

// mulPublicConst on bit-shared 64-bit value.
static SharedU64Bin
mulPublicConst64(const SharedU64Bin& x, uint64_t c,
                   const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    const uint32_t N = x.N();
    SharedU64Bin acc;
    for (int i = 0; i < 64; ++i) acc.bits[i] = SharedBit(N);
    for (int bit = 0; bit < 64; ++bit) {
        if (!((c >> bit) & 1)) continue;
        SharedU64Bin shifted;
        for (int i = 0; i < 64; ++i) shifted.bits[i] = SharedBit(N);
        for (int i = 0; i < 64 - bit; ++i) shifted.bits[i + bit] = x.bits[i];
        acc = bitAdd64(acc, shifted, triples, idx);
    }
    return acc;
}

// Right-shift a SharedU64Bin by public shift (free — bit relabel).
static SharedU64Bin
shiftRight64(const SharedU64Bin& x, int s) {
    const uint32_t N = x.N();
    SharedU64Bin out;
    for (int i = 0; i < 64; ++i) out.bits[i] = SharedBit(N);
    for (int i = 0; i < 64 - s; ++i) out.bits[i] = x.bits[i + s];
    return out;
}

SharedU64Bin
percentileBucketWire(const std::vector<SharedU64Bin>& cum,
                       const SharedU64Bin& N,
                       uint32_t q_num, uint32_t q_den,
                       const std::vector<BeaverTripleBit>& triples,
                       size_t& idx) {
    if (cum.empty())
        throw std::invalid_argument("percentileBucketWire: empty cum");
    if (q_den == 0)
        throw std::invalid_argument("percentileBucketWire: q_den = 0");
    const uint32_t N_share = cum[0].N();

    // Compute shared target = ⌈q_num · N / q_den⌉.
    // We approximate ceil(q_num · N / q_den) using integer arithmetic on the
    // shared N:
    //   target = (N · q_num + q_den - 1) / q_den
    // The +q_den-1 term is a public constant, add via XOR with party-0.
    // The final / q_den is a PUBLIC divide — precompute a multiplier if q_den
    // is a power of 2 (right-shift); else compute via reciprocal (not needed
    // for standard percentiles 25/50/75/90/95/99 with q_den = 100 → we can
    // pre-scale q_num by 2^k / 100 and shift).
    //
    // For simplicity handle q_den being a power of 2 (percentiles like
    // q=1/2, 1/4, 1/8) directly. For q=1/2 (median): q_num=1, q_den=2,
    // right-shift N by 1. Non-power-of-2 handled below via mul + shift.
    SharedU64Bin target;
    if (q_num == 1 && (q_den & (q_den - 1)) == 0) {
        // Power-of-2 divisor: N · 1 / q_den = N >> log2(q_den).
        int s = 0;
        while ((1u << s) < q_den) ++s;
        target = shiftRight64(N, s);
    } else {
        // General: target = (N · q_num) / q_den. We approximate by choosing
        // a bit-width B such that q_num · 2^B / q_den fits nicely, then
        // multiply and shift.
        // For the standard percentiles (q_den = 100), use B = 20:
        //   scale = 2^20 · q_num / q_den (public integer)
        //   target = (N · scale) >> 20  (public constant mult + shift)
        const int B_scale = 20;
        uint64_t scale = (static_cast<uint64_t>(q_num) << B_scale) / q_den;
        SharedU64Bin scaled = mulPublicConst64(N, scale, triples, idx);
        target = shiftRight64(scaled, B_scale);
    }

    // Linear scan for smallest b with cum[b] >= target.
    // For each b:
    //   ge_b = NOT secureLessThan(cum[b], target)
    //   found_b = ge_b AND NOT prev_ge
    // Fold b · found_b into shared bucket ID.
    SharedU64Bin bucket;
    for (int i = 0; i < 64; ++i) bucket.bits[i] = SharedBit(N_share);

    SharedBit prev_ge(N_share);   // starts as shared 0
    for (size_t b = 0; b < cum.size(); ++b) {
        SharedBit lt = secureLessThan(cum[b], target, triples, idx);
        SharedBit ge = xorConst(lt, 1);
        SharedBit not_prev_ge = xorConst(prev_ge, 1);
        if (idx >= triples.size())
            throw std::runtime_error("triple bag exhausted (found_b AND)");
        SharedBit found = secureAnd(ge, not_prev_ge, triples[idx++]);
        // Fold: for each bit i where b has bit i set, XOR `found` into bucket.
        for (int i = 0; i < 32; ++i) {
            if ((b >> i) & 1) bucket.bits[i] = xorShared(bucket.bits[i], found);
        }
        prev_ge = ge;
    }
    return bucket;
}

} // namespace mpsvs
} // namespace volePSI
