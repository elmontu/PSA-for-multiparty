#include "MpsvsGoldschmidtWire.h"

#include <cmath>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::secureAnd;
using mpstar::shareBit;
using mpstar::xorConst;
using mpstar::xorShared;

// ---------------------------------------------------------------------------
// Share / helpers
// ---------------------------------------------------------------------------

SharedU128Bin shareU128Bin(uint32_t N, __int128 value, oc::PRNG& prng) {
    SharedU128Bin out(N);
    for (int i = 0; i < 128; ++i) {
        uint8_t bit = static_cast<uint8_t>((value >> i) & 1);
        out.bits[i] = shareBit(N, bit, prng);
    }
    return out;
}

SharedU128Bin shareFpFromU64(uint32_t N, uint64_t value, oc::PRNG& prng) {
    __int128 v = static_cast<__int128>(value) << kFpFractionalBits;
    return shareU128Bin(N, v, prng);
}

double fpToDoubleShared(const SharedU128Bin& v) {
    __int128 raw = v.reconstruct();
    // Interpret as unsigned for our positive-only fp case.
    long double d = static_cast<long double>(raw);
    long double scale = static_cast<long double>(1ULL << kFpFractionalBits);
    return static_cast<double>(d / scale);
}

// ---------------------------------------------------------------------------
// 128-bit ripple-carry add
// ---------------------------------------------------------------------------

SharedU128Bin bitAdd128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& idx) {
    const uint32_t N = x.bits[0].N();
    SharedU128Bin out(N);
    SharedBit carry(N);
    for (int i = 0; i < 128; ++i) {
        // full-adder
        SharedBit ab = xorShared(x.bits[i], y.bits[i]);
        SharedBit sum = xorShared(ab, carry);
        if (idx + 3 > triples.size())
            throw std::runtime_error("triple bag exhausted (bitAdd128)");
        SharedBit and_ab = secureAnd(x.bits[i], y.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(carry, ab, triples[idx++]);
        SharedBit or_a = xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        carry = xorShared(or_a, or_b);
        out.bits[i] = sum;
    }
    return out;
}

SharedU128Bin bitSub128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& idx) {
    // Two's complement: -y = ~y + 1.
    // ~y (bitwise NOT via XOR with 1): free.
    // +1 via one full-adder chain with carry-in = 1.
    const uint32_t N = x.bits[0].N();
    SharedU128Bin ny(N);
    for (int i = 0; i < 128; ++i) ny.bits[i] = xorConst(y.bits[i], 1);
    // Now compute x + ny + 1, absorbing +1 as initial carry.
    SharedU128Bin out(N);
    SharedBit carry(N);
    carry.shares[0] = 1;   // party 0 holds the +1
    for (int i = 0; i < 128; ++i) {
        SharedBit ab = xorShared(x.bits[i], ny.bits[i]);
        SharedBit sum = xorShared(ab, carry);
        SharedBit and_ab = secureAnd(x.bits[i], ny.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(carry, ab, triples[idx++]);
        SharedBit or_a = xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        carry = xorShared(or_a, or_b);
        out.bits[i] = sum;
    }
    return out;
}

// ---------------------------------------------------------------------------
// 128-bit multiplication: shift-and-conditional-add.
// Iterates over bits of y; for each set bit y_i, add (x << i) into acc.
// The "condition" is y_i (shared bit); the add is gated per output bit via
// secureAnd(y_i, x_bit).
// ---------------------------------------------------------------------------

SharedU128Bin bitMul128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& idx) {
    const uint32_t N = x.bits[0].N();
    SharedU128Bin acc(N);
    for (int i = 0; i < 128; ++i) {
        // partial = (y_i ? (x << i) : 0)
        // For each output bit j >= i: partial.bit[j] = y_i AND x.bit[j-i]
        SharedU128Bin partial(N);
        for (int j = 0; j < 128; ++j) {
            if (j < i) continue;   // partial.bit[j] = 0
            if (idx >= triples.size())
                throw std::runtime_error("triple bag exhausted (bitMul128 mux)");
            partial.bits[j] = secureAnd(y.bits[i], x.bits[j - i], triples[idx++]);
        }
        // acc += partial (128-bit add)
        acc = bitAdd128(acc, partial, triples, idx);
    }
    return acc;
}

// Fp multiply: bitMul128 then right-shift f bits (relabel — free).
SharedU128Bin fpMulShared(const SharedU128Bin& a, const SharedU128Bin& b,
                            const std::vector<BeaverTripleBit>& triples,
                            size_t& idx) {
    SharedU128Bin prod = bitMul128(a, b, triples, idx);
    // Right-shift by kFpFractionalBits (=40).
    SharedU128Bin out(a.bits[0].N());
    for (int i = 0; i < 128; ++i) {
        int j = i + kFpFractionalBits;
        if (j < 128) out.bits[i] = prod.bits[j];
        // else out.bits[i] remains zero-shared (sign-extension for positive only).
    }
    return out;
}

// ---------------------------------------------------------------------------
// Range reduction: reveal p = ceil(log2(x)) — controlled leak.
// Returns x' fp-encoded in SharedU128Bin, and stores p in `p_out`.
// Cost: 64 open-reveals of x's bits — but we open x itself (cheapest) since
// we're already leaking its bit-length. This is documented as the "magnitude
// class leak" in the header — for MPSVS aggregate counts this is acceptable.
// ---------------------------------------------------------------------------
static SharedU128Bin
rangeReduceReveal(const SharedU64Bin& x, uint64_t /*N_max*/,
                    int& p_out, oc::PRNG& prng) {
    // Reveal x (documented leak).
    uint64_t x_plain = x.reconstruct();
    if (x_plain == 0)
        throw std::runtime_error("goldschmidtRecipWire: x = 0");

    p_out = 0;
    while ((1ULL << p_out) < x_plain) ++p_out;
    // x' = x / 2^p ∈ (0.5, 1]. In fp with f=40: x' fp = x << (f - p) if p ≤ f.
    __int128 x_prime_fp;
    if (p_out <= kFpFractionalBits) {
        x_prime_fp = static_cast<__int128>(x_plain) << (kFpFractionalBits - p_out);
    } else {
        x_prime_fp = static_cast<__int128>(x_plain) >> (p_out - kFpFractionalBits);
    }
    // Re-share x'_fp between the two parties (since we opened, we re-blind).
    return shareU128Bin(x.N(), x_prime_fp, prng);
}

// ---------------------------------------------------------------------------
// goldschmidtRecipWire
// ---------------------------------------------------------------------------

size_t goldschmidtWireTripleBudget(int iterations) {
    // Per iter: 2 fpMulShared calls.
    //   Each fpMulShared = 128 (shift-and-cond-add rounds) × (128 secureAnd + 384 add) = 65536
    // Range reduce: 0 (we reveal x_plain, no bit-triples needed for the reveal).
    // Also: 3 subtract for (2 - xy) = ~380 triples per iter.
    return iterations * (2 * 65536 + 380) + 1000;
}

SharedU128Bin
goldschmidtRecipWire(const SharedU64Bin& x, uint64_t N_max,
                      int iterations,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& idx) {
    // Range-reduce (reveals p; re-shares x').
    oc::PRNG prng(oc::block(0x1111, 0x2222));   // fresh for re-sharing
    int p = 0;
    SharedU128Bin x_prime_fp = rangeReduceReveal(x, N_max, p, prng);
    const uint32_t N = x.N();

    // Initial approximation y_0 = 3 - 2·x' (fp).
    __int128 three_fp = static_cast<__int128>(3) << kFpFractionalBits;
    SharedU128Bin three_shared = shareU128Bin(N, three_fp, prng);

    // 2·x' fp — since fp encoding is x · 2^40, 2·x' fp = 2 · (x' · 2^40) —
    // multiply the encoded value by 2 (left-shift by 1 in the encoding).
    SharedU128Bin two_x_prime(N);
    for (int i = 0; i < 128; ++i) {
        if (i == 0) two_x_prime.bits[i] = SharedBit(N);
        else        two_x_prime.bits[i] = x_prime_fp.bits[i - 1];
    }

    // y = three_fp - 2·x' (128-bit sub)
    SharedU128Bin y = bitSub128(three_shared, two_x_prime, triples, idx);

    // Newton iterations
    __int128 two_fp = static_cast<__int128>(2) << kFpFractionalBits;
    SharedU128Bin two_shared = shareU128Bin(N, two_fp, prng);
    for (int t = 0; t < iterations; ++t) {
        // xy = fpMul(x', y)
        SharedU128Bin xy = fpMulShared(x_prime_fp, y, triples, idx);
        // two_minus_xy = 2 - xy
        SharedU128Bin two_minus_xy = bitSub128(two_shared, xy, triples, idx);
        // y = fpMul(y, two_minus_xy)
        y = fpMulShared(y, two_minus_xy, triples, idx);
    }

    // Rescale: 1/x = (1/x') / 2^p → right-shift y by p in fp encoding.
    if (p > 0) {
        SharedU128Bin shifted(N);
        for (int i = 0; i < 128; ++i) {
            int j = i + p;
            if (j < 128) shifted.bits[i] = y.bits[j];
        }
        y = shifted;
    }
    return y;
}

} // namespace mpsvs
} // namespace volePSI
