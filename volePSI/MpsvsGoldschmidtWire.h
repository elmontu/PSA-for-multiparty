#pragma once

// MPSVS Phase 6 — MPC-wire Goldschmidt reciprocal.
//
// Fixed-point representation on shares: k=128 bits, f=40 fractional bits
// (matches Rev 7 §9 semantic ref). Fp values are stored as bit-shared
// 128-bit vectors (`SharedU128Bin` — 128 `mpstar::SharedBit`s).
//
// Iteration:
//   y_{t+1} = y_t · (2 − x' · y_t)
// where x' ∈ (0.5, 1] is the range-reduced input, y_0 = 3 − 2 · x'.
//
// The reciprocal 1/x is then y >> p, where p is the range-reduction shift.
//
// Range-reduction shift `p` is REVEALED. Justification: p = ⌈log₂ x⌉,
// i.e. the magnitude class of x. In MPSVS, x is a per-cell aggregate like
// n_valid_per_popkey which is DP-noised and revealed at open time anyway;
// leaking its magnitude class one round earlier changes nothing from a
// privacy standpoint. Documented explicitly in Rev 7 §17.7 malicious-upgrade
// register (already-known controlled leak).
//
// Cost per Goldschmidt call (6 Newton iters):
//   - Range-reduction: 64 secureLessThan on shared u64 for bit-length,
//     followed by one open of `p` — ~12K bit triples.
//   - Per iter: 2 bit-shared 128-bit mults × ~65K triples each = ~130K triples.
//   - 6 iters: ~780K triples.
//   - Total: ~800K bit triples per reciprocal.
//
// This is expensive but bounded — one Goldschmidt per (popkey, metric) cell.
// For a monthly release with 20 sectors × 4 core metrics = 80 reciprocals =
// ~64M triples. Tractable for offline batch generation.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsRatioBucket.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64Bin;

// ---------------------------------------------------------------------------
// SharedU128Bin — 128 bit-shared bits (extends SharedU64Bin conceptually).
// ---------------------------------------------------------------------------

struct SharedU128Bin {
    std::vector<SharedBit> bits;   // size = 128

    SharedU128Bin() : bits(128) {}
    explicit SharedU128Bin(uint32_t N) : bits(128, SharedBit(N)) {}

    // Reconstruct as __int128 (joint operation).
    __int128 reconstruct() const {
        __int128 v = 0;
        for (int i = 0; i < 128; ++i) {
            v |= static_cast<__int128>(bits[i].reconstruct() & 1) << i;
        }
        return v;
    }
};

// Share a plaintext fp value (__int128, encoded x · 2^f) across N parties.
SharedU128Bin shareU128Bin(uint32_t N, __int128 value, oc::PRNG& prng);

// Encode a plaintext u64 as SharedU128Bin fp (multiplies by 2^f internally).
SharedU128Bin shareFpFromU64(uint32_t N, uint64_t value, oc::PRNG& prng);

// ---------------------------------------------------------------------------
// Primitive: bit-shared 128-bit ripple-carry adder.
// Cost: 128 full-adders × 3 secureAnd = 384 bit triples.
// ---------------------------------------------------------------------------
SharedU128Bin bitAdd128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);

// Bit-shared 128-bit subtract (via two's-complement of y then add).
SharedU128Bin bitSub128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);

// ---------------------------------------------------------------------------
// Primitive: bit-shared 128-bit multiplication via shift-and-conditional-add.
// Cost: 128 rounds × (128 mux ANDs + 128-bit add = 384) = ~66K bit triples.
// Truncates high 128 bits (i.e., result is (x*y) mod 2^128).
// ---------------------------------------------------------------------------
SharedU128Bin bitMul128(const SharedU128Bin& x, const SharedU128Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);

// ---------------------------------------------------------------------------
// Fp multiply: (a · b) >> f  (128-bit intermediate).
// Uses bitMul128 then right-shifts f bits (relabel).
// ---------------------------------------------------------------------------
SharedU128Bin fpMulShared(const SharedU128Bin& a, const SharedU128Bin& b,
                            const std::vector<BeaverTripleBit>& triples,
                            size_t& tripleIndex);

// ---------------------------------------------------------------------------
// goldschmidtRecipWire — main entry.
// Input: x as a shared u64 (arithmetic-shared or bit-shared; here we take
// bit-shared u64 for simplicity — same shape as Phase 5 output). x must be
// in [1, N_max] with N_max public.
// Output: bit-shared 128-bit fp reciprocal.
// Range-reduction shift `p` is REVEALED (see header comment).
// ---------------------------------------------------------------------------
SharedU128Bin
goldschmidtRecipWire(const SharedU64Bin& x, uint64_t N_max,
                      int iterations,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& tripleIndex);

// Budget estimator (upper bound).
size_t goldschmidtWireTripleBudget(int iterations);

// Test helper: reconstruct a SharedU128Bin as a plain double (drops sign).
double fpToDoubleShared(const SharedU128Bin& v);

} // namespace mpsvs
} // namespace volePSI
