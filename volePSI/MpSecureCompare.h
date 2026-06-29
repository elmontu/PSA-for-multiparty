#pragma once

// Secure 64-bit comparison circuit on XOR-shared bits (R34d).
//
// Design: each 64-bit value is stored as 64 independent SharedBits (one
// per bit position). This sidesteps the arithmetic-to-binary conversion
// that would be required if values were arithmetic-shared (Toft, SPDZ
// bit-decomposition). The trade-off is more storage per value, but the
// LT circuit becomes a clean 64-iteration boolean network.
//
// Each comparison consumes O(64) Beaver triple bits via secureAnd.
// For a bitonic sort of n elements: O(n · log² n) comparisons.
//
// Reference for the bit-by-bit LT circuit: standard MPC textbook
// construction; see Damgård-Nielsen "Secure Multiparty Computation and
// Secret Sharing" §10.2.

#include "MpSecretShare.h"
#include "MpBeaverTriple.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// 64-bit value as 64 XOR-shared bits. bits[0] is the LSB, bits[63] is the
// MSB. All bits share the same N-party shape.
struct SharedU64Bin {
    std::vector<SharedBit> bits;   // size = 64

    SharedU64Bin() : bits(64) {}

    uint32_t N() const {
        return bits.empty() ? 0 : bits[0].N();
    }

    // Reconstruct the 64-bit value (joint operation, leaks the value).
    uint64_t reconstruct() const {
        uint64_t v = 0;
        for (uint32_t i = 0; i < 64; ++i) {
            v |= (uint64_t(bits[i].reconstruct() & 1) << i);
        }
        return v;
    }
};

// Bit-decompose `value` and share each bit additively over Z_2.
SharedU64Bin shareU64Bin(uint32_t N, uint64_t value, oc::PRNG& prng);

// Secure unsigned less-than: returns a SharedBit b such that
// b.reconstruct() = 1 iff x.reconstruct() < y.reconstruct() (unsigned 64-bit).
//
// Consumes `tripleIndex` Beaver triple bits from `triples` starting at
// the given index. Returns the consumed count via &tripleIndex so the
// caller can step through a pre-generated triple bag. Roughly 192 triples
// per call (3 ANDs per bit × 64 bits).
SharedBit secureLessThan(const SharedU64Bin& x,
                         const SharedU64Bin& y,
                         const std::vector<BeaverTripleBit>& triples,
                         size_t& tripleIndex);

// Returns the exact number of Beaver triple bits secureLessThan consumes.
size_t secureLessThanTripleCost();

// Secure equality test: returns a SharedBit b with
// b.reconstruct() = 1 iff x.reconstruct() == y.reconstruct(). Used for
// Phase 4 (window detection).
//
// Implemented as ~64 secureAnd calls (one per bit XOR, then 6 levels of
// pairwise AND-tree). Returns triple consumption via tripleIndex.
SharedBit secureEqual(const SharedU64Bin& x,
                      const SharedU64Bin& y,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& tripleIndex);

size_t secureEqualTripleCost();

} // namespace mpstar
} // namespace volePSI
