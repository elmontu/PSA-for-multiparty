#pragma once

// Additive secret sharing over Z_2^64, simulated in-memory for N parties.
// R34a deliverable — foundation for the full MPC variant of the private
// join protocol. See docs/PRIVATE_JOIN_DESIGN.md.
//
// Threat model in this in-memory simulation: each "party" is an integer
// index in [0, N); a SharedValue<T> stores party-indexed shares. NO
// PARTY can read another party's share through this API — the only ways
// to materialize a plaintext value are (a) reconstruct() (joint
// computation by all parties revealing their shares) or (b) constants
// embedded at sharing time. This is the structural invariant the tests
// exercise.
//
// Algebra: shares sum to the plaintext value mod 2^64.
//   x = Σ_i share_i (mod 2^64)
// Local operations:
//   - share + share  (party-wise add)
//   - share - share  (party-wise sub)
//   - share + const  (party 0 absorbs the constant; others unchanged)
//   - share * const  (each party multiplies its share by the constant)
// Joint operations:
//   - reconstruct() (sum all shares)
// Multiplication of two SHARED values is NOT local — see MpBeaverTriple.h.

#include "cryptoTools/Crypto/PRNG.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpstar {

// Additive share of a 64-bit value across N parties. shares[i] is held
// only by party i in the protocol — but the simulation stores them
// together in the same struct for test convenience.
struct SharedU64 {
    std::vector<uint64_t> shares;   // size = N

    SharedU64() = default;
    explicit SharedU64(uint32_t N) : shares(N, 0) {}

    uint32_t N() const { return static_cast<uint32_t>(shares.size()); }

    // Joint reconstruction. In the real wire protocol, this is a round
    // where each party broadcasts its share and the receiver sums.
    uint64_t reconstruct() const {
        uint64_t out = 0;
        for (uint64_t s : shares) out += s;  // mod 2^64 via wrap
        return out;
    }
};

// Fresh additive sharing of a known plaintext. Party 0 gets the
// "remainder" share so the sum equals the plaintext exactly.
SharedU64 shareU64(uint32_t N, uint64_t value, oc::PRNG& prng);

// Element-wise add: c.shares[i] = a.shares[i] + b.shares[i]. Local on
// each party.
SharedU64 addShared(const SharedU64& a, const SharedU64& b);

// Element-wise sub: c.shares[i] = a.shares[i] - b.shares[i].
SharedU64 subShared(const SharedU64& a, const SharedU64& b);

// Add a public constant to a share: only party 0 absorbs the constant.
// (Equivalent: a.shares[0] += c on party 0; other parties unchanged.)
SharedU64 addConst(const SharedU64& a, uint64_t c);

// Multiply a share by a public constant (scalar multiplication is local).
SharedU64 mulConst(const SharedU64& a, uint64_t c);

// Per-bit share view: each bit position of a SharedU64 is a binary
// additive share (mod 2). Used by secure comparison (R34d) which needs
// bit-wise reasoning.
//
// Bit shares are stored as uint8_t but only the low bit is meaningful.
struct SharedBit {
    std::vector<uint8_t> shares;  // size = N, each in {0, 1}

    SharedBit() = default;
    explicit SharedBit(uint32_t N) : shares(N, 0) {}

    uint32_t N() const { return static_cast<uint32_t>(shares.size()); }

    // Joint reconstruction (XOR of all party shares).
    uint8_t reconstruct() const {
        uint8_t out = 0;
        for (uint8_t s : shares) out ^= s;
        return out & 1;
    }
};

// Fresh additive sharing of a known plaintext bit.
SharedBit shareBit(uint32_t N, uint8_t value, oc::PRNG& prng);

// XOR of two shared bits: c.shares[i] = a.shares[i] ^ b.shares[i].
SharedBit xorShared(const SharedBit& a, const SharedBit& b);

// XOR a shared bit with a public bit.
SharedBit xorConst(const SharedBit& a, uint8_t c);

} // namespace mpstar
} // namespace volePSI
