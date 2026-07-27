#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace volePSI {
namespace mpstar {

// Information-theoretic MAC over GF(2^128) for the malicious-secure cascade
// (T1 production; see docs/DESIGN.md).
//
// Tag invariant: for a share `s` and MAC key `α`, `tag = α · s` (multiply
// in GF(2^128) via PCLMUL). Tags are linear in `s`, so they survive XOR
// and permutation operations without any extra protocol round.
//
// Verification: at protocol end, all parties reveal their `α_k`. Each
// party recomputes `α · s` for its claimed `s` and confirms against the
// tags it received. Mismatch ⇒ abort with attribution (which round + which
// column the tampering occurred).

// An "authenticated share" pairs a data vector with a tag vector.
// Invariant maintained throughout the protocol:
//   for all i:  authParty1.tag[i] ⊕ authParty2.tag[i]
//                 == α · (authParty1.data[i] ⊕ authParty2.data[i])
// where α is the per-round MAC key shared between the two parties.
struct AuthShare {
    std::vector<oc::block> data;
    std::vector<oc::block> tag;

    AuthShare() = default;
    AuthShare(std::vector<oc::block> d, std::vector<oc::block> t)
        : data(std::move(d)), tag(std::move(t))
    {
        if (data.size() != tag.size())
            throw std::runtime_error("AuthShare: data and tag sizes differ");
    }

    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }
};

// XOR two authenticated shares element-wise. The MAC homomorphism holds:
//   α · (a.data ⊕ b.data) = α · a.data ⊕ α · b.data = a.tag ⊕ b.tag.
AuthShare xorAuth(const AuthShare& a, const AuthShare& b);

// XOR a known constant (a vector of blocks, public) into an authenticated
// share. The tag must be updated: `new_tag = old_tag ⊕ α · c[i]`. The
// caller must supply `α` since it's their party's secret.
AuthShare xorConstAuth(const AuthShare& a,
                       const std::vector<oc::block>& c,
                       const oc::block& alpha);

// Apply a permutation `dest` to both data and tag in lockstep. After the
// shuffle: `new_data[i] = old_data[dest[i]]`, `new_tag[i] = old_tag[dest[i]]`.
// The MAC homomorphism continues to hold trivially.
AuthShare permuteAuth(const AuthShare& a, const std::vector<int>& dest);

// Locally compute the MAC tag of a plaintext vector under `α`.
//   out[i] = α · plain[i].
std::vector<oc::block> tagVector(const oc::block& alpha,
                                 const std::vector<oc::block>& plain);

// Two-party random sharing of `plain` with valid MAC tags under `α`:
//   share1.data ⊕ share2.data = plain
//   share1.tag  ⊕ share2.tag  = α · plain
// Uses caller-supplied PRNG for the randomness.
std::pair<AuthShare, AuthShare> randomAuthShare(
    const std::vector<oc::block>& plain,
    const oc::block& alpha,
    oc::PRNG& prng);

// Batched verification: given a claimed plain vector and two parties'
// authenticated shares, verify that the MAC invariant holds for the joint
// reconstruction. Returns true iff:
//   for all i: tag1[i] ⊕ tag2[i] == α · (data1[i] ⊕ data2[i]).
bool verifyAuthShares(const AuthShare& a1, const AuthShare& a2,
                      const oc::block& alpha);

// Batched random-linear-combination check (Chida et al. CRYPTO'18 §4):
// instead of checking C separate equations, fold them into one by random
// linear combination. Sound up to 2^{-128} per check; reduces verifier
// communication / work from O(C) to O(1) in the dominant secret material.
//
// Returns true iff `<challenge, a1.tag ⊕ a2.tag> == α · <challenge, a1.data ⊕ a2.data>`
// where <.,.> is the dot product in GF(2^128).
bool verifyAuthSharesBatched(const AuthShare& a1, const AuthShare& a2,
                             const oc::block& alpha,
                             const std::vector<oc::block>& challenge);

} // namespace mpstar
} // namespace volePSI
