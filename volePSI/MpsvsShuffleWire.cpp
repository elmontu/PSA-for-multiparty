#include "MpsvsShuffleWire.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::freshOpenings;
using mpstar::pedersenCommitVector;
using mpstar::shuffleProveBg;
using mpstar::shuffleVerifyBg;

ShuffleTranscript shuffleAndProve(const std::vector<uint64_t>& keys,
                                    const std::vector<int>& permutation) {
    if (keys.size() != permutation.size())
        throw std::invalid_argument("shuffleAndProve: size mismatch");
    const size_t n = keys.size();

    ShuffleTranscript t;
    // Convert u64 keys to R255 scalars.
    for (uint64_t k : keys) t.orig_messages.push_back(R255Scalar::fromU64(k));
    t.permutation = permutation;

    // Apply permutation to get shuffled messages.
    t.shuf_messages.resize(n);
    for (size_t i = 0; i < n; ++i)
        t.shuf_messages[i] = t.orig_messages[permutation[i]];

    // Fresh openings for both sides.
    t.openings_orig = freshOpenings(n);
    t.openings_shuf = freshOpenings(n);

    // Compute Pedersen commitments.
    t.origC = pedersenCommitVector(t.orig_messages, t.openings_orig);
    t.shufC = pedersenCommitVector(t.shuf_messages, t.openings_shuf);

    // Generate the shuffle proof.
    t.proof = shuffleProveBg(t.orig_messages, t.openings_orig, t.openings_shuf,
                               permutation, t.origC, t.shufC);
    return t;
}

bool verifyShuffleTranscript(const ShuffleTranscript& t) {
    return shuffleVerifyBg(t.proof, t.origC, t.shufC);
}

// ---------------------------------------------------------------------------
// Malicious simulators
// ---------------------------------------------------------------------------

ShuffleTranscript maliciousSubstitute(const ShuffleTranscript& honest,
                                        int shuf_idx, uint64_t new_key) {
    ShuffleTranscript t = honest;
    // Replace shuffled message at position shuf_idx with a different value.
    t.shuf_messages[shuf_idx] = R255Scalar::fromU64(new_key);
    // Recompute commitment for that position (with a fresh opening).
    auto new_openings = freshOpenings(1);
    t.openings_shuf[shuf_idx] = new_openings[0];
    t.shufC = pedersenCommitVector(t.shuf_messages, t.openings_shuf);
    // Attempt to re-prove with the tampered messages/commitments — but the
    // prover doesn't have a valid permutation to (m + substitute), so its
    // proof will be inconsistent with the sum/product checks in verify.
    // We reprove naively (from the substituted state):
    t.proof = shuffleProveBg(t.orig_messages, t.openings_orig, t.openings_shuf,
                               t.permutation, t.origC, t.shufC);
    return t;
}

ShuffleTranscript maliciousDrop(const ShuffleTranscript& honest, int shuf_idx) {
    ShuffleTranscript t = honest;
    // Drop shuffled message at shuf_idx (leaves size mismatch, which
    // shuffleVerifyBg's internal length check should catch).
    t.shuf_messages.erase(t.shuf_messages.begin() + shuf_idx);
    t.openings_shuf.erase(t.openings_shuf.begin() + shuf_idx);
    t.shufC.erase(t.shufC.begin() + shuf_idx);
    return t;
}

ShuffleTranscript maliciousInsert(const ShuffleTranscript& honest,
                                    uint64_t new_key) {
    ShuffleTranscript t = honest;
    t.shuf_messages.push_back(R255Scalar::fromU64(new_key));
    auto new_openings = freshOpenings(1);
    t.openings_shuf.push_back(new_openings[0]);
    t.shufC = pedersenCommitVector(t.shuf_messages, t.openings_shuf);
    return t;
}

} // namespace mpsvs
} // namespace volePSI
