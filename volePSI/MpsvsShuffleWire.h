#pragma once

// MPSVS Phase 17.4 — Bayer-Groth shuffle NIZK integration.
//
// Wraps the existing MpShuffleNizkBg module for the MPSVS Phase 4 CGP shuffle
// context. When S1 shuffles the aligned union table before handing off to S2
// (Rev 7 §5.5 ComposedShuffle), a malicious S1 could substitute, drop, or
// insert rows. The BG shuffle NIZK proves the shuffle is a valid permutation
// of the original committed multiset.
//
// Protocol:
//   Prover (S1):
//     1. Compute Pedersen commitments C_i for each original row's key.
//     2. Apply a permutation π; compute openings for shuffled commitments C'_i.
//     3. Run shuffleProveBg(...) — produces ShuffleProofBg.
//     4. Broadcast (C, C', proof) to S2 (or to a verifier/auditor).
//
//   Verifier (S2 or auditor):
//     1. Receive (C, C', proof).
//     2. Run shuffleVerifyBg(proof, C, C') — returns TRUE if valid shuffle.
//
// Attacks caught:
//   - Substitution: replace a row's key with a different value.
//   - Deletion: drop a row from the shuffled output.
//   - Insertion: add a fake row not present in the original.
//   - Duplication: duplicate a row (also caught since multiset changes).
//
// Cost: 2n Pedersen commitments + prover work O(n log n) + verify O(n).

#include "MpPedersen.h"
#include "MpRistretto.h"
#include "MpShuffleNizkBg.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::PedersenCommitment;
using mpstar::R255Scalar;
using mpstar::ShuffleProofBg;

// One "row" in the shuffle context — just the key (as u64, packed into R255).
// In production, this would be extended to (bin, key, memb) as a hashed
// single scalar (or via vector commitments for multi-field messages).
struct ShuffleTranscript {
    std::vector<PedersenCommitment> origC;    // commitments to orig msgs
    std::vector<PedersenCommitment> shufC;    // commitments to shuffled msgs
    ShuffleProofBg proof;
    // For test-only reconstruction:
    std::vector<R255Scalar> orig_messages;
    std::vector<R255Scalar> shuf_messages;
    std::vector<int> permutation;
    std::vector<R255Scalar> openings_orig;
    std::vector<R255Scalar> openings_shuf;
};

// S1 (prover): given u64 keys, shuffle and produce a ShuffleTranscript.
ShuffleTranscript shuffleAndProve(const std::vector<uint64_t>& keys,
                                    const std::vector<int>& permutation);

// S2 (verifier): check the transcript. Returns TRUE if valid.
bool verifyShuffleTranscript(const ShuffleTranscript& t);

// Test-only simulators of malicious S1 deviations:
//   - Substitute one shuffled message with a different value.
//   - Drop one message from the shuffled output.
//   - Insert an extra message not in the original.
ShuffleTranscript maliciousSubstitute(const ShuffleTranscript& honest,
                                        int shuf_idx, uint64_t new_key);
ShuffleTranscript maliciousDrop(const ShuffleTranscript& honest, int shuf_idx);
ShuffleTranscript maliciousInsert(const ShuffleTranscript& honest,
                                    uint64_t new_key);

} // namespace mpsvs
} // namespace volePSI
