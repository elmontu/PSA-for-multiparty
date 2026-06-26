#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include "cryptoTools/Common/Defines.h"

namespace volePSI {
namespace mpstar {

// Serialize a vector of oc::block into a byte vector.
std::vector<uint8_t> serializeBlocks(const std::vector<oc::block>& blocks);

// Deserialize count blocks from a byte vector.
std::vector<oc::block> deserializeBlocks(const std::vector<uint8_t>& data, size_t count);

// AEAD encrypt with a random 24-byte nonce. Output layout: nonce || ciphertext.
std::vector<uint8_t> aeadEncrypt(const std::vector<uint8_t>& plain,
                                 const std::array<uint8_t, 32>& key);

// AEAD decrypt. Expects input layout: nonce || ciphertext.
std::vector<uint8_t> aeadDecrypt(const std::vector<uint8_t>& ct,
                                 const std::array<uint8_t, 32>& key);

// Derive a session-bound 32-byte key from a long-term base key, a session
// identifier (e.g. random 32 bytes picked by SP at the top of each MPSA
// invocation), and a short purpose tag for domain separation
// (e.g. "sp_session", "pair_session"). Uses RandomOracle as the KDF.
//
// This is the replay-protection layer: ciphertext from session A cannot
// be opened in session B because the keys derive differently.
std::array<uint8_t, 32> deriveSessionKey(
    const std::array<uint8_t, 32>& baseKey,
    const std::array<uint8_t, 32>& sessionId,
    const std::string& purpose);

// Hiding + binding commitment to a vector of blocks. Output is a 32-byte
// digest: commit = H(message || nonce). The caller chooses a random nonce
// (16 bytes is sufficient for binding under SHA-2 / Blake2's collision
// resistance). To open: re-supply (message, nonce); the verifier recomputes
// and compares.
//
// Used for malicious-secure Phase 0: each sender broadcasts a commitment to
// its r_i BEFORE opening to sender 0. Other senders hold the commitment as
// a check value; sender 0 verifies on receipt.
std::array<uint8_t, 32> commit(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 16>& nonce);

// Verify a commitment opens correctly. Returns true iff
// commit(message, nonce) == expected. Constant-time comparison.
bool verifyCommit(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 16>& nonce,
    const std::array<uint8_t, 32>& expected);

} // namespace mpstar
} // namespace volePSI
