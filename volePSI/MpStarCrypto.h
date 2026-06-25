#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include "cryptoTools/Common/block.h"

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

} // namespace mpstar
} // namespace volePSI
