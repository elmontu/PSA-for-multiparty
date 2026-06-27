#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "coproto/coproto.h"
#include "macoro/task.h"

namespace volePSI {

namespace mpstar { struct Kem; }

// Post-quantum hybrid SP↔sender handshake. Combines the classical X25519
// ECDH (preserved from MpSpHandshake) with a swappable Kem so the session
// key is secure as long as AT LEAST ONE of the two primitives remains
// secure (defence in depth against future cryptanalysis or PQC attacks).
//
// Round 18 ships with a StubKem (returns zeros, NOT SECURE) so the
// protocol structure compiles + runs end-to-end. Once a real KEM
// (ML-KEM / Kyber-768 via liboqs or pqcrystals) is wired in, the
// caller just swaps the Kem instance and gets hybrid security.
//
// Wire format on each socket (in order):
//   1. SP → sender:  x25519_pk_sp (32 bytes)
//   2. SP → sender:  kem_pk_sp (kem.publicKeyBytes())
//   3. sender → SP:  x25519_pk_sender (32 bytes)
//   4. sender → SP:  kem_ct (kem.ciphertextBytes())   — sender encaps to SP's pk
//
// SP recvs kem_ct from sender, decaps with its own sk → kem_ss.
// Sender computed kem_ss locally during encap.
// Both derive the final session key via:
//   session_key = KDF(x25519_ss || kem_ss || "mphybrid.v1" || senderIdx_BE)
class MpHybridHandshake {
public:
    // SP side. Conducts the hybrid handshake against every sender in
    // parallel. Returns one 32-byte symmetric session key per sender.
    static macoro::task<std::vector<std::array<uint8_t, 32>>> runSp(
        std::vector<coproto::Socket>& senderSocks,
        const mpstar::Kem& kem);

    // Sender side. Returns one 32-byte symmetric session key for SP.
    static macoro::task<std::array<uint8_t, 32>> runSender(
        coproto::Socket& spSock,
        uint32_t selfIdx,
        const mpstar::Kem& kem);
};

} // namespace volePSI
