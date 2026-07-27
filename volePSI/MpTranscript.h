#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpstar {

// Append-only hash transcript for non-repudiation (T11 / CCoP 2.0 audit).
//
// Each party maintains an MpTranscript locally. Every observable protocol
// message (send + recv, in order) is appended via `record(...)`. At
// protocol end the transcript digest is signed under the party's long-term
// Ed25519 keypair (signEd25519). Any other party (or an external auditor)
// verifying the signed digest against its own transcript can attribute
// who said what.
//
// This is the lightweight Path C "identifiable abort" from
// docs/HISTORY.md: doesn't prevent attacks (the
// info-theoretic MAC layer does that) but lets a post-protocol observer
// prove who deviated.
class MpTranscript {
public:
    MpTranscript();

    // Append a labeled event. Label is a short ASCII tag describing the
    // step (e.g., "send.session_id", "recv.commit.j=2"). Data is the
    // serialized message bytes (or a hash for very large messages).
    void record(const std::string& label,
                const std::vector<uint8_t>& data);

    // Append a record where the data is just N bytes from a raw pointer.
    void recordSpan(const std::string& label,
                    const uint8_t* data, size_t len);

    // Finalize and return the 32-byte transcript digest. Idempotent;
    // calling multiple times returns the same digest.
    std::array<uint8_t, 32> digest() const;

    // Sign the current digest with an Ed25519 secret key (64 bytes,
    // libsodium format). Returns a 64-byte signature.
    std::array<uint8_t, 64> sign(
        const std::array<uint8_t, 64>& ed25519_sk) const;

    // Verify a signature against the current digest using a peer's
    // Ed25519 public key (32 bytes).
    static bool verify(
        const std::array<uint8_t, 32>& digest_value,
        const std::array<uint8_t, 64>& signature,
        const std::array<uint8_t, 32>& ed25519_pk);

private:
    // Internal accumulator state (hash chain).
    std::vector<uint8_t> mAcc;
};

// Generate a fresh Ed25519 keypair (libsodium-compatible: 32B pk, 64B sk).
void ed25519Keypair(std::array<uint8_t, 32>& pk,
                    std::array<uint8_t, 64>& sk);

} // namespace mpstar
} // namespace volePSI
