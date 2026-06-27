#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpstar {

// Abstract Key-Encapsulation Mechanism (KEM) interface for use in the
// hybrid post-quantum handshake. Mirrors the NIST KEM API:
//   - keypair() generates (pk, sk)
//   - encap(pk) → (ct, ss)
//   - decap(ct, sk) → ss
//
// Three concrete implementations are envisioned:
//   1. StubKem (this round, here): emits deterministic zeroes. NOT secure;
//      lets the protocol structure compile and run end-to-end while a real
//      PQC library is being integrated.
//   2. MlKemKem: ML-KEM (Kyber-768) via liboqs or pqcrystals/kyber.
//      Round 18 ships only the design + integration spec.
//   3. (future) HybridKem wrapping both X25519 and ML-KEM with a KDF.

// Public/secret/ciphertext/shared-secret sizes are per-implementation.
// We expose them as opaque byte vectors and let the KDF combiner produce
// a fixed-size session key downstream.

struct Kem {
    virtual ~Kem() = default;

    virtual std::string name() const = 0;

    // Sizes (fixed per concrete instance).
    virtual size_t publicKeyBytes()    const = 0;
    virtual size_t secretKeyBytes()    const = 0;
    virtual size_t ciphertextBytes()   const = 0;
    virtual size_t sharedSecretBytes() const = 0;

    // Generate a fresh keypair.
    virtual void keypair(std::vector<uint8_t>& pk,
                         std::vector<uint8_t>& sk) const = 0;

    // Encapsulate: given a peer's pk, produce a ciphertext + the shared
    // secret derived locally.
    virtual void encap(const std::vector<uint8_t>& peer_pk,
                       std::vector<uint8_t>& ct,
                       std::vector<uint8_t>& ss) const = 0;

    // Decapsulate: given a peer's ciphertext and our sk, recover the
    // shared secret. Should produce the same ss the peer computed on encap.
    virtual void decap(const std::vector<uint8_t>& ct,
                       const std::vector<uint8_t>& sk,
                       std::vector<uint8_t>& ss) const = 0;
};

// Stub implementation. Outputs all-zero bytes for every field. Provides
// the right SHAPE for the hybrid handshake to compile and run but
// CONTRIBUTES NO REAL SECURITY. Replace with a real KEM in production.
//
// Marked plainly so tests / audits can detect when it's in use.
class StubKem : public Kem {
public:
    static constexpr size_t kPkBytes = 1184;   // matches ML-KEM-768 public key
    static constexpr size_t kSkBytes = 2400;   // matches ML-KEM-768 secret key
    static constexpr size_t kCtBytes = 1088;   // matches ML-KEM-768 ciphertext
    static constexpr size_t kSsBytes = 32;     // matches ML-KEM-768 shared secret

    std::string name() const override { return "StubKem (NOT SECURE — placeholder)"; }
    size_t publicKeyBytes()    const override { return kPkBytes; }
    size_t secretKeyBytes()    const override { return kSkBytes; }
    size_t ciphertextBytes()   const override { return kCtBytes; }
    size_t sharedSecretBytes() const override { return kSsBytes; }

    void keypair(std::vector<uint8_t>& pk,
                 std::vector<uint8_t>& sk) const override;

    void encap(const std::vector<uint8_t>& peer_pk,
               std::vector<uint8_t>& ct,
               std::vector<uint8_t>& ss) const override;

    void decap(const std::vector<uint8_t>& ct,
               const std::vector<uint8_t>& sk,
               std::vector<uint8_t>& ss) const override;
};

} // namespace mpstar
} // namespace volePSI
