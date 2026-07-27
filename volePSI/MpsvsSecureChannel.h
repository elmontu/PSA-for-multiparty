#pragma once

// MPSVS Secure Channel — mutually-authenticated encrypted byte channel.
//
// Purpose: replaces the plaintext in-process `coproto::LocalAsyncSocket`
// used for the reference build with a real, authenticated, confidential
// channel between two remote machines.
//
// This implementation uses libsodium primitives directly (rather than
// pulling in OpenSSL / mbedTLS) because libsodium is already a project
// dependency and its authenticated encryption + key exchange primitives
// are misuse-resistant and audit-friendly:
//
//   - Handshake:  crypto_kx (X25519, deterministic session-key derivation
//                 from long-term identity keys + ephemeral randomness)
//                 with mutual identity assertion — each party binds its
//                 long-term X25519 identity to the session and verifies
//                 the peer's expected identity.
//   - Bulk data:  crypto_secretstream_xchacha20poly1305 in each direction
//                 (separate keys for send/recv). Provides:
//                   * per-frame authenticated encryption (XChaCha20-Poly1305)
//                   * automatic nonce management
//                   * built-in ordering + replay protection
//                   * TAG_FINAL sentinel for clean shutdown detection
//
// Threat model:
//   ✓ passive eavesdropper (recovers nothing beyond frame length + timing)
//   ✓ active MITM (rejected: mutual identity check on handshake)
//   ✓ message tampering (rejected: Poly1305 tag per frame)
//   ✓ replay (rejected: secretstream nonce state)
//   ✓ frame reordering (rejected: secretstream nonce state)
//   ~ traffic analysis (frame lengths visible)
//   ✗ physical side-channel adversary (out of scope)
//   ✗ post-compromise recovery (no forward secrecy beyond session)
//
// When regulators require X.509 PKI:
//   Replace the handshake with OpenSSL SSL_do_handshake in mTLS mode with
//   SSL_CTX_set_verify(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
//   and pinned CA. Bulk-data layer can stay libsodium, or migrate to
//   TLS 1.3 record layer. The `ISecureChannel` interface below is designed
//   so the substitution is a single-file swap.

#include "MpsvsProdHygiene.h"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Identity — party's long-term X25519 keypair
// ---------------------------------------------------------------------------

struct ChannelIdentity {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> public_key{};
    std::array<uint8_t, crypto_kx_SECRETKEYBYTES> secret_key{};
    std::string party_name;  // e.g. "MAS", "S1" — for audit logs only

    // Generate a fresh identity keypair. Secret is CSPRNG-sampled.
    static ChannelIdentity generate(std::string party_name);

    // Zero out the secret key in place (call before drop if reusing memory).
    void zeroise();
};

// Peer's advertised identity that we expect to authenticate against.
struct PeerIdentity {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> public_key{};
    std::string party_name;
};

// ---------------------------------------------------------------------------
// Abstract channel interface
// ---------------------------------------------------------------------------

// Byte-oriented send/recv. Both are blocking. Concrete implementations
// framing bytes over TCP, TLS, coproto socket, or in-memory queue.
class ISecureChannel {
public:
    virtual ~ISecureChannel() = default;

    // Send `data` as a single authenticated frame. Length is fixed
    // (32-bit big-endian prefix). Throws on IO failure.
    virtual void sendFrame(const std::vector<uint8_t>& data) = 0;

    // Receive one frame. Blocks. Throws on connection close mid-frame,
    // MAC failure, protocol violation, or peer sent TAG_FINAL.
    virtual std::vector<uint8_t> recvFrame() = 0;

    // Send a TAG_FINAL close signal and shut the channel down cleanly.
    // Subsequent send/recv calls throw.
    virtual void closeClean() = 0;

    // Get the authenticated peer identity (populated post-handshake).
    virtual const PeerIdentity& peer() const = 0;
};

// ---------------------------------------------------------------------------
// InMemoryTransport — the "pipe" the channel encrypts over.
// ---------------------------------------------------------------------------

// Abstracts the raw byte pipe. Real deployment uses a TCP socket wrapper;
// tests use an in-process queue pair. The channel handshake + framing +
// crypto sit above this — the transport is unaware.
class IByteTransport {
public:
    virtual ~IByteTransport() = default;
    virtual void sendAll(const uint8_t* p, size_t n) = 0;
    virtual void recvAll(uint8_t* p, size_t n) = 0;
    virtual void close() = 0;
};

// Two coupled in-memory transports (for tests). Each side reads what the
// other wrote. Thread-safe (backed by a mutex + condvar).
class InMemoryPipe {
public:
    struct Impl;                                    // pimpl, visible to .cpp helpers
    InMemoryPipe();
    std::unique_ptr<IByteTransport> sideA();
    std::unique_ptr<IByteTransport> sideB();

private:
    std::shared_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Libsodium-backed secure channel
// ---------------------------------------------------------------------------

// Handshake role: initiator or responder. Both parties must agree who is
// which. Convention: initiator = the party with the lexicographically
// smaller party_name (deterministic tie-breaker).
enum class HandshakeRole { INITIATOR, RESPONDER };

// Perform an authenticated handshake over `transport`, deriving two session
// keys (send + recv) via crypto_kx. Verifies the peer's long-term X25519
// public key matches `expected_peer.public_key`. Returns an ISecureChannel
// ready for send/recv.
//
// Throws on:
//   - transport IO failure
//   - peer identity mismatch (MITM detection)
//   - handshake protocol violation
std::unique_ptr<ISecureChannel> handshakeSodium(
    HandshakeRole role,
    const ChannelIdentity& my_identity,
    const PeerIdentity& expected_peer,
    std::unique_ptr<IByteTransport> transport);

// ---------------------------------------------------------------------------
// Handshake helper — deterministic role assignment
// ---------------------------------------------------------------------------

// Returns HandshakeRole::INITIATOR if my_name < peer_name lexicographically,
// else RESPONDER. Used to break the "who talks first" symmetry without an
// out-of-band coordinator.
HandshakeRole assignRole(const std::string& my_name, const std::string& peer_name);

} // namespace mpsvs
} // namespace volePSI
