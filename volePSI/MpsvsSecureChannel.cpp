#include "MpsvsSecureChannel.h"

#include <sodium.h>

#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// ChannelIdentity
// ---------------------------------------------------------------------------

ChannelIdentity ChannelIdentity::generate(std::string party_name) {
    ensureSodiumInit();
    ChannelIdentity id;
    id.party_name = std::move(party_name);
    if (crypto_kx_keypair(id.public_key.data(), id.secret_key.data()) != 0)
        throw std::runtime_error("ChannelIdentity::generate: crypto_kx_keypair failed");
    return id;
}

void ChannelIdentity::zeroise() {
    sodium_memzero(secret_key.data(), secret_key.size());
}

// ---------------------------------------------------------------------------
// InMemoryPipe
// ---------------------------------------------------------------------------

struct InMemoryPipe::Impl {
    std::mutex m;
    std::condition_variable cv_a, cv_b;
    std::deque<uint8_t> a_to_b;   // side A writes here, side B reads
    std::deque<uint8_t> b_to_a;
    bool closed_a = false;
    bool closed_b = false;
};

namespace {

class PipeSide : public IByteTransport {
public:
    PipeSide(std::shared_ptr<InMemoryPipe::Impl> impl, bool is_a)
        : impl_(std::move(impl)), is_a_(is_a) {}

    void sendAll(const uint8_t* p, size_t n) override {
        std::unique_lock<std::mutex> lk(impl_->m);
        auto& q = is_a_ ? impl_->a_to_b : impl_->b_to_a;
        bool& peer_closed = is_a_ ? impl_->closed_b : impl_->closed_a;
        if (peer_closed) throw std::runtime_error("InMemoryPipe: peer closed");
        q.insert(q.end(), p, p + n);
        auto& peer_cv = is_a_ ? impl_->cv_b : impl_->cv_a;
        peer_cv.notify_all();
    }

    void recvAll(uint8_t* p, size_t n) override {
        std::unique_lock<std::mutex> lk(impl_->m);
        auto& q = is_a_ ? impl_->b_to_a : impl_->a_to_b;
        auto& my_cv = is_a_ ? impl_->cv_a : impl_->cv_b;
        bool& peer_closed = is_a_ ? impl_->closed_b : impl_->closed_a;
        while (q.size() < n) {
            if (peer_closed && q.empty())
                throw std::runtime_error("InMemoryPipe: peer closed while reading");
            my_cv.wait(lk);
        }
        for (size_t i = 0; i < n; ++i) { p[i] = q.front(); q.pop_front(); }
    }

    void close() override {
        std::unique_lock<std::mutex> lk(impl_->m);
        bool& mine = is_a_ ? impl_->closed_a : impl_->closed_b;
        mine = true;
        impl_->cv_a.notify_all();
        impl_->cv_b.notify_all();
    }

    ~PipeSide() override {
        try { close(); } catch (...) {}
    }

private:
    std::shared_ptr<InMemoryPipe::Impl> impl_;
    bool is_a_;
};

} // namespace

InMemoryPipe::InMemoryPipe() : impl_(std::make_shared<Impl>()) {}

std::unique_ptr<IByteTransport> InMemoryPipe::sideA() {
    return std::unique_ptr<IByteTransport>(new PipeSide(impl_, true));
}
std::unique_ptr<IByteTransport> InMemoryPipe::sideB() {
    return std::unique_ptr<IByteTransport>(new PipeSide(impl_, false));
}

// ---------------------------------------------------------------------------
// Role assignment
// ---------------------------------------------------------------------------

HandshakeRole assignRole(const std::string& my_name, const std::string& peer_name) {
    if (my_name == peer_name)
        throw std::runtime_error("assignRole: names must differ");
    return (my_name < peer_name) ? HandshakeRole::INITIATOR : HandshakeRole::RESPONDER;
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

namespace {

constexpr uint32_t kMaxFrameBytes = 32u * 1024u * 1024u;   // 32 MiB hard cap

void sendU32(IByteTransport& t, uint32_t v) {
    uint8_t buf[4] = {
        static_cast<uint8_t>((v >> 24) & 0xFF),
        static_cast<uint8_t>((v >> 16) & 0xFF),
        static_cast<uint8_t>((v >> 8)  & 0xFF),
        static_cast<uint8_t>((v)       & 0xFF),
    };
    t.sendAll(buf, 4);
}

uint32_t recvU32(IByteTransport& t) {
    uint8_t buf[4];
    t.recvAll(buf, 4);
    return (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16)
         | (uint32_t(buf[2]) << 8)  |  uint32_t(buf[3]);
}

} // namespace

// ---------------------------------------------------------------------------
// SodiumChannel
// ---------------------------------------------------------------------------

namespace {

class SodiumChannel : public ISecureChannel {
public:
    SodiumChannel(std::unique_ptr<IByteTransport> t, PeerIdentity peer)
        : transport_(std::move(t)), peer_(std::move(peer)) {}

    ~SodiumChannel() override {
        sodium_memzero(&tx_state_, sizeof(tx_state_));
        sodium_memzero(&rx_state_, sizeof(rx_state_));
        sodium_memzero(tx_key_.data(), tx_key_.size());
        sodium_memzero(rx_key_.data(), rx_key_.size());
    }

    // Initialise send/recv streams after handshake. `tx_key` and `rx_key`
    // are the two crypto_kx-derived session keys. Both sides send their
    // stream headers up-front on the wire so the peer can init_pull.
    void bootstrap(const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& tx_key,
                    const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& rx_key) {
        tx_key_ = tx_key;
        rx_key_ = rx_key;

        // Push side: emit header.
        std::array<uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> tx_hdr{};
        if (crypto_secretstream_xchacha20poly1305_init_push(
                &tx_state_, tx_hdr.data(), tx_key_.data()) != 0) {
            throw std::runtime_error("SodiumChannel: init_push failed");
        }
        transport_->sendAll(tx_hdr.data(), tx_hdr.size());

        // Pull side: read peer's header.
        std::array<uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> rx_hdr{};
        transport_->recvAll(rx_hdr.data(), rx_hdr.size());
        if (crypto_secretstream_xchacha20poly1305_init_pull(
                &rx_state_, rx_hdr.data(), rx_key_.data()) != 0) {
            throw std::runtime_error("SodiumChannel: init_pull failed");
        }
    }

    void sendFrame(const std::vector<uint8_t>& data) override {
        if (closed_) throw std::runtime_error("SodiumChannel: send on closed channel");
        if (data.size() > kMaxFrameBytes)
            throw std::runtime_error("SodiumChannel: frame too large");

        std::vector<uint8_t> ct(data.size()
                                  + crypto_secretstream_xchacha20poly1305_ABYTES);
        unsigned long long clen = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &tx_state_, ct.data(), &clen,
                data.data(), data.size(), nullptr, 0,
                crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
            throw std::runtime_error("SodiumChannel: push failed");
        }
        sendU32(*transport_, static_cast<uint32_t>(clen));
        transport_->sendAll(ct.data(), static_cast<size_t>(clen));
    }

    std::vector<uint8_t> recvFrame() override {
        if (closed_) throw std::runtime_error("SodiumChannel: recv on closed channel");

        uint32_t clen = recvU32(*transport_);
        if (clen == 0 ||
            clen > kMaxFrameBytes + crypto_secretstream_xchacha20poly1305_ABYTES) {
            throw std::runtime_error("SodiumChannel: bad frame length");
        }
        std::vector<uint8_t> ct(clen);
        transport_->recvAll(ct.data(), clen);

        std::vector<uint8_t> pt(clen);
        unsigned long long mlen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &rx_state_, pt.data(), &mlen, &tag,
                ct.data(), clen, nullptr, 0) != 0) {
            throw std::runtime_error("SodiumChannel: pull auth failed");
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            closed_ = true;
            throw std::runtime_error("SodiumChannel: peer closed (TAG_FINAL)");
        }
        pt.resize(static_cast<size_t>(mlen));
        return pt;
    }

    void closeClean() override {
        if (closed_) return;
        std::vector<uint8_t> empty;
        uint8_t ct[crypto_secretstream_xchacha20poly1305_ABYTES] = {0};
        unsigned long long clen = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &tx_state_, ct, &clen, empty.data(), 0, nullptr, 0,
                crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
            throw std::runtime_error("SodiumChannel: close push failed");
        }
        sendU32(*transport_, static_cast<uint32_t>(clen));
        transport_->sendAll(ct, static_cast<size_t>(clen));
        transport_->close();
        closed_ = true;
    }

    const PeerIdentity& peer() const override { return peer_; }

private:
    std::unique_ptr<IByteTransport> transport_;
    PeerIdentity peer_;
    std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> tx_key_{};
    std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx_key_{};
    crypto_secretstream_xchacha20poly1305_state tx_state_{};
    crypto_secretstream_xchacha20poly1305_state rx_state_{};
    bool closed_ = false;
};

} // namespace

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------
//
// Wire format (all length-prefixed for extensibility):
//   Both sides simultaneously send their long-term public key + party_name.
//   HELLO:  u32 name_len | name_bytes | 32 bytes X25519 public key
//
// After exchange, each side:
//   1. Verifies the received public key exactly matches expected_peer.public_key
//      (constant-time compare via libsodium).
//   2. Derives session keys via crypto_kx_client_session_keys (initiator)
//      or crypto_kx_server_session_keys (responder). Both sides feed the
//      same (client_pk, server_pk) so the crypto_kx derivation matches
//      even though the roles are asymmetric.
//   3. Constructs a SodiumChannel and calls bootstrap() to establish
//      the two secretstream directions.
//
// Note: the handshake is NOT resistant to KCI (key-compromise impersonation)
// or forward-secrecy loss on identity-key compromise. That is intentional
// for a mutually-authenticated intra-consortium deployment where the
// concern is unauthorized external parties, not post-hoc compromise of
// consortium members. Add ephemeral X25519 keys signed with the identity
// key if forward secrecy against a compromised MPSVS operator is needed.

std::unique_ptr<ISecureChannel> handshakeSodium(
    HandshakeRole role,
    const ChannelIdentity& my_identity,
    const PeerIdentity& expected_peer,
    std::unique_ptr<IByteTransport> transport) {

    ensureSodiumInit();

    // 1. Exchange HELLO.
    {
        uint32_t nlen = static_cast<uint32_t>(my_identity.party_name.size());
        sendU32(*transport, nlen);
        transport->sendAll(
            reinterpret_cast<const uint8_t*>(my_identity.party_name.data()), nlen);
        transport->sendAll(my_identity.public_key.data(),
                            my_identity.public_key.size());
    }
    std::string peer_name;
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> peer_pk{};
    {
        uint32_t nlen = recvU32(*transport);
        if (nlen > 256)
            throw std::runtime_error("handshake: peer name too long");
        peer_name.resize(nlen);
        transport->recvAll(reinterpret_cast<uint8_t*>(&peer_name[0]), nlen);
        transport->recvAll(peer_pk.data(), peer_pk.size());
    }

    // 2. Verify peer identity (CT compare of public key). The public key
    //    is the sole authentication root — name mismatch after PK match
    //    is a misconfiguration, not an MITM. We render a fingerprint
    //    (first 8 bytes hex) in the error for incident-response clarity.
    auto fp = [](const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& k) {
        char buf[17]; buf[16] = 0;
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 8; ++i) {
            buf[2*i]   = hex[k[i] >> 4];
            buf[2*i+1] = hex[k[i] & 0xF];
        }
        return std::string(buf);
    };
    if (sodium_memcmp(peer_pk.data(), expected_peer.public_key.data(),
                        peer_pk.size()) != 0) {
        throw std::runtime_error(
            "handshake: peer public key mismatch — MITM or misconfiguration "
            "(expected fp=" + fp(expected_peer.public_key) +
            " for '" + expected_peer.party_name +
            "', received fp=" + fp(peer_pk) +
            " claiming '" + peer_name + "')");
    }
    if (peer_name != expected_peer.party_name) {
        throw std::runtime_error(
            "handshake: peer name inconsistency (public key matches "
            "'" + expected_peer.party_name + "' but peer identifies as "
            "'" + peer_name + "') — likely misconfiguration");
    }

    // 3. Derive session keys.
    std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx_key{}, tx_key{};
    int rc;
    if (role == HandshakeRole::INITIATOR) {
        // "client": rx = server→client, tx = client→server
        rc = crypto_kx_client_session_keys(
            rx_key.data(), tx_key.data(),
            my_identity.public_key.data(),
            my_identity.secret_key.data(),
            peer_pk.data());
    } else {
        // "server": rx = client→server, tx = server→client
        rc = crypto_kx_server_session_keys(
            rx_key.data(), tx_key.data(),
            my_identity.public_key.data(),
            my_identity.secret_key.data(),
            peer_pk.data());
    }
    if (rc != 0) {
        throw std::runtime_error("handshake: crypto_kx session_keys failed");
    }

    // 4. Construct channel and bootstrap the secretstream directions.
    PeerIdentity peer;
    peer.public_key = peer_pk;
    peer.party_name = std::move(peer_name);
    auto ch = std::unique_ptr<SodiumChannel>(
        new SodiumChannel(std::move(transport), std::move(peer)));
    ch->bootstrap(tx_key, rx_key);

    sodium_memzero(rx_key.data(), rx_key.size());
    sodium_memzero(tx_key.data(), tx_key.size());

    return std::unique_ptr<ISecureChannel>(ch.release());
}

} // namespace mpsvs
} // namespace volePSI
