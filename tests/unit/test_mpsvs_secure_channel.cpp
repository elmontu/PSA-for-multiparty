// MPSVS SecureChannel tests: handshake success, MITM rejection, frame
// integrity, tampering detection, clean shutdown.

#include "volePSI/MpsvsSecureChannel.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <atomic>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Concurrent handshake helper. Runs both parties in parallel threads,
// returns their resulting channels (or captures exceptions).
struct HandshakeResult {
    std::unique_ptr<ISecureChannel> a;
    std::unique_ptr<ISecureChannel> b;
    std::exception_ptr err_a, err_b;
};

static HandshakeResult doHandshake(
    const ChannelIdentity& id_a,
    const ChannelIdentity& id_b,
    const PeerIdentity& expected_by_a,
    const PeerIdentity& expected_by_b) {

    InMemoryPipe pipe;
    auto ta = pipe.sideA();
    auto tb = pipe.sideB();

    HandshakeResult r;
    HandshakeRole role_a = assignRole(id_a.party_name, id_b.party_name);
    HandshakeRole role_b = (role_a == HandshakeRole::INITIATOR)
                            ? HandshakeRole::RESPONDER
                            : HandshakeRole::INITIATOR;

    std::thread th_a([&]{
        try {
            r.a = handshakeSodium(role_a, id_a, expected_by_a, std::move(ta));
        } catch (...) { r.err_a = std::current_exception(); }
    });
    std::thread th_b([&]{
        try {
            r.b = handshakeSodium(role_b, id_b, expected_by_b, std::move(tb));
        } catch (...) { r.err_b = std::current_exception(); }
    });
    th_a.join();
    th_b.join();
    return r;
}

static PeerIdentity toPeer(const ChannelIdentity& id) {
    PeerIdentity p;
    p.public_key = id.public_key;
    p.party_name = id.party_name;
    return p;
}

// ==========================================================================
// C1 — Honest handshake succeeds
// ==========================================================================

static void test_honest_handshake_and_data_transfer() {
    std::printf("--- C1: honest 2-party handshake succeeds and data transfers ---\n");
    auto id_a = ChannelIdentity::generate("MAS");
    auto id_b = ChannelIdentity::generate("S1");
    auto r = doHandshake(id_a, id_b, toPeer(id_b), toPeer(id_a));
    CHECK(!r.err_a && !r.err_b, "C1a: no handshake exceptions");
    CHECK(r.a && r.b, "C1b: both channels open");
    if (!r.a || !r.b) return;

    // Data transfer both ways, multiple frames.
    std::thread sender([&]{
        r.a->sendFrame({0x01, 0x02, 0x03});
        r.a->sendFrame(std::vector<uint8_t>(1024, 0xAB));
        r.a->sendFrame({});
    });
    auto f1 = r.b->recvFrame();
    auto f2 = r.b->recvFrame();
    auto f3 = r.b->recvFrame();
    sender.join();
    CHECK(f1 == std::vector<uint8_t>({0x01, 0x02, 0x03}),
          "C1c: 3-byte frame roundtrip");
    CHECK(f2.size() == 1024 && f2[0] == 0xAB && f2[1023] == 0xAB,
          "C1d: 1KB frame roundtrip");
    CHECK(f3.empty(), "C1e: empty frame supported");

    r.a->closeClean();
}

// ==========================================================================
// C2 — MITM (attacker swaps public key) rejected
// ==========================================================================

static void test_mitm_wrong_pk_rejected() {
    std::printf("--- C2: peer with wrong public key rejected ---\n");
    auto id_mas = ChannelIdentity::generate("MAS");
    auto id_s1_real = ChannelIdentity::generate("S1");
    auto id_s1_fake = ChannelIdentity::generate("S1");
    // MAS expects id_s1_real, but the wire connects to id_s1_fake.
    auto r = doHandshake(id_mas, id_s1_fake, toPeer(id_s1_real), toPeer(id_mas));
    CHECK(!r.a && r.err_a, "C2a: MAS's handshake threw");
    // S1_fake's own view: it thinks it should see id_mas — that succeeds
    // on its side because MAS's key matches. The mismatch is unilateral.
    CHECK(r.err_a != nullptr, "C2b: MAS detected the mismatch");
}

// ==========================================================================
// C3 — Name mismatch (wrong party) rejected
// ==========================================================================

static void test_name_mismatch_rejected() {
    std::printf("--- C3: peer name mismatch rejected ---\n");
    auto id_a = ChannelIdentity::generate("MAS");
    auto id_b = ChannelIdentity::generate("S1");
    // MAS expects to talk to "DOS" (wrong name), but wire has "S1".
    PeerIdentity wrong_expected = toPeer(id_b);
    wrong_expected.party_name = "DOS";   // key correct, name wrong
    auto r = doHandshake(id_a, id_b, wrong_expected, toPeer(id_a));
    CHECK(!r.a && r.err_a, "C3: MAS's handshake threw on name mismatch");
}

// ==========================================================================
// C4 — Tampering on the wire detected
// ==========================================================================

// A transport wrapper that flips a byte in every frame we send.
namespace {
class TamperingTransport : public IByteTransport {
public:
    TamperingTransport(std::unique_ptr<IByteTransport> inner, size_t bytes_before_flip)
        : inner_(std::move(inner)), bytes_before_flip_(bytes_before_flip),
          bytes_seen_(0) {}
    void sendAll(const uint8_t* p, size_t n) override {
        std::vector<uint8_t> buf(p, p + n);
        for (size_t i = 0; i < n; ++i) {
            if (bytes_seen_ + i == bytes_before_flip_) {
                buf[i] ^= 0x01;
            }
        }
        bytes_seen_ += n;
        inner_->sendAll(buf.data(), n);
    }
    void recvAll(uint8_t* p, size_t n) override { inner_->recvAll(p, n); }
    void close() override { inner_->close(); }
private:
    std::unique_ptr<IByteTransport> inner_;
    size_t bytes_before_flip_;
    size_t bytes_seen_;
};
}

static void test_tampered_frame_rejected() {
    std::printf("--- C4: tampered ciphertext byte rejected ---\n");
    auto id_a = ChannelIdentity::generate("MAS");
    auto id_b = ChannelIdentity::generate("S1");
    // Complete handshake normally first.
    auto r = doHandshake(id_a, id_b, toPeer(id_b), toPeer(id_a));
    if (r.err_a || r.err_b || !r.a || !r.b) {
        CHECK(false, "C4-pre: handshake failed unexpectedly");
        return;
    }
    // Now do a lightweight tamper test by having A send a large frame,
    // sniffing bytes on B's recv, and mutating one — approximated by using
    // a fresh channel wrapped with TamperingTransport.

    // We approximate: build a new pipe wrapped in TamperingTransport for
    // one side, redo handshake, then send.
    InMemoryPipe pipe;
    auto ta = pipe.sideA();
    // Wrap side A's transport so byte at offset 1000 (well inside a big
    // frame's ciphertext) gets flipped.
    auto ta_tamper = std::unique_ptr<IByteTransport>(
        new TamperingTransport(std::move(ta), 1000));
    auto tb = pipe.sideB();

    std::exception_ptr ea, eb;
    std::unique_ptr<ISecureChannel> ca, cb;
    std::thread th_a([&]{
        try {
            ca = handshakeSodium(HandshakeRole::INITIATOR, id_a, toPeer(id_b),
                                    std::move(ta_tamper));
        } catch (...) { ea = std::current_exception(); }
    });
    std::thread th_b([&]{
        try {
            cb = handshakeSodium(HandshakeRole::RESPONDER, id_b, toPeer(id_a),
                                    std::move(tb));
        } catch (...) { eb = std::current_exception(); }
    });
    th_a.join(); th_b.join();

    if (ea || eb) {
        // Handshake bytes got flipped — that itself is a tamper detection.
        CHECK(true, "C4a: handshake tamper detected");
        return;
    }
    if (!ca || !cb) {
        CHECK(false, "C4b: channels missing post-handshake");
        return;
    }

    // Handshake somehow survived (flip byte landed in a spot secretstream
    // tolerates on plaintext — should be rare/impossible). Try a data
    // frame: send from A, expect B to detect the MAC failure eventually.
    bool recv_threw = false;
    std::thread sender([&]{
        try { ca->sendFrame(std::vector<uint8_t>(2048, 0x77)); }
        catch (...) {}
    });
    try { (void)cb->recvFrame(); }
    catch (const std::exception&) { recv_threw = true; }
    sender.join();
    CHECK(recv_threw, "C4c: MAC failure detected on tampered data frame");
}

// ==========================================================================
// C5 — Clean shutdown via TAG_FINAL
// ==========================================================================

static void test_clean_shutdown() {
    std::printf("--- C5: closeClean → peer sees TAG_FINAL on next recv ---\n");
    auto id_a = ChannelIdentity::generate("MAS");
    auto id_b = ChannelIdentity::generate("S1");
    auto r = doHandshake(id_a, id_b, toPeer(id_b), toPeer(id_a));
    if (r.err_a || r.err_b || !r.a || !r.b) {
        CHECK(false, "C5-pre: handshake failed");
        return;
    }
    r.a->closeClean();
    bool threw = false;
    try { (void)r.b->recvFrame(); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw, "C5: peer recv threw after clean close");
}

// ==========================================================================
// C6 — Role assignment is deterministic
// ==========================================================================

static void test_role_assignment() {
    std::printf("--- C6: assignRole is deterministic ---\n");
    CHECK(assignRole("MAS", "S1") == HandshakeRole::INITIATOR,
          "C6a: MAS < S1 → INITIATOR");
    CHECK(assignRole("S1", "MAS") == HandshakeRole::RESPONDER,
          "C6b: S1 > MAS → RESPONDER");
    bool threw = false;
    try { (void)assignRole("MAS", "MAS"); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw, "C6c: same-name assignment throws");
}

// ==========================================================================
// C7 — Frame size limits enforced
// ==========================================================================

static void test_frame_size_cap() {
    std::printf("--- C7: send rejects frames > 32MiB ---\n");
    auto id_a = ChannelIdentity::generate("MAS");
    auto id_b = ChannelIdentity::generate("S1");
    auto r = doHandshake(id_a, id_b, toPeer(id_b), toPeer(id_a));
    if (r.err_a || r.err_b) { CHECK(false, "C7-pre: handshake failed"); return; }
    std::vector<uint8_t> huge(33ULL * 1024ULL * 1024ULL);
    bool threw = false;
    try { r.a->sendFrame(huge); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw, "C7: 33MB frame rejected");
}

int main() {
    ensureSodiumInit();
    std::printf("=== MPSVS SecureChannel ===\n\n");
    test_honest_handshake_and_data_transfer();
    test_mitm_wrong_pk_rejected();
    test_name_mismatch_rejected();
    test_tampered_frame_rejected();
    test_clean_shutdown();
    test_role_assignment();
    test_frame_size_cap();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — authenticated encrypted channel with MITM detection.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
