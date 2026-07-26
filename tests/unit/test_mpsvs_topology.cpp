// Phase 3 acceptance-criteria tests: two-domain topology + session + Beaver + transcript.
// Per docs/DEPLOYMENT_FULL_MPC.md Phase 3.

#include "volePSI/MpsvsTopology.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

using namespace volePSI::mpsvs;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// Small nonce helper
static std::array<uint8_t, 16> makeNonce(uint8_t seed) {
    std::array<uint8_t, 16> n{};
    for (size_t i = 0; i < n.size(); ++i) n[i] = static_cast<uint8_t>(seed ^ i);
    return n;
}

static PhiSummary makePhi() {
    PhiSummary p;
    p.epoch_id = 2026003;
    p.Q_tilde = 1000;
    p.cap_P = 256;
    p.N_hat = (1u << p.beta) * 3 * p.cap_P;   // 3 clients
    return p;
}

// ---------------------------------------------------------------------------
// C1: SP transcript contains ZERO plaintext of any client id, payload, ratio,
//     or entity-level intermediate. Structurally verified: every event class
//     is whitelisted and every payload conforms to a fixed size class (§14').
// ---------------------------------------------------------------------------

static void test_sp_transcript_no_plaintext() {
    TopologySession sess(makePhi(), SessionId::random(), makeNonce(0x11));
    sess.runDkg();
    oc::PRNG prng(oc::block(0, 1));
    sess.provisionBeaver(64, prng);

    // Have MAS/DOS/MOM derive keys for the same 3 entities.
    for (const std::string& id : {"200812345K", "199988877A", "200455566B"}) {
        sess.clientDeriveKey(Role::MAS, "UEN", id, 20263);
        sess.clientDeriveKey(Role::DOS, "UEN", id, 20263);
        sess.clientDeriveKey(Role::MOM, "UEN", id, 20263);
    }

    const auto& trans = sess.transcript();
    CHECK(trans.size() >= 3 /*dkg*/ + 3*3*2 /*oprf hops*/,
          "C1: transcript populated by DKG + OPRF");

    // Whitelist of event classes and their maximum sizes.
    // dkg_commit  = SHA-256 output (32 bytes)
    // dkg_hop1    = Y1 (32) + Schnorr (c=32, s=32) = 96 bytes
    // dkg_hop2    = Y2 (32) + pi2 (64) + Y (32) + piY (64) = 192 bytes
    // oprf_hop1   = U (32) + V1 (32) + DLEQ (64) = 128 bytes
    // oprf_hop2   = V1 (32) + V2 (32) + DLEQ (64) = 128 bytes
    std::unordered_map<std::string, size_t> class_max = {
        {"dkg_commit", 32},
        {"dkg_hop1",   96},
        {"dkg_hop2",  192},
        {"oprf_hop1", 128},
        {"oprf_hop2", 128},
    };
    CHECK(trans.auditFixedShape(class_max),
          "C1: every transcript entry conforms to a whitelisted fixed-shape event class");

    // Structural check: no transcript payload contains a client's raw id
    // bytes verbatim. (Client id "200812345K" as ASCII is 10 bytes.)
    for (const auto& e : trans.entries()) {
        for (const std::string& id : {"200812345K", "199988877A", "200455566B"}) {
            std::vector<uint8_t> needle(id.begin(), id.end());
            auto it = std::search(e.payload.begin(), e.payload.end(),
                                  needle.begin(), needle.end());
            if (it != e.payload.end()) {
                std::printf("    !!! transcript event '%s' contained id '%s' verbatim\n",
                            e.event.c_str(), id.c_str());
                ++failures;
                return;
            }
        }
    }
    CHECK(true, "C1: no client id appears verbatim in any transcript entry");
}

// ---------------------------------------------------------------------------
// C2: Removing SP breaks the protocol; removing any one client breaks that
//     client's contribution but others complete.
// ---------------------------------------------------------------------------

static void test_removing_sp_breaks() {
    // Simulate SP absence by attempting to run without DKG.
    TopologySession sess(makePhi(), SessionId::random(), makeNonce(0x22));
    oc::PRNG prng(oc::block(0, 2));
    sess.provisionBeaver(64, prng);
    bool threw = false;
    try {
        sess.clientDeriveKey(Role::MAS, "UEN", "TEST", 20263);
    } catch (const std::exception& e) {
        threw = true;
    }
    CHECK(threw,
          "C2: attempting client OPRF without SP (no DKG) throws — protocol blocked");
}

static void test_client_absence_others_complete() {
    TopologySession sess(makePhi(), SessionId::random(), makeNonce(0x33));
    sess.runDkg();
    oc::PRNG prng(oc::block(0, 3));
    sess.provisionBeaver(64, prng);

    // MAS and DOS derive; MOM does not participate.
    for (const std::string& id : {"200812345K", "199988877A"}) {
        sess.clientDeriveKey(Role::MAS, "UEN", id, 20263);
        sess.clientDeriveKey(Role::DOS, "UEN", id, 20263);
    }
    // MOM has no entity keys but session state is otherwise complete
    CHECK(sess.client(Role::MAS).entity_keys.size() == 2 &&
          sess.client(Role::DOS).entity_keys.size() == 2 &&
          sess.client(Role::MOM).entity_keys.size() == 0,
          "C2': MAS+DOS complete OPRF; MOM absent → its contribution empty; others OK");

    // Downstream would flag MOM as missing → generic external abort per §25;
    // but MAS and DOS can pass their inputs to the next stage. In an actual
    // deployment this becomes a policy question (whether to abort or run
    // with n-1 clients). Phase 3 test just confirms session integrity.
}

// ---------------------------------------------------------------------------
// C3: Beaver triples freshly generated per session; no reuse across runs.
// ---------------------------------------------------------------------------

static void test_beaver_no_reuse() {
    PhiSummary phi = makePhi();
    SessionId sid1 = SessionId::random();
    SessionId sid2 = SessionId::random();
    // Sanity: different session ids
    CHECK(std::memcmp(sid1.bytes.data(), sid2.bytes.data(), 16) != 0,
          "C3: two random SessionIds differ");

    BeaverBag bag;
    oc::PRNG prng(oc::block(0, 4));

    auto b1 = bag.generate(sid1, 32, prng);
    CHECK(b1.s1_view.size() == 32 && b1.s2_view.size() == 32,
          "C3: bag provisions 32 triples for session 1");

    // Same session again → refuses (no reuse invariant).
    bool threw = false;
    try {
        bag.generate(sid1, 32, prng);
    } catch (const std::exception& e) {
        threw = true;
    }
    CHECK(threw, "C3: bag refuses to re-provision the same session id");

    // Different session → allowed
    auto b2 = bag.generate(sid2, 16, prng);
    CHECK(b2.s1_view.size() == 16, "C3: bag provisions triples for session 2");

    // Freshness: triples in b1 differ from b2 (at least one u share differs)
    bool differ = false;
    for (size_t i = 0; i < std::min(b1.s1_view.size(), b2.s1_view.size()); ++i) {
        auto u1 = b1.s1_view[i].u.reconstruct();
        auto u2 = b2.s1_view[i].u.reconstruct();
        if (u1 != u2) { differ = true; break; }
    }
    CHECK(differ, "C3: triples across sessions are fresh (u values differ)");
}

// ---------------------------------------------------------------------------
// C4: GovTech (GT) has no share, handle, or payload at any point.
// ---------------------------------------------------------------------------

static void test_gt_blindness() {
    TopologySession sess(makePhi(), SessionId::random(), makeNonce(0x44));
    sess.runDkg();
    oc::PRNG prng(oc::block(0, 5));
    sess.provisionBeaver(64, prng);

    sess.clientDeriveKey(Role::MAS, "UEN", "200812345K", 20263);
    sess.clientDeriveKey(Role::DOS, "UEN", "200812345K", 20263);

    // Structural audit: GtState fields are only public (phi, session,
    // attestations, final_release). auditGtBlindness returns "" on OK.
    std::string result = auditGtBlindness(sess.gt());
    CHECK(result.empty(), "C4: GT holds no shares / handles / payloads (structural audit)");

    // GT should not see the entity keys (which live at clients) nor Beaver
    // shares (which live at S1/S2).
    // Type system prevents access via TopologySession API — no gt() getter
    // returns any share or handle. Compile-time invariant.
    CHECK(sess.gt().final_release.empty(),
          "C4: GT final_release is empty until Phase 12 disclosure (Phase 3 does not populate)");
}

// ---------------------------------------------------------------------------
// Additional: metering — Q̃ cap enforced
// ---------------------------------------------------------------------------

static void test_metering() {
    PhiSummary phi = makePhi();
    phi.Q_tilde = 2;   // very low cap
    TopologySession sess(phi, SessionId::random(), makeNonce(0x55));
    sess.runDkg();
    oc::PRNG prng(oc::block(0, 6));
    sess.provisionBeaver(64, prng);

    sess.clientDeriveKey(Role::MAS, "UEN", "id1", 20263);
    sess.clientDeriveKey(Role::MAS, "UEN", "id2", 20263);
    // 3rd should throw
    bool threw = false;
    try {
        sess.clientDeriveKey(Role::MAS, "UEN", "id3", 20263);
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw, "Metering: Q̃=2 cap enforced — 3rd query throws");
}

// ---------------------------------------------------------------------------
// Session isolation — same entity across sessions yields unlinkable keys
// ---------------------------------------------------------------------------

static void test_session_isolation() {
    PhiSummary phi = makePhi();
    TopologySession s1(phi, SessionId::random(), makeNonce(0x66));
    s1.runDkg();
    oc::PRNG prng1(oc::block(0, 7));
    s1.provisionBeaver(16, prng1);

    TopologySession s2(phi, SessionId::random(), makeNonce(0x67));
    s2.runDkg();
    oc::PRNG prng2(oc::block(0, 8));
    s2.provisionBeaver(16, prng2);

    s1.clientDeriveKey(Role::MAS, "UEN", "SAME_ENTITY", 20263);
    s2.clientDeriveKey(Role::MAS, "UEN", "SAME_ENTITY", 20263);

    const auto& k1 = s1.client(Role::MAS).entity_keys[0];
    const auto& k2 = s2.client(Role::MAS).entity_keys[0];
    bool differ = std::memcmp(k1.data(), k2.data(), 32) != 0;
    CHECK(differ,
          "Session isolation: same entity across two DKGs yields unlinkable keys");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) {
        std::printf("FATAL: libsodium init failed\n");
        return 2;
    }
    std::puts("=== MpsvsTopology — Phase 3 acceptance-criteria tests ===\n");

    test_sp_transcript_no_plaintext();
    std::puts("");
    test_removing_sp_breaks();
    std::puts("");
    test_client_absence_others_complete();
    std::puts("");
    test_beaver_no_reuse();
    std::puts("");
    test_gt_blindness();
    std::puts("");
    test_metering();
    std::puts("");
    test_session_isolation();

    std::puts("");
    if (failures) { std::printf("== %d FAILURES ==\n", failures); return 1; }
    std::puts("ALL PASSED — Phase 3 acceptance criteria met");
    return 0;
}
