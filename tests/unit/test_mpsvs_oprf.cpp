// Phase 2 acceptance-criteria tests: server-aided blind DH-OPRF.
// Per docs/DEPLOYMENT_FULL_MPC.md Phase 2 + Protocol §2 (DKG) + §3 (OPRF).

#include "volePSI/MpsvsOprf.h"

#include <sodium.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace volePSI::mpsvs;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static Context makeCtx(const std::string& tag) {
    // ctx = "protocol_version||epoch_id||session_id||nonce". Any bytestring.
    return Context(tag.begin(), tag.end());
}

// Two-server in-process setup used by all tests.
struct InProcessTwoServer {
    DkgS1State s1{};
    DkgS2State s2{};

    void setup(const Context& ctx) {
        // Rev 7 §2 bias-frozen DKG: S2 commits first.
        DkgS2Prep prep = dkgS2Prepare(ctx);
        // S1 sends Hop1.
        Scalar k1{};
        DkgS1Msg1 msg1 = dkgS1SendHop1(ctx, k1);
        DkgHop1 hop1{ msg1.Y1, msg1.pi1 };
        // S2 finalizes (verifies pi1, produces Y + DLEQ).
        DkgHop2Final finalMsg = dkgS2Finalize(ctx, prep, hop1, s2);
        // S1 finalizes (verifies commit opening, pi2, piY).
        bool ok = dkgS1Finalize(ctx, prep.commit, k1, msg1.Y1, finalMsg, s1);
        if (!ok) throw std::runtime_error("in-process DKG finalize failed");
        // Sanity: both hold the same Y.
        assert(sodium_memcmp(s1.Y.data(), s2.Y.data(), 32) == 0);
    }

    // Party-side OPRF callbacks.
    std::function<OprfHop1Response(const GroupElement&)> hop1Cb(const Context& ctx) {
        return [this, ctx](const GroupElement& U) { return oprfServerHop1(s1, U, ctx); };
    }
    std::function<OprfHop2Response(const GroupElement&)> hop2Cb(const Context& ctx) {
        return [this, ctx](const GroupElement& V1) { return oprfServerHop2(s2, V1, ctx); };
    }
};

// ---------------------------------------------------------------------------
// Criterion 1: For a given (run_id, entity), all agencies derive the same
//              handle. Cross-party OPRF determinism.
// ---------------------------------------------------------------------------

static void test_cross_party_deterministic_handles() {
    Context ctx = makeCtx("SVS|epoch=2026Q3|session=42|nonce=abc");
    InProcessTwoServer server;
    server.setup(ctx);

    std::string id_type = "UEN";
    std::string ent = "200812345K";

    // Party MAS derives
    auto rMAS = deriveEntityKey(id_type, ent, ctx, server.s1.Y1, server.s2.Y2, server.s1.Y,
                                server.hop1Cb(ctx), server.hop2Cb(ctx));
    // Party DOS derives (independently — fresh blind r)
    auto rDOS = deriveEntityKey(id_type, ent, ctx, server.s1.Y1, server.s2.Y2, server.s1.Y,
                                server.hop1Cb(ctx), server.hop2Cb(ctx));
    // Party MOM derives
    auto rMOM = deriveEntityKey(id_type, ent, ctx, server.s1.Y1, server.s2.Y2, server.s1.Y,
                                server.hop1Cb(ctx), server.hop2Cb(ctx));

    CHECK(rMAS.ok && rDOS.ok && rMOM.ok,
          "C1: all three agencies successfully derive entity key");
    CHECK(sodium_memcmp(rMAS.W.data(), rDOS.W.data(), 32) == 0,
          "C1: MAS and DOS derive identical W for same entity");
    CHECK(sodium_memcmp(rDOS.W.data(), rMOM.W.data(), 32) == 0,
          "C1: DOS and MOM derive identical W for same entity");

    // Different entity → different W
    auto rOther = deriveEntityKey(id_type, "199988877A", ctx, server.s1.Y1, server.s2.Y2,
                                  server.s1.Y, server.hop1Cb(ctx), server.hop2Cb(ctx));
    CHECK(rOther.ok && sodium_memcmp(rMAS.W.data(), rOther.W.data(), 32) != 0,
          "C1: different entities produce different W");

    // Row tags for same entity + same period match across agencies
    uint32_t p = 20263;  // 2026 Q3 encoded (year*10 + quarter)
    RowTag tMAS = deriveRowTag(id_type, ent, p, rMAS.W, ctx);
    RowTag tDOS = deriveRowTag(id_type, ent, p, rDOS.W, ctx);
    CHECK(sodium_memcmp(tMAS.t.data(), tDOS.t.data(), 32) == 0,
          "C1: same-entity same-period row tags identical across agencies");

    // Different period → different tag
    RowTag tOtherPeriod = deriveRowTag(id_type, ent, 20264, rMAS.W, ctx);
    CHECK(sodium_memcmp(tMAS.t.data(), tOtherPeriod.t.data(), 32) != 0,
          "C1: different periods produce different row tags for same entity");
}

// ---------------------------------------------------------------------------
// Criterion 2: Handle cannot be linked back to source id without K_run.
// (Cannot test formally — trust the OPRF pseudorandomness. But verify
//  that W is a valid group element and that different id_types disambiguate.)
// ---------------------------------------------------------------------------

static void test_id_type_domain_separation() {
    Context ctx = makeCtx("SVS|epoch=1");
    InProcessTwoServer server; server.setup(ctx);

    // Same canonical bytes under different id_types must produce DIFFERENT W.
    auto rUEN  = deriveEntityKey("UEN",  "200812345K", ctx, server.s1.Y1, server.s2.Y2,
                                 server.s1.Y, server.hop1Cb(ctx), server.hop2Cb(ctx));
    auto rNRIC = deriveEntityKey("NRIC", "200812345K", ctx, server.s1.Y1, server.s2.Y2,
                                 server.s1.Y, server.hop1Cb(ctx), server.hop2Cb(ctx));
    CHECK(rUEN.ok && rNRIC.ok, "C2: both id_types derive OK");
    CHECK(sodium_memcmp(rUEN.W.data(), rNRIC.W.data(), 32) != 0,
          "C2: same string under different id_types produces different W (R23 domain sep)");
}

// ---------------------------------------------------------------------------
// Criterion 3: Different runs produce unlinkable handles.
// ---------------------------------------------------------------------------

static void test_cross_run_unlinkability() {
    std::string id_type = "UEN";
    std::string ent = "200812345K";

    Context ctxA = makeCtx("SVS|epoch=2026Q3|session=1|nonce=aa");
    Context ctxB = makeCtx("SVS|epoch=2026Q4|session=1|nonce=bb");

    InProcessTwoServer sA; sA.setup(ctxA);
    InProcessTwoServer sB; sB.setup(ctxB);

    auto rA = deriveEntityKey(id_type, ent, ctxA, sA.s1.Y1, sA.s2.Y2, sA.s1.Y,
                              sA.hop1Cb(ctxA), sA.hop2Cb(ctxA));
    auto rB = deriveEntityKey(id_type, ent, ctxB, sB.s1.Y1, sB.s2.Y2, sB.s1.Y,
                              sB.hop1Cb(ctxB), sB.hop2Cb(ctxB));

    CHECK(rA.ok && rB.ok, "C3: both runs derive OK");
    CHECK(sodium_memcmp(rA.W.data(), rB.W.data(), 32) != 0,
          "C3: fresh DKG per epoch → unlinkable W across runs");

    // Even with same ctx, row tags differ because W differs
    uint32_t p = 20263;
    RowTag tA = deriveRowTag(id_type, ent, p, rA.W, ctxA);
    RowTag tB = deriveRowTag(id_type, ent, p, rB.W, ctxB);
    CHECK(sodium_memcmp(tA.t.data(), tB.t.data(), 32) != 0,
          "C3: row tags across runs unlinkable");
}

// ---------------------------------------------------------------------------
// Criterion 4: LP() encoding injectivity (R23 defect F fix).
// ---------------------------------------------------------------------------

static void test_lp_injectivity() {
    // Attack vector: ("UEN", "123...") vs ("UE", "N123...")
    Context ctx = makeCtx("SVS|epoch=1");
    InProcessTwoServer server; server.setup(ctx);

    auto rA = deriveEntityKey("UEN", "123ABC", ctx, server.s1.Y1, server.s2.Y2,
                              server.s1.Y, server.hop1Cb(ctx), server.hop2Cb(ctx));
    auto rB = deriveEntityKey("UE", "N123ABC", ctx, server.s1.Y1, server.s2.Y2,
                              server.s1.Y, server.hop1Cb(ctx), server.hop2Cb(ctx));

    CHECK(rA.ok && rB.ok, "C4: both LP variants derive OK");
    CHECK(sodium_memcmp(rA.W.data(), rB.W.data(), 32) != 0,
          "C4: LP(id_type)+LP(x) is injective — ('UEN','123ABC') != ('UE','N123ABC')");

    // Direct LP encoding check on raw bytes
    std::vector<uint8_t> a, b;
    appendLP(a, std::string("UEN")); appendLP(a, std::string("123ABC"));
    appendLP(b, std::string("UE"));  appendLP(b, std::string("N123ABC"));
    CHECK(a != b, "C4: raw LP-encoded byte streams differ");
}

// ---------------------------------------------------------------------------
// Criterion 5: DKG bias-freezing (R24). S2 commits before Y1 revealed.
//              Attempt to swap Y2 post-commit → verification fails.
// ---------------------------------------------------------------------------

static void test_dkg_bias_freezing() {
    Context ctx = makeCtx("SVS|bias-test");

    // Honest flow
    DkgS2Prep prep = dkgS2Prepare(ctx);
    Scalar k1; DkgS1Msg1 msg1 = dkgS1SendHop1(ctx, k1);
    DkgHop1 hop1{ msg1.Y1, msg1.pi1 };
    DkgS2State s2{};
    DkgHop2Final finalMsg = dkgS2Finalize(ctx, prep, hop1, s2);
    DkgS1State s1{};
    bool ok = dkgS1Finalize(ctx, prep.commit, k1, msg1.Y1, finalMsg, s1);
    CHECK(ok, "C5: honest DKG finalizes");

    // Malicious S2: try to swap Y2 after seeing Y1 (attempt to bias Y).
    // Any (Y2', pi2') that hashes to prep.commit is bound to prep.Y2 by the
    // commitment binding. Swapping requires finding a collision in SHA-256.
    // Simulate: attacker replaces Y2 with garbage in the final message; commit
    // check must fail.
    DkgHop2Final tampered = finalMsg;
    randombytes_buf(tampered.Y2.data(), 32);   // random new "Y2"
    DkgS1State s1_bad{};
    bool bad_ok = dkgS1Finalize(ctx, prep.commit, k1, msg1.Y1, tampered, s1_bad);
    CHECK(!bad_ok, "C5: tampered Y2 rejected by commit-opening check");

    // Also: tampered piY should be rejected
    DkgHop2Final tampered2 = finalMsg;
    randombytes_buf(tampered2.piY.s.data(), 32);
    DkgS1State s1_bad2{};
    bool bad_ok2 = dkgS1Finalize(ctx, prep.commit, k1, msg1.Y1, tampered2, s1_bad2);
    CHECK(!bad_ok2, "C5: tampered DLEQ proof rejected");
}

// ---------------------------------------------------------------------------
// Criterion 6: DLEQ per-hop verifies correctness of server response.
//              Malicious server response → client abort.
// ---------------------------------------------------------------------------

static void test_dleq_catches_wrong_response() {
    Context ctx = makeCtx("SVS|dleq-test");
    InProcessTwoServer server; server.setup(ctx);

    // Wrap S1 hop with a tampering callback: server returns V1 = U^k1 as normal
    // but the DLEQ proof is corrupted. Client must abort.
    auto tampered_hop1 = [&](const GroupElement& U) {
        OprfHop1Response r = oprfServerHop1(server.s1, U, ctx);
        randombytes_buf(r.dleq.s.data(), 32);  // corrupt s
        return r;
    };

    auto r = deriveEntityKey("UEN", "TEST", ctx, server.s1.Y1, server.s2.Y2,
                             server.s1.Y, tampered_hop1, server.hop2Cb(ctx));
    CHECK(!r.ok, "C6: DLEQ failure at hop 1 causes client abort");

    // Now tamper hop 2
    auto tampered_hop2 = [&](const GroupElement& V1) {
        OprfHop2Response r = oprfServerHop2(server.s2, V1, ctx);
        randombytes_buf(r.dleq.c.data(), 32);
        return r;
    };
    auto r2 = deriveEntityKey("UEN", "TEST2", ctx, server.s1.Y1, server.s2.Y2,
                              server.s1.Y, server.hop1Cb(ctx), tampered_hop2);
    CHECK(!r2.ok, "C6: DLEQ failure at hop 2 causes client abort");
}

// ---------------------------------------------------------------------------
// Sanity: Schnorr and DLEQ standalone
// ---------------------------------------------------------------------------

static void test_schnorr_dleq_standalone() {
    Context ctx = makeCtx("standalone");
    Scalar k; randomScalar(k);
    GroupElement Y; scalarMultBase(Y, k);

    SchnorrProof pi = schnorrProve(k, Y, ctx);
    CHECK(schnorrVerify(Y, pi, ctx), "Schnorr: valid proof verifies");

    // Wrong Y → fail
    GroupElement Y_wrong; Scalar k2; randomScalar(k2); scalarMultBase(Y_wrong, k2);
    CHECK(!schnorrVerify(Y_wrong, pi, ctx), "Schnorr: wrong Y fails");

    // Wrong ctx → fail
    Context ctx2 = makeCtx("different");
    CHECK(!schnorrVerify(Y, pi, ctx2), "Schnorr: wrong ctx fails");

    // DLEQ
    GroupElement U; hashToGroup(U, std::vector<uint8_t>{1,2,3});
    GroupElement V; scalarMult(V, k, U);
    DLEQProof piD = dleqProve(k, Y, U, V, ctx);
    CHECK(dleqVerify(Y, U, V, piD, ctx), "DLEQ: valid proof verifies");
    // Wrong V → fail
    GroupElement V_wrong; scalarMult(V_wrong, k2, U);
    CHECK(!dleqVerify(Y, U, V_wrong, piD, ctx), "DLEQ: wrong V fails");
}

// ---------------------------------------------------------------------------
// RowTag bin/key slicing
// ---------------------------------------------------------------------------

static void test_row_tag_slicing() {
    // Test 1: all-zero prefix → bin=0
    RowTag t1{};
    for (int i = 0; i < 32; ++i) t1.t[i] = static_cast<uint8_t>(i);
    // t1 = 0x00 0x01 0x02 ... first 13 bits are all zero → bin(13) = 0
    CHECK(t1.bin(13) == 0, "RowTag: bin(13) of 0x00 0x01 ... = top 13 bits = 0");

    // Test 2: all-ones prefix → bin = 2^13 − 1
    RowTag t2{};
    for (int i = 0; i < 32; ++i) t2.t[i] = 0xFF;
    CHECK(t2.bin(13) == (1ULL << 13) - 1,
          "RowTag: bin(13) of 0xFF... = 2^13 - 1");

    // Test 3: crafted specific top bits
    // Byte 0 = 0xAA, byte 1 = 0xF0 → 16-bit prefix = 0xAAF0
    // Top 13 bits = 0xAAF0 >> 3 = 0x155E (5470)
    RowTag t3{}; t3.t[0] = 0xAA; t3.t[1] = 0xF0;
    CHECK(t3.bin(13) == 0x155E,
          "RowTag: bin(13) of 0xAA 0xF0 = top 13 bits = 0x155E (0xAAF0>>3)");

    // Test 4: 64-bit bin (edge)
    RowTag t4{}; for (int i = 0; i < 8; ++i) t4.t[i] = static_cast<uint8_t>(i + 1);
    // Bytes 0x01 0x02 ... 0x08 → 0x0102030405060708
    CHECK(t4.bin(64) == 0x0102030405060708ULL,
          "RowTag: bin(64) reads full 8-byte prefix");

    // Test 5: key extraction with byte-aligned beta
    RowTag t5{}; for (int i = 0; i < 32; ++i) t5.t[i] = static_cast<uint8_t>(i);
    auto k = t5.key(16, 32);   // start byte 2, 4 bytes
    CHECK(k.size() == 4 && k[0] == 2 && k[3] == 5,
          "RowTag: key(16, 32) extracts bytes t[2..5]");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) {
        std::printf("FATAL: libsodium init failed\n");
        return 2;
    }
    std::puts("=== MpsvsOprf — Phase 2 acceptance-criteria tests ===\n");

    test_schnorr_dleq_standalone();      std::puts("");
    test_cross_party_deterministic_handles(); std::puts("");
    test_id_type_domain_separation();    std::puts("");
    test_cross_run_unlinkability();      std::puts("");
    test_lp_injectivity();               std::puts("");
    test_dkg_bias_freezing();            std::puts("");
    test_dleq_catches_wrong_response();  std::puts("");
    test_row_tag_slicing();

    std::puts("");
    if (failures) { std::printf("== %d FAILURES ==\n", failures); return 1; }
    std::puts("ALL PASSED — Phase 2 acceptance criteria met");
    return 0;
}
