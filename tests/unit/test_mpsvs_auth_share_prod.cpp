// MPSVS Production Retrofit tests — hardened AuthShare with hygiene primitives.

#include "volePSI/MpsvsAuthShare.h"
#include "volePSI/MpsvsAuthShareProd.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_authShareU64Prod_correctness() {
    std::printf("--- C1: authShareU64Prod produces valid MAC-authenticated share ---\n");
    SecureAlpha alpha = SecureAlpha::generate();
    AuthSharedU64 x = authShareU64Prod(2, /*value=*/12345, alpha);
    // Reconstruct value and MAC.
    uint64_t v = x.value.reconstruct();
    uint64_t m = x.mac.reconstruct();
    CHECK(v == 12345, "C1: reconstructed value = 12345");
    CHECK(m == alpha.get() * 12345, "C1: MAC = α · value");
}

static void test_openWithMacCheckProd_success() {
    std::printf("--- C2: openWithMacCheckProd honest → Result ok ---\n");
    SecureAlpha alpha = SecureAlpha::generate();
    AuthSharedU64 x = authShareU64Prod(2, 999, alpha);
    std::array<uint8_t, 32> genesis{};
    AbortContext ctx{"test", 0, "cell_a", ""};
    Result<uint64_t> r = openWithMacCheckProd(x, alpha, ctx, genesis);
    CHECK(r.ok(), "C2: honest Result.ok() = true");
    CHECK(r.value == 999, "C2: value carried through");
}

static void test_openWithMacCheckProd_tampered() {
    std::printf("--- C3: openWithMacCheckProd tampered → Result with abort report ---\n");
    SecureAlpha alpha = SecureAlpha::generate();
    AuthSharedU64 x = authShareU64Prod(2, 999, alpha);
    simulateTampering(x, /*bad_party=*/0, /*tamper=*/13);
    std::array<uint8_t, 32> genesis{};
    AbortContext ctx{"test", 0, "cell_a", "tampered"};
    Result<uint64_t> r = openWithMacCheckProd(x, alpha, ctx, genesis);
    CHECK(!r.ok(), "C3: tampered Result.ok() = false");
    CHECK(r.abort.reason == AbortReason::MAC_FAIL, "C3: reason = MAC_FAIL");
    CHECK(r.abort.ctx.cell_key == "cell_a", "C3: cell_key preserved in abort");
    CHECK(r.abort.timestamp_ns > 0, "C3: timestamp populated");
}

static void test_secure_alpha_zeroes() {
    std::printf("--- C4: SecureAlpha wipes on scope exit ---\n");
    // Verify: SecureAlpha holds α while in scope, is move-only.
    SecureAlpha a = SecureAlpha::generate();
    uint64_t val_a = a.get();
    CHECK(val_a != 0, "C4: fresh α is non-zero (rejected 0 in generator)");
    // Move: source wiped, destination has value.
    SecureAlpha b = std::move(a);
    CHECK(b.get() == val_a, "C4: move transfers α");
    CHECK(a.get() == 0, "C4: source α wiped after move");
}

static void test_session_audit_log() {
    std::printf("--- C5: SessionAuditLog accumulates verifiable hash chain ---\n");
    SessionAuditLog log;
    CHECK(log.size() == 0, "C5: empty log initially");

    SecureAlpha alpha = SecureAlpha::generate();
    // Simulate 3 successful opens (no abort) + 2 MAC failures.
    for (int i = 0; i < 3; ++i) {
        AuthSharedU64 x = authShareU64Prod(2, i * 100, alpha);
        AbortContext ctx{"agg", 0, "cell_" + std::to_string(i), ""};
        auto r = openWithAuditLog(x, alpha, ctx, log);
        CHECK(r.ok(), "C5: honest open succeeds");
    }
    CHECK(log.size() == 0, "C5: no abort entries after 3 successful opens");

    for (int i = 0; i < 2; ++i) {
        AuthSharedU64 x = authShareU64Prod(2, 500 + i, alpha);
        simulateTampering(x, /*bad_party=*/i % 2, /*tamper=*/7 + i);
        AbortContext ctx{"agg", static_cast<uint32_t>(i % 2),
                           "cell_bad_" + std::to_string(i), "tamper"};
        auto r = openWithAuditLog(x, alpha, ctx, log);
        CHECK(!r.ok(), "C5: tampered open aborts");
    }
    CHECK(log.size() == 2, "C5: 2 abort entries after 2 tampered opens");

    // Verify chain integrity end-to-end.
    auto chain = log.snapshot();
    bool ok = verifyAbortChain(chain);
    CHECK(ok, "C5: hash chain verifies end-to-end");
}

static void test_audit_chain_survives_tampering() {
    std::printf("--- C6: post-hoc tampering with audit chain is detected ---\n");
    SessionAuditLog log;
    SecureAlpha alpha = SecureAlpha::generate();
    for (int i = 0; i < 4; ++i) {
        AuthSharedU64 x = authShareU64Prod(2, i, alpha);
        simulateTampering(x, 0, 1);
        AbortContext ctx{"agg", 0, "cell_" + std::to_string(i), ""};
        openWithAuditLog(x, alpha, ctx, log);
    }
    auto chain = log.snapshot();
    CHECK(chain.size() == 4, "C6: 4 abort entries logged");
    // Post-hoc attacker tries to hide entry 2 by modifying context.
    chain[2].ctx.cell_key = "cell_HIDDEN";
    bool ok = verifyAbortChain(chain);
    CHECK(!ok, "C6: hash chain detects post-hoc audit tampering");
}

static void test_csprng_alpha_diversity() {
    std::printf("--- C7: multiple SecureAlpha::generate() produce distinct α ---\n");
    uint64_t a = SecureAlpha::generate().get();
    uint64_t b = SecureAlpha::generate().get();
    uint64_t c = SecureAlpha::generate().get();
    CHECK(a != b && b != c && a != c, "C7: 3 fresh α values all distinct");
}

int main() {
    std::printf("=== MPSVS Prod-Retrofit: AuthShare with hygiene primitives ===\n\n");
    test_authShareU64Prod_correctness();
    test_openWithMacCheckProd_success();
    test_openWithMacCheckProd_tampered();
    test_secure_alpha_zeroes();
    test_session_audit_log();
    test_audit_chain_survives_tampering();
    test_csprng_alpha_diversity();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — production-hardened auth-share works end-to-end.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
