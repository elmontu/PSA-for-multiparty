#include "MpsvsProdHygiene.h"

#include <sodium.h>

#include <mutex>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// libsodium init — thread-safe via std::call_once.
// Note: sodium_init() itself is documented as thread-safe and idempotent
// (returns 1 if already initialized), but wrapping in call_once avoids
// any repeated syscall overhead + eliminates the race on our flag.
// ---------------------------------------------------------------------------

static std::once_flag s_sodium_init_once;

void ensureSodiumInit() {
    std::call_once(s_sodium_init_once, []{
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium sodium_init() failed");
        }
    });
}

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------

void secureRandBytes(void* buf, size_t n) {
    ensureSodiumInit();
    randombytes_buf(buf, n);
}

uint64_t secureRandU64() {
    uint64_t v = 0;
    secureRandBytes(&v, sizeof(v));
    return v;
}

uint64_t secureRandU64Bounded(uint64_t upper) {
    ensureSodiumInit();
    if (upper == 0) return 0;
    // libsodium provides an unbiased u32 API; extend to u64 via composition.
    // For simplicity in the prototype: rejection-sample u64 % upper if bias
    // is negligible (upper << 2^64 → bias < 2^-63).
    // Production caller should use randombytes_uniform for 32-bit ranges.
    uint64_t x;
    do {
        secureRandBytes(&x, sizeof(x));
    } while (x >= (UINT64_MAX - (UINT64_MAX % upper)));
    return x % upper;
}

// ---------------------------------------------------------------------------
// Structured abort
// ---------------------------------------------------------------------------

const char* abortReasonName(AbortReason r) {
    switch (r) {
        case AbortReason::NONE:                 return "NONE";
        case AbortReason::MAC_FAIL:             return "MAC_FAIL";
        case AbortReason::SACRIFICE_FAIL:       return "SACRIFICE_FAIL";
        case AbortReason::DLEQ_FAIL:            return "DLEQ_FAIL";
        case AbortReason::NIZK_SHUFFLE_FAIL:    return "NIZK_SHUFFLE_FAIL";
        case AbortReason::BIT_PROOF_FAIL:       return "BIT_PROOF_FAIL";
        case AbortReason::RECIP_INVARIANT_FAIL: return "RECIP_INVARIANT_FAIL";
        case AbortReason::DP_COMMIT_MISMATCH:   return "DP_COMMIT_MISMATCH";
        case AbortReason::OLE_INVARIANT_FAIL:   return "OLE_INVARIANT_FAIL";
    }
    return "?";
}

static std::array<uint8_t, 32>
computeLink(AbortReason reason, const AbortContext& ctx, uint64_t ts_ns,
             const std::array<uint8_t, 32>& prev_link) {
    ensureSodiumInit();
    std::vector<uint8_t> buf;
    // reason (1 byte for enum id) + party (4 bytes) + timestamp (8) +
    // phase + cell_key + notes (with length prefixes) + prev_link (32).
    buf.push_back(static_cast<uint8_t>(reason));
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((ctx.party_id >> (i * 8)) & 0xff));
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<uint8_t>((ts_ns >> (i * 8)) & 0xff));
    auto push_str = [&](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xff));
        buf.insert(buf.end(), s.begin(), s.end());
    };
    push_str(ctx.protocol_phase);
    push_str(ctx.cell_key);
    push_str(ctx.extra_notes);
    buf.insert(buf.end(), prev_link.begin(), prev_link.end());
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(), buf.data(), buf.size());
    return h;
}

AbortReport makeAbortReport(AbortReason reason, AbortContext ctx,
                              const std::array<uint8_t, 32>& prev_link) {
    AbortReport r;
    r.reason = reason;
    r.ctx = std::move(ctx);
    // Nanosecond wall-clock.
    r.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    r.prev_link = prev_link;
    r.this_link = computeLink(r.reason, r.ctx, r.timestamp_ns, r.prev_link);
    return r;
}

bool verifyAbortChain(const std::vector<AbortReport>& chain) {
    for (size_t i = 0; i < chain.size(); ++i) {
        // Recompute this_link from (reason, ctx, ts, prev_link).
        auto expected = computeLink(chain[i].reason, chain[i].ctx,
                                      chain[i].timestamp_ns, chain[i].prev_link);
        if (expected != chain[i].this_link) return false;
        // prev_link must match previous entry's this_link.
        if (i > 0 && chain[i].prev_link != chain[i-1].this_link) return false;
    }
    return true;
}

} // namespace mpsvs
} // namespace volePSI
