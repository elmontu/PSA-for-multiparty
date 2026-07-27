#include "MpsvsAuthShareProd.h"

#include <cstring>

namespace volePSI {
namespace mpsvs {

AuthSharedU64 authShareU64Prod(uint32_t N, uint64_t value,
                                 const SecureAlpha& alpha) {
    AuthSharedU64 x;
    x.value.shares.assign(N, 0);
    x.mac.shares.assign(N, 0);
    // Fresh CSPRNG shares for value and MAC.
    for (uint32_t p = 0; p + 1 < N; ++p) {
        x.value.shares[p] = secureRandU64();
        x.mac.shares[p]   = secureRandU64();
    }
    // Party N-1 absorbs the remainder so sum matches (value, α·value).
    uint64_t sum_v = 0, sum_m = 0;
    for (uint32_t p = 0; p + 1 < N; ++p) {
        sum_v += x.value.shares[p];
        sum_m += x.mac.shares[p];
    }
    x.value.shares[N - 1] = value - sum_v;
    x.mac.shares[N - 1]   = alpha.get() * value - sum_m;
    return x;
}

Result<uint64_t> openWithMacCheckProd(const AuthSharedU64& x,
                                        const SecureAlpha& alpha,
                                        const AbortContext& ctx,
                                        const std::array<uint8_t, 32>& prev_link) {
    uint64_t x_val = x.value.reconstruct();
    uint64_t x_mac = x.mac.reconstruct();
    uint64_t expected = alpha.get() * x_val;
    if (expected != x_mac) {
        return Result<uint64_t>::makeAbort(
            makeAbortReport(AbortReason::MAC_FAIL, ctx, prev_link));
    }
    return Result<uint64_t>::makeValue(x_val);
}

Result<uint64_t> openWithAuditLog(const AuthSharedU64& x,
                                    const SecureAlpha& alpha,
                                    const AbortContext& ctx,
                                    SessionAuditLog& log) {
    auto prev = log.currentLink();
    auto r = openWithMacCheckProd(x, alpha, ctx, prev);
    if (!r.ok()) {
        // Append to audit log; caller can inspect log after batch.
        log.append(r.abort.reason, r.abort.ctx);
    }
    return r;
}

} // namespace mpsvs
} // namespace volePSI
