#pragma once

// MPSVS Auth-Share Production Retrofit.
//
// Hardened variants of MpsvsAuthShare functions using:
//   - SecureU64 for α (auto-wiped on scope exit)
//   - libsodium CSPRNG for all secret sampling
//   - Result<T> return with structured AbortReport on MAC failures
//   - Hash-chained audit log across a session
//
// Legacy MpsvsAuthShare APIs are preserved for backward compatibility.
// New code paths should use the *Prod variants.

#include "MpsvsAuthShare.h"
#include "MpsvsProdHygiene.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <mutex>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// SecureAlpha — RAII wrapper around SPDZ α with production guarantees.
// ---------------------------------------------------------------------------

class SecureAlpha {
public:
    // Generate a fresh α from CSPRNG (production).
    static SecureAlpha generate() {
        uint64_t v = secureRandU64();
        if (v == 0) v = 1;   // reject 0 (would degenerate MAC)
        return SecureAlpha(v);
    }
    // Wrap an existing α (used by tests or key-ceremony wire).
    explicit SecureAlpha(uint64_t v) : value_(v) {}
    // Non-copyable, movable (via SecureU64).
    SecureAlpha(const SecureAlpha&) = delete;
    SecureAlpha& operator=(const SecureAlpha&) = delete;
    SecureAlpha(SecureAlpha&&) noexcept = default;
    SecureAlpha& operator=(SecureAlpha&&) noexcept = default;

    uint64_t get() const { return value_.get(); }

private:
    SecureU64 value_;
};

// ---------------------------------------------------------------------------
// Production-hardened auth-share ops.
// ---------------------------------------------------------------------------

// Create an authenticated share using CSPRNG. `prng` param is ignored
// (kept for signature compatibility with the legacy path).
AuthSharedU64 authShareU64Prod(uint32_t N, uint64_t value,
                                 const SecureAlpha& alpha);

// Open with MAC verification — returns Result<uint64_t> instead of bool.
// On failure, `abort` populated with (MAC_FAIL, ctx, timestamp, hash-chain
// link derived from `prev_link`).
Result<uint64_t> openWithMacCheckProd(const AuthSharedU64& x,
                                        const SecureAlpha& alpha,
                                        const AbortContext& ctx,
                                        const std::array<uint8_t, 32>& prev_link);

// ---------------------------------------------------------------------------
// SessionAuditLog — thread-safe hash-chained audit log for a session.
// ---------------------------------------------------------------------------

class SessionAuditLog {
public:
    SessionAuditLog() { last_link_.fill(0); }

    // Append an abort event; returns the new report (with computed link).
    AbortReport append(AbortReason reason, AbortContext ctx) {
        std::lock_guard<std::mutex> lg(mu_);
        AbortReport r = makeAbortReport(reason, std::move(ctx), last_link_);
        last_link_ = r.this_link;
        chain_.push_back(r);
        return r;
    }

    // Get the current chain (copy for external verification).
    std::vector<AbortReport> snapshot() const {
        std::lock_guard<std::mutex> lg(mu_);
        return chain_;
    }

    // Get the current head link (for callers passing prev_link into
    // ad-hoc makeAbortReport).
    std::array<uint8_t, 32> currentLink() const {
        std::lock_guard<std::mutex> lg(mu_);
        return last_link_;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lg(mu_);
        return chain_.size();
    }

private:
    mutable std::mutex mu_;
    std::vector<AbortReport> chain_;
    std::array<uint8_t, 32> last_link_;
};

// Higher-level: open with a shared audit log. Appends on failure automatically.
Result<uint64_t> openWithAuditLog(const AuthSharedU64& x,
                                    const SecureAlpha& alpha,
                                    const AbortContext& ctx,
                                    SessionAuditLog& log);

} // namespace mpsvs
} // namespace volePSI
