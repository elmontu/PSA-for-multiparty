#pragma once

// MPSVS Production Hygiene — CSPRNG + memzero + structured abort.
//
// Foundational hardening for moving MPSVS from demo to production:
//
//   1. CSPRNG: replace test PRNGs (oc::PRNG seeded from oc::block(0x1, 0x2))
//      with libsodium's randombytes_buf, which pulls from /dev/urandom.
//      All secret sampling in production paths MUST use these helpers.
//
//   2. sodium_memzero: sensitive values (SPDZ α, additive shares, MAC shares,
//      OPRF keys, DP noise samples) must be explicitly zeroed on scope exit.
//      Provided via SecureU64 / SecureBuffer RAII wrappers.
//
//   3. Structured abort: replace `bool openWithMacCheck` return with
//      Result<T, AbortReport> pattern. AbortReport carries:
//         - reason (enum: MAC_FAIL, DLEQ_FAIL, NIZK_FAIL, HASH_FAIL, ...)
//         - context (protocol phase, party, cell key)
//         - timestamp
//         - audit hash chain link
//      Callers can log to tamper-evident audit trail and trigger
//      admin-alert / release-abort protocol.

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// CSPRNG — libsodium-backed cryptographic randomness.
// ---------------------------------------------------------------------------

// Initialise libsodium (safe to call multiple times).
void ensureSodiumInit();

// Fill `buf` with `n` bytes from the system CSPRNG.
void secureRandBytes(void* buf, size_t n);

// Convenience: uniform u64 from CSPRNG.
uint64_t secureRandU64();

// Convenience: uniform integer in [0, upper). Uses libsodium's rejection
// sampler (avoids modulo bias).
uint64_t secureRandU64Bounded(uint64_t upper);

// ---------------------------------------------------------------------------
// SecureU64 — RAII wrapper that zeroes on destruction.
// ---------------------------------------------------------------------------

class SecureU64 {
public:
    SecureU64() : value_(0) {}
    explicit SecureU64(uint64_t v) : value_(v) {}
    ~SecureU64() { sodium_memzero(&value_, sizeof(value_)); }

    // Copy would defeat the zeroization guarantee — force explicit.
    SecureU64(const SecureU64&) = delete;
    SecureU64& operator=(const SecureU64&) = delete;

    SecureU64(SecureU64&& o) noexcept : value_(o.value_) {
        sodium_memzero(&o.value_, sizeof(o.value_));
    }
    SecureU64& operator=(SecureU64&& o) noexcept {
        if (this != &o) {
            sodium_memzero(&value_, sizeof(value_));
            value_ = o.value_;
            sodium_memzero(&o.value_, sizeof(o.value_));
        }
        return *this;
    }

    uint64_t get() const { return value_; }
    void set(uint64_t v) { value_ = v; }
    void zero() { sodium_memzero(&value_, sizeof(value_)); value_ = 0; }

private:
    uint64_t value_;
};

// ---------------------------------------------------------------------------
// SecureBuffer — RAII byte buffer with sodium_memzero on destruction.
// ---------------------------------------------------------------------------

class SecureBuffer {
public:
    explicit SecureBuffer(size_t n) : data_(new uint8_t[n]), size_(n) {
        std::memset(data_.get(), 0, n);
    }
    ~SecureBuffer() {
        if (data_) sodium_memzero(data_.get(), size_);
    }
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&&) = default;
    SecureBuffer& operator=(SecureBuffer&&) = default;

    uint8_t* data() { return data_.get(); }
    const uint8_t* data() const { return data_.get(); }
    size_t size() const { return size_; }

private:
    std::unique_ptr<uint8_t[]> data_;
    size_t size_;
};

// ---------------------------------------------------------------------------
// Structured abort — replaces bool return with rich failure context.
// ---------------------------------------------------------------------------

enum class AbortReason {
    NONE = 0,
    MAC_FAIL,            // SPDZ MAC check on opened share failed (17.1)
    SACRIFICE_FAIL,      // Beaver triple sacrifice check failed (17.1-ext)
    DLEQ_FAIL,           // OPRF partial DLEQ verify failed (17.3)
    NIZK_SHUFFLE_FAIL,   // BG shuffle NIZK verify failed (17.4)
    BIT_PROOF_FAIL,      // Chaum-Pedersen bit proof verify failed (17.5)
    RECIP_INVARIANT_FAIL,// y_fp · x ≠ 2^f algebraic check (17.6)
    DP_COMMIT_MISMATCH,  // DP commit-reveal SHA-256 mismatch (Phase 12)
    OLE_INVARIANT_FAIL,  // u·v ≠ w on OLE-generated triple (17.2)
};

const char* abortReasonName(AbortReason r);

struct AbortContext {
    std::string protocol_phase;   // e.g. "Phase 11 aggregation"
    uint32_t    party_id;         // which party detected the failure
    std::string cell_key;         // e.g. "sector=1 period=202601 metric=DTI"
    std::string extra_notes;
};

struct AbortReport {
    AbortReason  reason = AbortReason::NONE;
    AbortContext ctx;
    // Wall-clock (Unix nanos) at time of abort.
    uint64_t     timestamp_ns = 0;
    // Previous entry's SHA-256 (hash-chain anchor for tamper-evidence).
    std::array<uint8_t, 32> prev_link{};
    // SHA-256 over (reason || ctx || timestamp || prev_link).
    std::array<uint8_t, 32> this_link{};

    bool isAbort() const { return reason != AbortReason::NONE; }
};

// Build an AbortReport, computing this_link deterministically from
// (reason, ctx, timestamp, prev_link).
AbortReport makeAbortReport(AbortReason reason, AbortContext ctx,
                              const std::array<uint8_t, 32>& prev_link);

// Verify a link chain: for i > 0, report[i].prev_link == report[i-1].this_link
// AND each this_link matches SHA-256(reason || ctx || ts || prev_link).
bool verifyAbortChain(const std::vector<AbortReport>& chain);

// Result<T> — either a value or an AbortReport (production replacement
// for functions that currently return bool).
template<typename T>
struct Result {
    T value{};
    AbortReport abort;

    bool ok() const { return !abort.isAbort(); }
    static Result<T> makeValue(T v) { Result<T> r; r.value = std::move(v); return r; }
    static Result<T> makeAbort(AbortReport a) { Result<T> r; r.abort = std::move(a); return r; }
};

} // namespace mpsvs
} // namespace volePSI
