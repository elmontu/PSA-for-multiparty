#pragma once

// MPSVS Constant-Time Primitives.
//
// Comparison and multiplex operations that produce results independent of
// secret bit patterns. Used in code paths where a data-dependent branch would
// leak secret data through timing side channels — e.g. MUX in MPC-evaluated
// comparators, k-anonymity threshold checks on secret share counts, MAC
// verification of opened values.
//
// Threat model: attacker with wall-clock timing observation over many
// invocations. These primitives eliminate the data-dependent branch and
// data-dependent memory access; they do NOT defend against a physical
// side-channel adversary (power analysis, EM, cache probing on shared
// hardware).
//
// Implementation notes:
//   - All ct* functions compile to straight-line arithmetic on modern
//     compilers (gcc/clang -O2 verified). We deliberately do not use `?:`
//     which some compilers lower to a conditional branch on some ISAs.
//   - Byte-buffer compares delegate to libsodium's `sodium_memcmp` which
//     provides a documented CT guarantee.
//   - We deliberately do not use `volatile` on locals — GCC/Clang do not
//     currently re-derive branches from these arithmetic sequences at any
//     supported optimisation level. If a future compiler regresses, wrap
//     the mask derivation in a `volatile` load and re-audit.

#include <sodium.h>

#include <cstdint>
#include <cstddef>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// 1-bit CT primitives (returned as uint64_t 0 or 1).
// ---------------------------------------------------------------------------

// Returns 1 iff a == b, 0 otherwise. No branch on the difference.
inline uint64_t ctEqU64(uint64_t a, uint64_t b) {
    uint64_t d = a ^ b;                       // 0 iff equal
    // d == 0 → high bit of (d - 1) is 1; d != 0 → some bit set → OR-reduce
    // to bit 0. We use the fact that -(d != 0) is 0 or ~0.
    uint64_t x = d;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    return (x & 1ULL) ^ 1ULL;                 // 0 → 1, nonzero → 0
}

inline uint64_t ctNeqU64(uint64_t a, uint64_t b) {
    return ctEqU64(a, b) ^ 1ULL;
}

// Returns 1 iff a < b (unsigned), else 0. Branch-free.
//
// Formula:  lt = ((~a & b) | (~(a ^ b) & (a - b))) >> 63
//
// Derivation: the sign bit of the "borrow-out" of unsigned subtraction
// is set iff a < b. The two OR-terms cover the two cases where a - b
// borrows:
//   - `~a & b` catches the case where they differ in the high bit
//     (a's high bit clear, b's high bit set → a definitely < b).
//   - `~(a ^ b) & (a - b)` catches the case where they agree in the
//     high bit — then the borrow propagates all the way up and lands
//     as the sign bit of (a - b).
inline uint64_t ctLtU64(uint64_t a, uint64_t b) {
    return ((~a & b) | (~(a ^ b) & (a - b))) >> 63;
}

inline uint64_t ctLeU64(uint64_t a, uint64_t b) {
    // a <= b  ↔  !(b < a)
    return ctLtU64(b, a) ^ 1ULL;
}

inline uint64_t ctGtU64(uint64_t a, uint64_t b) { return ctLtU64(b, a); }
inline uint64_t ctGeU64(uint64_t a, uint64_t b) { return ctLeU64(b, a); }

// ---------------------------------------------------------------------------
// Multiplex — select between two values with a 0/1 mask, no branch.
// ---------------------------------------------------------------------------

// Returns (sel ? a : b). Only the low bit of `sel` is inspected — any
// value with bit 0 set selects `a`, otherwise `b`. This is deliberately
// defensive: callers occasionally pass raw comparison results (e.g. the
// low bit of a subtraction) which may have upper bits set.
inline uint64_t ctMuxU64(uint64_t sel, uint64_t a, uint64_t b) {
    uint64_t s = sel & 1ULL;
    uint64_t mask = 0ULL - s;                 // 0 → 0, 1 → 0xFFFF...
    return b ^ (mask & (a ^ b));
}

// ---------------------------------------------------------------------------
// Byte-buffer compares.
// ---------------------------------------------------------------------------

// Returns 1 iff (a[0..n) == b[0..n)), 0 otherwise. CT guarantee from
// libsodium's sodium_memcmp. Length parameter is not secret.
inline int ctMemcmpEq(const void* a, const void* b, size_t n) {
    return sodium_memcmp(a, b, n) == 0 ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Signed comparisons (interpret uint64_t as int64_t via two's-complement).
// ---------------------------------------------------------------------------

// Returns 1 iff (int64_t)a < (int64_t)b, else 0. Uses the fact that signed <
// = unsigned < after flipping the sign bit.
inline uint64_t ctLtI64(int64_t a, int64_t b) {
    uint64_t ua = static_cast<uint64_t>(a) ^ (1ULL << 63);
    uint64_t ub = static_cast<uint64_t>(b) ^ (1ULL << 63);
    return ctLtU64(ua, ub);
}

// ---------------------------------------------------------------------------
// Sensitivity attestation — asserts that expected CT primitives are
// available. Meant for a startup check.
// ---------------------------------------------------------------------------

// Verifies at runtime that the CT primitives produce correct results across
// a small set of edge inputs. Returns empty string on success; error message
// otherwise. Callers should treat a nonempty return as a fatal init failure.
const char* ctSelfCheck();

} // namespace mpsvs
} // namespace volePSI
