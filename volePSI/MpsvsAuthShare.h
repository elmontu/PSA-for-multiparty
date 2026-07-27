#pragma once

// MPSVS Phase 17.1 — MAC-authenticated shares (SPDZ-style).
//
// FOUNDATIONAL malicious-security primitive: every additive share carries a
// MAC that is checked on open. Detects any dishonest party that tampers with
// its share before broadcasting.
//
// Design (SPDZ, Damgård-Pastro-Smart-Zakarias 2012):
//   Global secret α ∈ Z_{2^k} is shared additively between S1 and S2.
//   Each authenticated share is a pair:
//     AuthSharedU64 x = ([x], [α·x])
//   where [x] is the additive share of x, and [α·x] is the additive share
//   of α·x.
//
// Operations preserving MAC:
//   x + y            : ([x] + [y], [α·x] + [α·y])                  (local)
//   x + c (public)   : ([x] + c, [α·x] + α·c)                     (local, need α public shares)
//   c · x (public)   : (c·[x], c·[α·x])                            (local)
//   x · y            : Beaver triple with authenticated triple    (1 auth Beaver triple)
//
// Open with MAC check:
//   Party i broadcasts (x_i, α·x_i shares).
//   Compute x = Σ x_i, MAC = Σ α·x_i.
//   Compute α = Σ α_i (via a commit-reveal of α).
//   Verify α · x == MAC. If not: ABORT.
//
// Security: catches ANY tampering by ≤ n-1 corrupt parties (SPDZ standard).
// A dishonest party cannot forge a valid (x', α·x') for x' ≠ true x without
// knowing α — but α is shared, so no one party knows it.
//
// This module implements the semi-honest CORE (the MAC check + arithmetic).
// The α-generation (via secure sampling) is treated as a public setup step
// for the prototype; production must use OLE-based α generation
// (Bendlin-Damgård-Orlandi-Zakarias 2011).

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleU64;
using mpstar::SharedU64;

// Exception thrown by malicious-secure ops (e.g. authSecureMultiply) when
// a MAC check on an intermediate opening fails. Callers should treat as a
// hard abort — protocol state is not recoverable.
class AuthShareMacFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---------------------------------------------------------------------------
// AuthSharedU64 — pair of ([x], [α·x]) additive shares.
// ---------------------------------------------------------------------------

struct AuthSharedU64 {
    SharedU64 value;    // [x] additive share of the value
    SharedU64 mac;      // [α·x] additive share of the MAC

    uint32_t N() const { return value.N(); }
};

// Global α is a public setup parameter shared additively.
// For prototype: generate α once, distribute shares to parties.
struct AlphaShare {
    SharedU64 alpha_share;   // each party holds its share
};

AlphaShare generateAlpha(uint32_t N, oc::PRNG& prng);

// Create an authenticated share from a plaintext value.
// Requires knowing α (or its shares) so [α·x] can be constructed.
// In the prototype, this is done at the trusted setup boundary.
AuthSharedU64 authShareU64(uint32_t N, uint64_t value, uint64_t alpha,
                            oc::PRNG& prng);

// Local operations preserving MAC.
AuthSharedU64 authAdd(const AuthSharedU64& a, const AuthSharedU64& b);
AuthSharedU64 authSub(const AuthSharedU64& a, const AuthSharedU64& b);
AuthSharedU64 authAddConst(const AuthSharedU64& a, uint64_t c, uint64_t alpha);
AuthSharedU64 authMulConst(const AuthSharedU64& a, uint64_t c);

// Authenticated Beaver triple: (u, v, w) where w = u·v, all authenticated.
struct AuthBeaverTriple {
    AuthSharedU64 u, v, w;
};
AuthBeaverTriple generateAuthBeaverTriple(uint32_t N, uint64_t alpha,
                                            oc::PRNG& prng);

// Secure multiplication of authenticated shares (plaintext-α legacy path).
// Consumes one auth triple.
AuthSharedU64 authSecureMultiply(const AuthSharedU64& x,
                                   const AuthSharedU64& y,
                                   const AuthBeaverTriple& triple,
                                   uint64_t alpha);

// Malicious-secure Beaver mult using shared-α. d = x - u and e = y - v are
// each opened via openWithMacCheckShared (α never reconstructed) before
// being used to combine w, u, v into z. On any MAC-check failure this
// throws AuthShareMacFailure.
//
// The output z carries a valid ([z], [α·z]) authentication under the same
// α_share, so downstream ops (including further Beaver mults) can be
// chained. To open z with malicious security, use openWithMacCheckShared.
AuthSharedU64 authSecureMultiplyShared(const AuthSharedU64& x,
                                          const AuthSharedU64& y,
                                          const AuthBeaverTriple& triple,
                                          const AlphaShare& alpha);

// ---------------------------------------------------------------------------
// Open with MAC verification.
//
// SECURITY-MODEL NOTES on the α parameter:
//
//  - `openWithMacCheck(x, uint64_t alpha, out)` — SEMI-HONEST / SINGLE-
//    VERIFIER model. The caller MUST possess α as a plaintext scalar. This
//    is the legacy signature and matches the trusted-verifier setting where
//    one party (auditor / GovTech) reconstructs α at release time. It is
//    NOT the standard-SPDZ malicious model.
//
//  - `openWithMacCheckShared(x, α_share, out)` — MALICIOUS 2-party model
//    per Damgård-Pastro-Smart-Zakarias 2012 §3.3. α is kept additively
//    shared across S1 and S2 for the entire session; neither party ever
//    holds α in plaintext. Each party locally computes σ_i = α_i·x - m_i,
//    then commits + opens σ_i (the commit-then-open prevents an adversary
//    from choosing its σ_i to cancel σ_{-i}). The MAC is valid iff
//    σ_1 + σ_2 = 0.  This is the correct primitive for a fully-malicious
//    S1 vs. S2 threat model.
//
// Choose the shared-α variant for any deployment where a malicious S1
// (independent of S2) is in scope. The plaintext-α variant remains as
// legacy for tests and single-verifier ceremonies.
// ---------------------------------------------------------------------------
bool openWithMacCheck(const AuthSharedU64& x, uint64_t alpha, uint64_t& out);

// DPSZ-style MAC check with α kept shared. σ_1 + σ_2 opens to 0 iff the
// MAC is valid; neither party ever holds α in plaintext.
//
// Threat model: honest-verifier / static-malicious adversary controlling
// exactly one of {S1, S2}. Sound with probability 1 - 2^{-64} over the
// random challenge, matching the SPDZ Ω-check bound.
//
// Inputs:
//   x        — the (2-party) authenticated share to open+verify
//   alpha    — an AlphaShare containing (α_1, α_2) as SharedU64 (only the
//              party's own entry α_i is used locally)
//   out      — populated with the reconstructed x iff MAC verifies
// Returns true iff σ_1 + σ_2 = 0 (MAC valid).
bool openWithMacCheckShared(const AuthSharedU64& x,
                              const AlphaShare& alpha,
                              uint64_t& out);

// Batched shared-α variant matching openWithMacCheckShared's threat model.
//
// Ω-check challenge derivation: r_j = SHA-256("mpsvs.omega.r" || j || tag),
// where `tag` is a Fiat-Shamir transcript over all reconstructed x_j and
// their MAC shares. This makes r_j deterministic given the transcript and
// unpredictable to any adversary who has not yet committed to their
// shares. A single-party CSPRNG sample is INSUFFICIENT for the Ω-check
// soundness bound — see comments in the implementation.
bool batchOpenWithMacCheckShared(const std::vector<AuthSharedU64>& xs,
                                    const AlphaShare& alpha,
                                    std::vector<uint64_t>& out);

// Test-only hook types for adversarial commit-reveal tests.
namespace test_hooks {

struct SigmaCommit {
    uint32_t                party;
    uint64_t                sigma;
    uint64_t                salt;
    std::array<uint8_t, 32> commit;
};

SigmaCommit computeSigmaCommitForTest(uint32_t party,
                                         uint64_t alpha_i,
                                         uint64_t mac_i,
                                         uint64_t x_rec);
bool verifySigmaRevealForTest(const SigmaCommit& revealed,
                                const std::array<uint8_t, 32>& expected_commit);

} // namespace test_hooks

// Test-only: simulate a dishonest party corrupting a share.
// modifies x.value.shares[bad_party] by adding tamper_amount.
void simulateTampering(AuthSharedU64& x, uint32_t bad_party,
                       uint64_t tamper_amount);

// ---------------------------------------------------------------------------
// Malicious-detection audit summary.
// ---------------------------------------------------------------------------
struct MacAuditResult {
    int total_opens;
    int mac_check_pass;
    int mac_check_fail;   // dishonest tampering caught
};

// ---------------------------------------------------------------------------
// Phase 17.1-ext: Batched MAC check (SPDZ Ω-check).
// Instead of verifying MACs on N openings separately, sample public
// coefficients r_1, ..., r_N and check MAC(Σ r_i · x_i). Catches any
// tampering in the batch with probability 1 - 1/2^k for k-bit r.
// ---------------------------------------------------------------------------
bool batchOpenWithMacCheck(const std::vector<AuthSharedU64>& xs,
                            uint64_t alpha,
                            std::vector<uint64_t>& out,
                            oc::PRNG& prng);

// ---------------------------------------------------------------------------
// Phase 17.1-ext: SPDZ Sacrifice check for Beaver triples.
// Given triple T = (a, b, c) claimed to satisfy c = a·b, and auxiliary
// triple T' = (a', b', c'), verify T is correct by:
//   1. Sample random public r
//   2. Compute [ρ] = r·[a] - [a']; open ρ (MAC-verified)
//   3. Compute [σ] = [b] - [b']; open σ (MAC-verified)
//   4. Compute [τ] = r·[c] - [c'] - σ·[a'] - ρ·[b']; open τ (MAC-verified)
//   5. Check τ == ρ·σ
// If either T or T' is malformed, check fails with prob 1 - 1/2^k.
// Consumes both triples; returns TRUE if T verified correct.
bool sacrificeCheckTriple(const AuthBeaverTriple& T,
                            const AuthBeaverTriple& T_aux,
                            uint64_t alpha,
                            oc::PRNG& prng);

// Shared-α variant of the sacrifice check. Uses openWithMacCheckShared for
// each of the three intermediate opens (ρ, σ, τ), so α is never
// reconstructed. Same probability bound (1 - 1/2^k), correct for the
// standard SPDZ malicious model.
bool sacrificeCheckTripleShared(const AuthBeaverTriple& T,
                                   const AuthBeaverTriple& T_aux,
                                   const AlphaShare& alpha);

// Test-only: create an INTENTIONALLY MALFORMED Beaver triple (w ≠ u·v).
// Used to test that sacrifice check catches malicious dealers.
AuthBeaverTriple generateMalformedBeaverTriple(uint32_t N, uint64_t alpha,
                                                  uint64_t w_offset,
                                                  oc::PRNG& prng);

} // namespace mpsvs
} // namespace volePSI
