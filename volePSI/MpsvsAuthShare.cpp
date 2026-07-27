#include "MpsvsAuthShare.h"
#include "MpsvsProdHygiene.h"    // for secureRandU64 in batchOpenWithMacCheck

#include <sodium.h>

#include <array>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::addShared;
using mpstar::subShared;
using mpstar::mulConst;
using mpstar::secureMultiply;
using mpstar::shareU64;
using mpstar::generateBeaverTriple;

AlphaShare generateAlpha(uint32_t N, oc::PRNG& prng) {
    AlphaShare a;
    // Generate random α and additively share it. Reject any individual
    // α_i share that happens to be 0 — a 0 share is a boundary case for
    // the shared-α MAC-check protocol (σ_i degenerates to -m_i and does
    // not blind m_i in the reveal). Probability of hitting this is 2^-64
    // per party per generation, but resampling costs nothing.
    while (true) {
        uint64_t alpha_plain = prng.get<uint64_t>();
        if (alpha_plain == 0) continue;
        a.alpha_share = shareU64(N, alpha_plain, prng);
        bool any_zero = false;
        for (uint32_t i = 0; i < N; ++i)
            if (a.alpha_share.shares[i] == 0) { any_zero = true; break; }
        if (!any_zero) return a;
    }
}

AuthSharedU64 authShareU64(uint32_t N, uint64_t value, uint64_t alpha,
                            oc::PRNG& prng) {
    AuthSharedU64 x;
    x.value = shareU64(N, value, prng);
    // MAC is α·x — compute mac_plain = α · value, then share it.
    uint64_t mac_plain = alpha * value;   // mod 2^64
    x.mac = shareU64(N, mac_plain, prng);
    return x;
}

AuthSharedU64 authAdd(const AuthSharedU64& a, const AuthSharedU64& b) {
    AuthSharedU64 c;
    c.value = addShared(a.value, b.value);
    c.mac = addShared(a.mac, b.mac);
    return c;
}

AuthSharedU64 authSub(const AuthSharedU64& a, const AuthSharedU64& b) {
    AuthSharedU64 c;
    c.value = subShared(a.value, b.value);
    c.mac = subShared(a.mac, b.mac);
    return c;
}

AuthSharedU64 authAddConst(const AuthSharedU64& a, uint64_t c, uint64_t alpha) {
    // [x + c] = ([x] + c),  [α·(x+c)] = [α·x] + α·c
    AuthSharedU64 out = a;
    out.value.shares[0] += c;   // party 0 absorbs the public constant
    out.mac.shares[0]   += alpha * c;
    return out;
}

AuthSharedU64 authMulConst(const AuthSharedU64& a, uint64_t c) {
    // [c·x] = c·[x],   [α·(c·x)] = c·[α·x]  (both local mul by public c)
    AuthSharedU64 out;
    out.value = mulConst(a.value, c);
    out.mac = mulConst(a.mac, c);
    return out;
}

AuthBeaverTriple generateAuthBeaverTriple(uint32_t N, uint64_t alpha,
                                            oc::PRNG& prng) {
    // Sample u, v uniformly and compute w = u·v (mod 2^64), all authenticated.
    uint64_t u_plain = prng.get<uint64_t>();
    uint64_t v_plain = prng.get<uint64_t>();
    uint64_t w_plain = u_plain * v_plain;
    AuthBeaverTriple t;
    t.u = authShareU64(N, u_plain, alpha, prng);
    t.v = authShareU64(N, v_plain, alpha, prng);
    t.w = authShareU64(N, w_plain, alpha, prng);
    return t;
}

AuthSharedU64 authSecureMultiply(const AuthSharedU64& x,
                                   const AuthSharedU64& y,
                                   const AuthBeaverTriple& triple,
                                   uint64_t alpha) {
    // Standard Beaver mult on the VALUE component:
    //   d = x - u, e = y - v (both opened + MAC-verified)
    //   z = w + d·v + e·u + d·e
    //   MAC(z) = MAC(w) + d·MAC(v) + e·MAC(u) + α·d·e
    //
    // CRITICAL: openings of d and e MUST be MAC-verified. Without this,
    // a malicious party can tamper their share of x or y, and the tampering
    // propagates into d/e (which are used to compute both value AND MAC of z).
    // The resulting MAC on z is then "consistent" with the tampered value,
    // and the final open passes — attack succeeds silently.
    // On MAC-check failure on d or e, the caller aborts.
    AuthSharedU64 x_minus_u = authSub(x, triple.u);
    AuthSharedU64 y_minus_v = authSub(y, triple.v);
    uint64_t d = 0, e = 0;
    if (!openWithMacCheck(x_minus_u, alpha, d))
        throw AuthShareMacFailure(
            "authSecureMultiply: MAC check failed on opening of d = x - u "
            "— input share x or triple.u was tampered");
    if (!openWithMacCheck(y_minus_v, alpha, e))
        throw AuthShareMacFailure(
            "authSecureMultiply: MAC check failed on opening of e = y - v "
            "— input share y or triple.v was tampered");

    // Compute the value of z = w + d·v + e·u + d·e using the OPENED d, e.
    SharedU64 val_z = triple.w.value;
    val_z = addShared(val_z, mulConst(triple.v.value, d));
    val_z = addShared(val_z, mulConst(triple.u.value, e));
    val_z.shares[0] += d * e;   // public constant absorbed by party 0

    // Compute MAC of z: MAC(z) = MAC(w) + d·MAC(v) + e·MAC(u) + α·d·e.
    SharedU64 mac_z = triple.w.mac;
    mac_z = addShared(mac_z, mulConst(triple.v.mac, d));
    mac_z = addShared(mac_z, mulConst(triple.u.mac, e));
    mac_z.shares[0] += alpha * d * e;

    AuthSharedU64 z;
    z.value = val_z;
    z.mac = mac_z;
    return z;
}

AuthSharedU64 authSecureMultiplyShared(const AuthSharedU64& x,
                                          const AuthSharedU64& y,
                                          const AuthBeaverTriple& triple,
                                          const AlphaShare& alpha) {
    // Guard the topology: MPSVS fixes N=2 for compute nodes (S1, S2). The
    // sharewise α·d·e accumulation in the MAC below is only valid under
    // the 2-party additive-shares abstraction; extending to N>2 requires
    // a different Beaver-mult structure (cross-terms in the product).
    if (x.value.N() != 2 || y.value.N() != 2 ||
        triple.u.value.N() != 2 || triple.v.value.N() != 2 ||
        triple.w.value.N() != 2 || alpha.alpha_share.N() != 2) {
        throw std::runtime_error(
            "authSecureMultiplyShared: 2-party only (matches MPSVS S1/S2)");
    }
    // Same Beaver structure as authSecureMultiply but with shared-α opens
    // of the two intermediates d = x - u and e = y - v.
    //
    //   d = x - u,  e = y - v          (both opened + MAC-verified via
    //                                    openWithMacCheckShared — α stays shared)
    //   z = w + d·v + e·u + d·e
    //   MAC(z) = MAC(w) + d·MAC(v) + e·MAC(u) + α·d·e
    //
    // The last MAC term α·d·e is added SHAREWISE per party:
    //   party_i contributes α_i · d · e to its MAC share of z.
    // Reconstruction: sum over parties = (Σ α_i) · d · e = α · d · e. ✓
    AuthSharedU64 x_minus_u = authSub(x, triple.u);
    AuthSharedU64 y_minus_v = authSub(y, triple.v);
    uint64_t d = 0, e = 0;
    if (!openWithMacCheckShared(x_minus_u, alpha, d))
        throw AuthShareMacFailure(
            "authSecureMultiplyShared: MAC check failed on opening of d = x - u");
    if (!openWithMacCheckShared(y_minus_v, alpha, e))
        throw AuthShareMacFailure(
            "authSecureMultiplyShared: MAC check failed on opening of e = y - v");

    // Value component z = w + d·v + e·u + d·e (party 0 absorbs the constant d·e).
    SharedU64 val_z = triple.w.value;
    val_z = addShared(val_z, mulConst(triple.v.value, d));
    val_z = addShared(val_z, mulConst(triple.u.value, e));
    val_z.shares[0] += d * e;

    // MAC component: MAC(w) + d·MAC(v) + e·MAC(u) + α·d·e.
    // The α·d·e term is split across parties per their α_i share.
    SharedU64 mac_z = triple.w.mac;
    mac_z = addShared(mac_z, mulConst(triple.v.mac, d));
    mac_z = addShared(mac_z, mulConst(triple.u.mac, e));
    // Party i contributes α_i · d · e to its MAC share.
    for (uint32_t i = 0; i < mac_z.N(); ++i) {
        mac_z.shares[i] += alpha.alpha_share.shares[i] * d * e;
    }

    AuthSharedU64 z;
    z.value = val_z;
    z.mac   = mac_z;
    return z;
}

bool openWithMacCheck(const AuthSharedU64& x, uint64_t alpha, uint64_t& out) {
    uint64_t x_reconstructed = x.value.reconstruct();
    uint64_t mac_reconstructed = x.mac.reconstruct();
    uint64_t expected_mac = alpha * x_reconstructed;
    if (expected_mac != mac_reconstructed) {
        return false;   // MAC mismatch — dishonest tampering detected
    }
    out = x_reconstructed;
    return true;
}

// ---------------------------------------------------------------------------
// Shared-α MAC check (DPSZ §3.3). α is NEVER reconstructed.
//
// Protocol (2-party, honest-verifier / static-malicious):
//   1. Both parties open x_i and m_i (their MAC shares) → reconstruct x, m.
//      (This is the same public opening as openWithMacCheck.)
//   2. Each party locally computes σ_i = α_i · x - m_i.
//      Note: x is public now, so α_i · x reveals nothing about α_i since
//      α_i itself was uniformly random and unrelated to x's distribution.
//   3. Both parties commit to σ_i (SHA-256 of σ_i || salt_i), broadcast
//      commitments, THEN open. The commit prevents a party from choosing
//      σ_i adversarially after seeing the peer's σ_{-i}.
//   4. Sum σ_1 + σ_2 mod 2^64. Valid iff sum == 0.
//
// The correctness follows from:
//   σ_1 + σ_2 = (α_1 + α_2)·x - (m_1 + m_2) = α·x - m
// which is 0 iff m = α·x (honest MAC).
// ---------------------------------------------------------------------------

namespace {

// Serialise a u64 into 8 little-endian bytes.
void appendU64LE(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

// Compute SHA-256("mpsvs.audit" || LE64(party) || LE64(σ) || LE64(salt))
// per PROTOCOL.md Alg 12 line 4. The domain prefix binds the commit to the
// shared-α MAC-check context and prevents cross-protocol replay.
std::array<uint8_t, 32> commitSigma(uint32_t party, uint64_t sigma, uint64_t salt) {
    ensureSodiumInit();
    static const char kDomain[] = "mpsvs.audit";
    const size_t domain_len = sizeof(kDomain) - 1;   // exclude NUL

    std::vector<uint8_t> buf;
    buf.reserve(domain_len + 8 + 8 + 8);
    buf.insert(buf.end(), kDomain, kDomain + domain_len);
    appendU64LE(buf, party);
    appendU64LE(buf, sigma);
    appendU64LE(buf, salt);
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(), buf.data(), buf.size());
    return h;
}

} // namespace

// Per-party σ commit — computed locally by each party from its own α_i,
// its own MAC share, and the publicly-opened x. The commit is broadcast
// BEFORE any σ is revealed. In a wire-level impl this is a single message
// (party i → peer). Here we materialise both parties' local state and
// then enforce the ordering explicitly below.
using SigmaCommit = test_hooks::SigmaCommit;

static SigmaCommit computeSigmaCommit(uint32_t party,
                                        uint64_t alpha_i,
                                        uint64_t mac_i,
                                        uint64_t x_rec) {
    SigmaCommit s;
    s.party = party;
    s.sigma = alpha_i * x_rec - mac_i;
    s.salt  = secureRandU64();
    s.commit = commitSigma(party, s.sigma, s.salt);
    return s;
}

// Given a party's revealed (σ, salt) and the pre-commit received from that
// party, verify the reveal matches the commit. This is the check that
// binds the party to what it committed BEFORE seeing the peer's σ.
static bool verifySigmaReveal(const SigmaCommit& revealed,
                                const std::array<uint8_t, 32>& expected_commit) {
    // sodium_memcmp for CT compare.
    std::array<uint8_t, 32> recomputed = commitSigma(
        revealed.party, revealed.sigma, revealed.salt);
    return sodium_memcmp(recomputed.data(), expected_commit.data(),
                            32) == 0;
}

bool openWithMacCheckShared(const AuthSharedU64& x,
                              const AlphaShare& alpha,
                              uint64_t& out) {
    if (x.value.N() != 2 || alpha.alpha_share.N() != 2) {
        throw std::runtime_error(
            "openWithMacCheckShared: 2-party only (matches MPSVS S1/S2)");
    }
    // 1. Reconstruct x publicly (both parties' value shares broadcast).
    uint64_t x_rec = x.value.reconstruct();

    // 2. PHASE A — each party locally computes (σ_i, salt_i, commit_i).
    //    In wire form: party i does NOT send σ_i or salt_i yet — only commit_i.
    SigmaCommit s1 = computeSigmaCommit(1, alpha.alpha_share.shares[0],
                                            x.mac.shares[0], x_rec);
    SigmaCommit s2 = computeSigmaCommit(2, alpha.alpha_share.shares[1],
                                            x.mac.shares[1], x_rec);

    // 3. PHASE B — commits exchanged. In this in-process reference we take
    //    snapshots of both commits BEFORE reveal, so any post-commit change
    //    to σ or salt fails verify. This mirrors the wire ordering where
    //    party 1 sends c1 to party 2 (and vice versa) BEFORE reveal.
    std::array<uint8_t, 32> commit_of_s1 = s1.commit;
    std::array<uint8_t, 32> commit_of_s2 = s2.commit;

    // 4. PHASE C — reveal σ and salt. Each side verifies the peer's reveal
    //    matches the earlier commit (binding).
    if (!verifySigmaReveal(s1, commit_of_s1)) return false;
    if (!verifySigmaReveal(s2, commit_of_s2)) return false;

    // 5. PHASE D — sum σ_1 + σ_2 mod 2^64.  Valid iff sum == 0
    //    (equivalently: (α_1 + α_2)·x - (m_1 + m_2) = α·x - m = 0).
    if ((s1.sigma + s2.sigma) != 0) return false;

    out = x_rec;
    return true;
}

// Test-only hook: exposes the per-party σ commit path so an adversarial
// test can prove that tampering AFTER commit-issue but BEFORE reveal
// is caught (the tamper wins the reveal race in a naïve impl).
namespace test_hooks {

SigmaCommit computeSigmaCommitForTest(uint32_t party,
                                         uint64_t alpha_i,
                                         uint64_t mac_i,
                                         uint64_t x_rec) {
    return computeSigmaCommit(party, alpha_i, mac_i, x_rec);
}

bool verifySigmaRevealForTest(const SigmaCommit& revealed,
                                const std::array<uint8_t, 32>& expected_commit) {
    return verifySigmaReveal(revealed, expected_commit);
}

} // namespace test_hooks

// Derive Ω-check challenges r_j = H("mpsvs.omega.r" || j || transcript)_j
// where transcript = SHA-256 over all (value_shares_j, mac_shares_j).
//
// Property required for soundness: r_j must be unpredictable to any
// adversary who has not yet committed to their shares. Fiat-Shamir over
// the shares themselves gives this: an adversary who wants to game r_j
// would need to find a share configuration whose transcript hash produces
// their desired r_j — a preimage attack on SHA-256.
//
// Note: this is stronger than sampling r_j locally on one party (which
// lets the OTHER party choose shares after seeing r_j) and matches the
// standard DPSZ 2012 Ω-check construction.
static std::vector<uint64_t> deriveOmegaChallenges(
        const std::vector<AuthSharedU64>& xs) {
    ensureSodiumInit();
    // Build transcript = SHA-256 over concatenated shares of all elements.
    std::vector<uint8_t> transcript;
    transcript.reserve(xs.size() * 4 * 8);
    for (const auto& x : xs) {
        for (uint32_t i = 0; i < x.value.N(); ++i) {
            appendU64LE(transcript, x.value.shares[i]);
            appendU64LE(transcript, x.mac.shares[i]);
        }
    }
    std::array<uint8_t, 32> tr_hash;
    crypto_hash_sha256(tr_hash.data(), transcript.data(), transcript.size());

    // Derive r_j = SHA-256("mpsvs.omega.r" || j_le || tr_hash)_first-8-bytes.
    // Reject r_j = 0 (would nullify that element's contribution).
    std::vector<uint64_t> rs(xs.size());
    for (size_t j = 0; j < xs.size(); ++j) {
        std::vector<uint8_t> input;
        static const char dom[] = "mpsvs.omega.r";
        input.insert(input.end(), dom, dom + sizeof(dom) - 1);
        appendU64LE(input, static_cast<uint64_t>(j));
        input.insert(input.end(), tr_hash.begin(), tr_hash.end());
        std::array<uint8_t, 32> h;
        crypto_hash_sha256(h.data(), input.data(), input.size());
        uint64_t r = 0;
        for (int b = 0; b < 8; ++b)
            r |= (static_cast<uint64_t>(h[b]) << (8 * b));
        if (r == 0) r = 1;   // avoid nulling this element's check
        rs[j] = r;
    }
    return rs;
}

bool batchOpenWithMacCheckShared(const std::vector<AuthSharedU64>& xs,
                                    const AlphaShare& alpha,
                                    std::vector<uint64_t>& out) {
    if (alpha.alpha_share.N() != 2) {
        throw std::runtime_error(
            "batchOpenWithMacCheckShared: 2-party only");
    }
    for (const auto& x : xs) {
        if (x.value.N() != 2) {
            throw std::runtime_error(
                "batchOpenWithMacCheckShared: element must be 2-party");
        }
    }

    // Derive the r_j vector BEFORE any reconstruction — this fixes r_j
    // deterministically against the shares, so a tampering adversary
    // cannot adaptively choose shares based on r_j.
    std::vector<uint64_t> rs = deriveOmegaChallenges(xs);

    out.clear();
    out.reserve(xs.size());
    AuthSharedU64 combined;
    combined.value = SharedU64(2);
    combined.mac   = SharedU64(2);
    for (size_t j = 0; j < xs.size(); ++j) {
        const AuthSharedU64& x = xs[j];
        const uint64_t r = rs[j];
        // Per-element reconstruction — value opens to caller (populates out).
        const uint64_t val = x.value.reconstruct();
        // Add r·x_i and r·m_i to the combined shares.
        combined.value.shares[0] += r * x.value.shares[0];
        combined.value.shares[1] += r * x.value.shares[1];
        combined.mac.shares[0]   += r * x.mac.shares[0];
        combined.mac.shares[1]   += r * x.mac.shares[1];
        out.push_back(val);
    }
    // Combined shared-α check: openWithMacCheckShared enforces the full
    // commit/reveal ordering + σ check on the batched combination.
    uint64_t dummy = 0;
    return openWithMacCheckShared(combined, alpha, dummy);
}

void simulateTampering(AuthSharedU64& x, uint32_t bad_party,
                       uint64_t tamper_amount) {
    if (bad_party >= x.value.N())
        throw std::invalid_argument("bad_party out of range");
    x.value.shares[bad_party] += tamper_amount;
    // Note: the attacker CANNOT also correctly adjust the MAC share without
    // knowing α. This is why the MAC check catches the tampering.
}

// ---------------------------------------------------------------------------
// Phase 17.1-ext: Batched MAC check (SPDZ Ω-check style).
// ---------------------------------------------------------------------------
bool batchOpenWithMacCheck(const std::vector<AuthSharedU64>& xs,
                            uint64_t alpha,
                            std::vector<uint64_t>& out,
                            oc::PRNG& prng) {
    out.clear();
    out.reserve(xs.size());
    // Reconstruct each value; also compute the batched combination [Σ r_i·x_i]
    // and its MAC [Σ r_i·(α·x_i)].
    // SECURITY: `r` must be sampled from a CSPRNG (not oc::PRNG which may be
    // seeded from test bytes). Attacker who predicts r can craft tampered
    // shares that pass the batch check. See Rev 7 §17.7.
    uint64_t combined_val = 0;
    uint64_t combined_mac = 0;
    (void)prng;   // legacy arg kept for API compat; not used for r sampling
    for (const auto& x : xs) {
        uint64_t r = secureRandU64();   // CSPRNG via libsodium (crypto)
        uint64_t val = x.value.reconstruct();
        uint64_t mac = x.mac.reconstruct();
        combined_val += r * val;
        combined_mac += r * mac;
        out.push_back(val);
    }
    // Check α · Σ r_i·x_i == Σ r_i·(α·x_i)  ⇔ α · combined_val == combined_mac.
    uint64_t expected = alpha * combined_val;
    return expected == combined_mac;
}

// ---------------------------------------------------------------------------
// Phase 17.1-ext: SPDZ sacrifice check.
// ---------------------------------------------------------------------------

// Local subtract for AuthSharedU64 with public multiplier on a shared value.
// Compute [r·x - y] where r is public, x, y are auth shares.
static AuthSharedU64 rXSubY(uint64_t r, const AuthSharedU64& x,
                              const AuthSharedU64& y) {
    AuthSharedU64 out;
    out.value = subShared(mulConst(x.value, r), y.value);
    out.mac   = subShared(mulConst(x.mac, r),   y.mac);
    return out;
}

// [α'·x - y] where α' is a public multiplier on x, y are auth shares.
static AuthSharedU64 authSubPubMulValue(uint64_t r_a, const AuthSharedU64& c,
                                          uint64_t sigma_pub, const AuthSharedU64& a_prime,
                                          uint64_t rho_pub,   const AuthSharedU64& b_prime,
                                          const AuthSharedU64& c_prime) {
    // Compute [r·c - c' - σ·a' - ρ·b']  — all linear, no Beaver needed.
    AuthSharedU64 rc = authMulConst(c, r_a);
    AuthSharedU64 sa = authMulConst(a_prime, sigma_pub);
    AuthSharedU64 rb = authMulConst(b_prime, rho_pub);
    AuthSharedU64 tmp = authSub(rc, c_prime);
    tmp = authSub(tmp, sa);
    tmp = authSub(tmp, rb);
    return tmp;
}

bool sacrificeCheckTriple(const AuthBeaverTriple& T,
                            const AuthBeaverTriple& T_aux,
                            uint64_t alpha,
                            oc::PRNG& /*prng*/) {
    // Sample public random challenge from CSPRNG (not the deterministic test
    // PRNG). The public random coefficient r gates the sacrifice-check
    // soundness (probability of undetected forgery = 1/|F|), so r MUST be
    // sampled unpredictably to the adversary.
    uint64_t r = secureRandU64();
    if (r == 0) r = 1;

    // [ρ] = r·[a] - [a']
    AuthSharedU64 rho_shared = rXSubY(r, T.u, T_aux.u);
    // [σ] = [b] - [b']  (r=1 case of rXSubY)
    AuthSharedU64 sigma_shared = rXSubY(1, T.v, T_aux.v);

    // Open ρ, σ with MAC verification.
    uint64_t rho = 0, sigma = 0;
    if (!openWithMacCheck(rho_shared, alpha, rho)) return false;
    if (!openWithMacCheck(sigma_shared, alpha, sigma)) return false;

    // [τ] = r·[c] - [c'] - σ·[a'] - ρ·[b']
    AuthSharedU64 tau_shared = authSubPubMulValue(r, T.w, sigma, T_aux.u,
                                                     rho, T_aux.v, T_aux.w);

    // Open τ with MAC check, verify τ == ρ·σ.
    uint64_t tau = 0;
    if (!openWithMacCheck(tau_shared, alpha, tau)) return false;
    uint64_t expected = rho * sigma;
    return tau == expected;
}

bool sacrificeCheckTripleShared(const AuthBeaverTriple& T,
                                   const AuthBeaverTriple& T_aux,
                                   const AlphaShare& alpha) {
    // Same protocol as sacrificeCheckTriple but every intermediate open
    // uses openWithMacCheckShared → α is never reconstructed.
    uint64_t r = secureRandU64();
    if (r == 0) r = 1;

    AuthSharedU64 rho_shared   = rXSubY(r, T.u, T_aux.u);
    AuthSharedU64 sigma_shared = rXSubY(1, T.v, T_aux.v);

    uint64_t rho = 0, sigma = 0;
    if (!openWithMacCheckShared(rho_shared,   alpha, rho))   return false;
    if (!openWithMacCheckShared(sigma_shared, alpha, sigma)) return false;

    AuthSharedU64 tau_shared = authSubPubMulValue(r, T.w, sigma, T_aux.u,
                                                     rho, T_aux.v, T_aux.w);
    uint64_t tau = 0;
    if (!openWithMacCheckShared(tau_shared, alpha, tau)) return false;
    return tau == rho * sigma;
}

// Malformed triple: (u, v, w') where w' = u·v + w_offset. Simulates a
// malicious dealer distributing wrong triples.
AuthBeaverTriple generateMalformedBeaverTriple(uint32_t N, uint64_t alpha,
                                                  uint64_t w_offset,
                                                  oc::PRNG& prng) {
    uint64_t u_plain = prng.get<uint64_t>();
    uint64_t v_plain = prng.get<uint64_t>();
    uint64_t w_correct = u_plain * v_plain;
    uint64_t w_bad = w_correct + w_offset;   // maliciously offset
    AuthBeaverTriple t;
    t.u = authShareU64(N, u_plain, alpha, prng);
    t.v = authShareU64(N, v_plain, alpha, prng);
    t.w = authShareU64(N, w_bad, alpha, prng);
    return t;
}

} // namespace mpsvs
} // namespace volePSI
