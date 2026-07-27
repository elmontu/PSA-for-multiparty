#include "MpsvsAuthShare128.h"

#include <sodium.h>

#include <array>
#include <cstring>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Ring helpers
// ---------------------------------------------------------------------------

static inline u128 modRing(u128 v) { return v & kSpdz2kRingMask; }

// Serialise a u128 to 16 bytes little-endian for hashing / wire format.
static void appendU128LE(std::vector<uint8_t>& out, u128 v) {
    for (int i = 0; i < 16; ++i)
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

// Uniform sample from ℤ_{2^{144}} using CSPRNG.
static u128 secureRandU128() {
    uint8_t buf[16];
    secureRandBytes(buf, 16);
    u128 v = 0;
    for (int i = 15; i >= 0; --i) {
        v = (v << 8) | buf[i];
    }
    return modRing(v);
}

// ---------------------------------------------------------------------------
// SharedU128 basics
// ---------------------------------------------------------------------------

SharedU128 shareU128(uint32_t N, u128 value) {
    SharedU128 out(N);
    value = modRing(value);
    u128 sum = 0;
    for (uint32_t i = 1; i < N; ++i) {
        out.shares[i] = secureRandU128();
        sum += out.shares[i];
    }
    out.shares[0] = modRing(value - sum);
    return out;
}

SharedU128 addShared128(const SharedU128& a, const SharedU128& b) {
    if (a.N() != b.N())
        throw std::runtime_error("addShared128: N mismatch");
    SharedU128 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i)
        out.shares[i] = modRing(a.shares[i] + b.shares[i]);
    return out;
}

SharedU128 subShared128(const SharedU128& a, const SharedU128& b) {
    if (a.N() != b.N())
        throw std::runtime_error("subShared128: N mismatch");
    SharedU128 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i)
        out.shares[i] = modRing(a.shares[i] - b.shares[i]);
    return out;
}

SharedU128 mulConst128(const SharedU128& a, u128 c) {
    c = modRing(c);
    SharedU128 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i)
        out.shares[i] = modRing(a.shares[i] * c);
    return out;
}

SharedU128 addConst128(const SharedU128& a, u128 c) {
    c = modRing(c);
    SharedU128 out = a;
    out.shares[0] = modRing(out.shares[0] + c);
    return out;
}

// ---------------------------------------------------------------------------
// AuthSharedU128 local ops (MAC preserved by linearity)
// ---------------------------------------------------------------------------

AuthSharedU128 authAdd128(const AuthSharedU128& a, const AuthSharedU128& b) {
    AuthSharedU128 c;
    c.value = addShared128(a.value, b.value);
    c.mac   = addShared128(a.mac,   b.mac);
    return c;
}

AuthSharedU128 authSub128(const AuthSharedU128& a, const AuthSharedU128& b) {
    AuthSharedU128 c;
    c.value = subShared128(a.value, b.value);
    c.mac   = subShared128(a.mac,   b.mac);
    return c;
}

AuthSharedU128 authMulConst128(const AuthSharedU128& a, u128 c) {
    AuthSharedU128 out;
    out.value = mulConst128(a.value, c);
    out.mac   = mulConst128(a.mac,   c);
    return out;
}

// ---------------------------------------------------------------------------
// α generation
// ---------------------------------------------------------------------------

AlphaShare128 generateAlpha128(uint32_t N) {
    ensureSodiumInit();
    AlphaShare128 out;
    while (true) {
        u128 alpha = secureRandU128();
        if (alpha == 0) continue;
        out.alpha_share = shareU128(N, alpha);
        bool any_zero = false;
        for (uint32_t i = 0; i < N; ++i)
            if (out.alpha_share.shares[i] == 0) { any_zero = true; break; }
        if (!any_zero) return out;
    }
}

AuthSharedU128 authShareU128(uint32_t N, u128 value,
                              const AlphaShare128& alpha) {
    AuthSharedU128 out;
    value = modRing(value);
    u128 alpha_recon = alpha.alpha_share.reconstruct();
    u128 mac = modRing(alpha_recon * value);
    out.value = shareU128(N, value);
    out.mac   = shareU128(N, mac);
    return out;
}

AuthBeaverTriple128 generateAuthBeaverTriple128(uint32_t N,
                                                  const AlphaShare128& alpha) {
    // Test-only: reconstruct α + sample u, v, compute w = u·v mod 2^k
    // (extended into full ring so all shares live in ℤ_{2^{144}}).
    AuthBeaverTriple128 t;
    u128 u_plain = secureRandU128();
    u128 v_plain = secureRandU128();
    u128 w_plain = modRing(u_plain * v_plain);
    t.u = authShareU128(N, u_plain, alpha);
    t.v = authShareU128(N, v_plain, alpha);
    t.w = authShareU128(N, w_plain, alpha);
    return t;
}

// ---------------------------------------------------------------------------
// DPSZ2k σ-commit helper
// ---------------------------------------------------------------------------

namespace {

std::array<uint8_t, 32> commitSigma128(uint32_t party, u128 sigma, u128 salt) {
    ensureSodiumInit();
    static const char kDomain[] = "mpsvs.audit.v2";
    const size_t dlen = sizeof(kDomain) - 1;
    std::vector<uint8_t> buf;
    buf.reserve(dlen + 4 + 16 + 16);
    buf.insert(buf.end(), kDomain, kDomain + dlen);
    // Party id as LE32.
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((party >> (8 * i)) & 0xFF));
    appendU128LE(buf, sigma);
    appendU128LE(buf, salt);
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(), buf.data(), buf.size());
    return h;
}

struct SigmaCommit128 {
    uint32_t party;
    u128 sigma;
    u128 salt;
    std::array<uint8_t, 32> commit;
};

SigmaCommit128 computeSigmaCommit128(uint32_t party, u128 alpha_i,
                                       u128 mac_i, u128 x_pub_ring) {
    SigmaCommit128 s;
    s.party  = party;
    s.sigma  = modRing(alpha_i * x_pub_ring - mac_i);
    s.salt   = secureRandU128();
    s.commit = commitSigma128(party, s.sigma, s.salt);
    return s;
}

bool verifySigmaReveal128(const SigmaCommit128& r,
                            const std::array<uint8_t, 32>& expected) {
    auto got = commitSigma128(r.party, r.sigma, r.salt);
    return sodium_memcmp(got.data(), expected.data(), 32) == 0;
}

} // namespace

// ---------------------------------------------------------------------------
// Open with SPDZ2k MAC check (Cramer et al. CRYPTO 2018 §3, Alg. 12).
// ---------------------------------------------------------------------------

bool openWithMacCheckShared128(const AuthSharedU128& x,
                                 const AlphaShare128& alpha,
                                 uint64_t& out_value) {
    if (x.value.N() != 2 || alpha.alpha_share.N() != 2) {
        throw std::runtime_error(
            "openWithMacCheckShared128: 2-party only (MPSVS S1/S2 topology)");
    }
    // Phase A: reconstruct x in the FULL extended ring.
    u128 x_ring = x.value.reconstruct();
    uint64_t x_value = static_cast<uint64_t>(x_ring & kSpdz2kValueMask);

    // Phase B: each party locally computes σ_i in ℤ_{2^{144}}.
    SigmaCommit128 s1 = computeSigmaCommit128(
        1, alpha.alpha_share.shares[0], x.mac.shares[0], x_ring);
    SigmaCommit128 s2 = computeSigmaCommit128(
        2, alpha.alpha_share.shares[1], x.mac.shares[1], x_ring);

    // Phase C: snapshot commits BEFORE reveal.
    auto c1 = s1.commit;
    auto c2 = s2.commit;

    // Phase D: reveal + verify against snapshot.
    if (!verifySigmaReveal128(s1, c1)) return false;
    if (!verifySigmaReveal128(s2, c2)) return false;

    // Phase E: SPDZ2k check — σ_1 + σ_2 == 0 in the FULL extended ring.
    u128 sigma_sum = modRing(s1.sigma + s2.sigma);
    if (sigma_sum != 0) return false;

    out_value = x_value;
    return true;
}

// ---------------------------------------------------------------------------
// Batch Ω-check with Fiat-Shamir-derived challenges over full ring.
// ---------------------------------------------------------------------------

static std::vector<u128> deriveOmegaChallenges128(
        const std::vector<AuthSharedU128>& xs) {
    ensureSodiumInit();
    std::vector<uint8_t> tr;
    tr.reserve(xs.size() * 4 * 16);
    for (const auto& x : xs) {
        for (uint32_t i = 0; i < x.N(); ++i) {
            appendU128LE(tr, x.value.shares[i]);
            appendU128LE(tr, x.mac.shares[i]);
        }
    }
    std::array<uint8_t, 32> tr_hash;
    crypto_hash_sha256(tr_hash.data(), tr.data(), tr.size());

    std::vector<u128> rs(xs.size());
    static const char kDom[] = "mpsvs.omega.r.v2";
    const size_t dlen = sizeof(kDom) - 1;
    for (size_t j = 0; j < xs.size(); ++j) {
        std::vector<uint8_t> input;
        input.insert(input.end(), kDom, kDom + dlen);
        for (int i = 0; i < 8; ++i)
            input.push_back(static_cast<uint8_t>((j >> (8 * i)) & 0xFF));
        input.insert(input.end(), tr_hash.begin(), tr_hash.end());
        // Hash twice to get 32 bytes → 16 bytes of challenge, then mask.
        std::array<uint8_t, 32> h;
        crypto_hash_sha256(h.data(), input.data(), input.size());
        u128 r = 0;
        for (int b = 15; b >= 0; --b) r = (r << 8) | h[b];
        r = modRing(r);
        if (r == 0) r = 1;
        rs[j] = r;
    }
    return rs;
}

bool batchOpenWithMacCheckShared128(const std::vector<AuthSharedU128>& xs,
                                      const AlphaShare128& alpha,
                                      std::vector<uint64_t>& out_values) {
    if (alpha.alpha_share.N() != 2)
        throw std::runtime_error("batchOpenWithMacCheckShared128: 2-party only");
    for (const auto& x : xs)
        if (x.value.N() != 2)
            throw std::runtime_error(
                "batchOpenWithMacCheckShared128: element must be 2-party");

    auto rs = deriveOmegaChallenges128(xs);

    out_values.clear();
    out_values.reserve(xs.size());
    AuthSharedU128 combined;
    combined.value = SharedU128(2);
    combined.mac   = SharedU128(2);
    for (size_t j = 0; j < xs.size(); ++j) {
        const auto& x = xs[j];
        u128 r = rs[j];
        // Value reveal per element (semantic-value only).
        u128 v_ring = x.value.reconstruct();
        out_values.push_back(static_cast<uint64_t>(v_ring & kSpdz2kValueMask));
        // Fold r·x_i into combined.
        combined.value.shares[0] = modRing(combined.value.shares[0] + r * x.value.shares[0]);
        combined.value.shares[1] = modRing(combined.value.shares[1] + r * x.value.shares[1]);
        combined.mac.shares[0]   = modRing(combined.mac.shares[0]   + r * x.mac.shares[0]);
        combined.mac.shares[1]   = modRing(combined.mac.shares[1]   + r * x.mac.shares[1]);
    }
    uint64_t dummy = 0;
    return openWithMacCheckShared128(combined, alpha, dummy);
}

// ---------------------------------------------------------------------------
// Beaver mult with shared α (SPDZ2k).
// ---------------------------------------------------------------------------

AuthSharedU128 authSecureMultiplyShared128(const AuthSharedU128& x,
                                             const AuthSharedU128& y,
                                             const AuthBeaverTriple128& triple,
                                             const AlphaShare128& alpha) {
    if (x.N() != 2 || y.N() != 2 || alpha.alpha_share.N() != 2 ||
        triple.u.N() != 2 || triple.v.N() != 2 || triple.w.N() != 2) {
        throw std::runtime_error(
            "authSecureMultiplyShared128: 2-party only (MPSVS S1/S2)");
    }

    // d = x - u; e = y - v; open + MAC-check in full ring.
    AuthSharedU128 xmu = authSub128(x, triple.u);
    AuthSharedU128 ymv = authSub128(y, triple.v);
    uint64_t d64 = 0, e64 = 0;
    if (!openWithMacCheckShared128(xmu, alpha, d64))
        throw AuthShareMacFailure128(
            "authSecureMultiplyShared128: MAC check failed on d = x - u");
    if (!openWithMacCheckShared128(ymv, alpha, e64))
        throw AuthShareMacFailure128(
            "authSecureMultiplyShared128: MAC check failed on e = y - v");

    // d, e are semantic-value low k bits; extend to full ring for arithmetic.
    u128 d = static_cast<u128>(d64);
    u128 e = static_cast<u128>(e64);

    // z = w + d·v + e·u + d·e; MAC(z) = MAC(w) + d·MAC(v) + e·MAC(u) + α·d·e.
    AuthSharedU128 out;
    out.value = SharedU128(2);
    out.mac   = SharedU128(2);
    for (uint32_t i = 0; i < 2; ++i) {
        u128 zi = triple.w.value.shares[i]
                + modRing(d * triple.v.value.shares[i])
                + modRing(e * triple.u.value.shares[i]);
        if (i == 0) zi += modRing(d * e);
        out.value.shares[i] = modRing(zi);

        u128 mi = triple.w.mac.shares[i]
                + modRing(d * triple.v.mac.shares[i])
                + modRing(e * triple.u.mac.shares[i])
                + modRing(alpha.alpha_share.shares[i] * d * e);
        out.mac.shares[i] = modRing(mi);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Sacrifice check.
// ---------------------------------------------------------------------------

static AuthSharedU128 rXSubY128(u128 r, const AuthSharedU128& x,
                                  const AuthSharedU128& y) {
    AuthSharedU128 out;
    out.value = subShared128(mulConst128(x.value, r), y.value);
    out.mac   = subShared128(mulConst128(x.mac,   r), y.mac);
    return out;
}

static AuthSharedU128 authSubPubMulValue128(
        u128 r_a, const AuthSharedU128& c,
        u128 sigma_pub, const AuthSharedU128& a_prime,
        u128 rho_pub,   const AuthSharedU128& b_prime,
        const AuthSharedU128& c_prime) {
    AuthSharedU128 rc = authMulConst128(c, r_a);
    AuthSharedU128 sa = authMulConst128(a_prime, sigma_pub);
    AuthSharedU128 rb = authMulConst128(b_prime, rho_pub);
    AuthSharedU128 tmp = authSub128(rc, c_prime);
    tmp = authSub128(tmp, sa);
    tmp = authSub128(tmp, rb);
    return tmp;
}

bool sacrificeCheckTripleShared128(const AuthBeaverTriple128& T,
                                     const AuthBeaverTriple128& T_aux,
                                     const AlphaShare128& alpha) {
    u128 r = secureRandU128();
    if (r == 0) r = 1;

    AuthSharedU128 rho_shared   = rXSubY128(r, T.u, T_aux.u);
    AuthSharedU128 sigma_shared = rXSubY128(1, T.v, T_aux.v);

    uint64_t rho64 = 0, sigma64 = 0;
    if (!openWithMacCheckShared128(rho_shared,   alpha, rho64))   return false;
    if (!openWithMacCheckShared128(sigma_shared, alpha, sigma64)) return false;
    u128 rho   = static_cast<u128>(rho64);
    u128 sigma = static_cast<u128>(sigma64);

    AuthSharedU128 tau_shared = authSubPubMulValue128(
        r, T.w, sigma, T_aux.u, rho, T_aux.v, T_aux.w);

    uint64_t tau64 = 0;
    if (!openWithMacCheckShared128(tau_shared, alpha, tau64)) return false;
    u128 tau = static_cast<u128>(tau64);

    // Check τ ≡ ρ · σ mod 2^k (semantic values). If both are opened via
    // shared-α MAC check, an adversarial Δ against T is caught by that
    // check with prob ≥ 1 - 2^{-s} directly.
    return tau == static_cast<u128>(static_cast<uint64_t>(rho * sigma));
}

// ---------------------------------------------------------------------------
// Test-only tamper helper.
// ---------------------------------------------------------------------------

void simulateTampering128(AuthSharedU128& x, uint32_t bad_party, u128 tamper_amount) {
    if (bad_party >= x.value.N())
        throw std::invalid_argument("simulateTampering128: bad_party out of range");
    x.value.shares[bad_party] = modRing(x.value.shares[bad_party] + tamper_amount);
}

} // namespace mpsvs
} // namespace volePSI
