#include "MpsvsOprf.h"

#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Fiat-Shamir domain prefixes (16 bytes, ASCII, '.'-padded)
// ---------------------------------------------------------------------------

static const std::array<uint8_t, kDomainPrefixBytes> kPrefSchnorr =
    {'S','C','H','N','O','R','R','|','.','.','.','.','.','.','.','.'};
static const std::array<uint8_t, kDomainPrefixBytes> kPrefDleq =
    {'D','L','E','Q','|','.','.','.','.','.','.','.','.','.','.','.'};
static const std::array<uint8_t, kDomainPrefixBytes> kPrefAlign =
    {'A','L','I','G','N','|','.','.','.','.','.','.','.','.','.','.'};
static const std::array<uint8_t, kDomainPrefixBytes> kPrefReal =
    {'R','E','A','L','|','.','.','.','.','.','.','.','.','.','.','.'};
static const std::array<uint8_t, kDomainPrefixBytes> kPrefDkgCommit =
    {'D','K','G','-','C','O','M','M','I','T','|','.','.','.','.','.'};

// ---------------------------------------------------------------------------
// LP encoding
// ---------------------------------------------------------------------------

void appendLP(std::vector<uint8_t>& dst, const uint8_t* data, size_t len) {
    // 4-byte big-endian length prefix
    if (len > 0xFFFFFFFFULL) throw std::runtime_error("appendLP: length > 2^32");
    uint32_t n = static_cast<uint32_t>(len);
    dst.push_back(static_cast<uint8_t>((n >> 24) & 0xFF));
    dst.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
    dst.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    dst.push_back(static_cast<uint8_t>(n & 0xFF));
    dst.insert(dst.end(), data, data + len);
}

void appendFixedWidthU32(std::vector<uint8_t>& dst, uint32_t v) {
    dst.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    dst.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    dst.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    dst.push_back(static_cast<uint8_t>(v & 0xFF));
}

void appendFixedWidthU64(std::vector<uint8_t>& dst, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        dst.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

// ---------------------------------------------------------------------------
// Ristretto255 helpers
// ---------------------------------------------------------------------------

void randomScalar(Scalar& out) {
    crypto_core_ristretto255_scalar_random(out.data());
}

void scalarInvert(Scalar& out, const Scalar& in) {
    if (crypto_core_ristretto255_scalar_invert(out.data(), in.data()) != 0)
        throw std::runtime_error("scalarInvert: zero scalar");
}

void scalarMultBase(GroupElement& out, const Scalar& s) {
    if (crypto_scalarmult_ristretto255_base(out.data(), s.data()) != 0)
        throw std::runtime_error("scalarMultBase failed");
}

void scalarMult(GroupElement& out, const Scalar& s, const GroupElement& p) {
    if (crypto_scalarmult_ristretto255(out.data(), s.data(), p.data()) != 0)
        throw std::runtime_error("scalarMult failed (bad point or zero scalar)");
}

void hashToGroup(GroupElement& out, const uint8_t* msg, size_t len) {
    std::array<uint8_t, 64> h;
    crypto_hash_sha512(h.data(), msg, len);
    if (crypto_core_ristretto255_from_hash(out.data(), h.data()) != 0)
        throw std::runtime_error("hashToGroup failed");
}

void hashToGroup(GroupElement& out, const std::vector<uint8_t>& msg) {
    hashToGroup(out, msg.data(), msg.size());
}

bool isValidPoint(const GroupElement& p) {
    return crypto_core_ristretto255_is_valid_point(p.data()) == 1;
}

GroupElement generatorBase() {
    // g = base point. Derive as base^1.
    GroupElement g;
    Scalar one{}; one[0] = 1;
    scalarMultBase(g, one);
    return g;
}

// ---------------------------------------------------------------------------
// Fiat-Shamir hash-to-scalar
// ---------------------------------------------------------------------------

Scalar hashToScalarCtx(const std::array<uint8_t, kDomainPrefixBytes>& prefix,
                       const Context& ctx,
                       const std::vector<uint8_t>& transcript) {
    // Build input: prefix || LP(ctx) || transcript
    std::vector<uint8_t> input;
    input.reserve(kDomainPrefixBytes + 4 + ctx.size() + transcript.size());
    input.insert(input.end(), prefix.begin(), prefix.end());
    appendLP(input, ctx);
    input.insert(input.end(), transcript.begin(), transcript.end());

    // SHA-512 → 64 bytes → reduce mod q
    std::array<uint8_t, 64> h;
    crypto_hash_sha512(h.data(), input.data(), input.size());
    Scalar out;
    crypto_core_ristretto255_scalar_reduce(out.data(), h.data());
    return out;
}

// ---------------------------------------------------------------------------
// Schnorr PoK { k : Y = g^k } — ctx-bound
// ---------------------------------------------------------------------------

SchnorrProof schnorrProve(const Scalar& k,
                          const GroupElement& Y,
                          const Context& ctx) {
    // r ← random; R = g^r
    Scalar r; randomScalar(r);
    GroupElement R; scalarMultBase(R, r);

    // c = H(LP(Y) || LP(R))
    std::vector<uint8_t> tr;
    appendLP(tr, Y);
    appendLP(tr, R);
    Scalar c = hashToScalarCtx(kPrefSchnorr, ctx, tr);

    // s = r + c·k  (mod q)
    Scalar ck;
    crypto_core_ristretto255_scalar_mul(ck.data(), c.data(), k.data());
    Scalar s;
    crypto_core_ristretto255_scalar_add(s.data(), r.data(), ck.data());

    return { c, s };
}

bool schnorrVerify(const GroupElement& Y,
                   const SchnorrProof& pi,
                   const Context& ctx) {
    if (!isValidPoint(Y)) return false;
    // Recompute R' = g^s - c·Y   (i.e. R' such that g^s = R' + c·Y)
    // Equivalent check: g^s ==? R + c·Y where R is recovered from
    // c = H(LP(Y) || LP(R)). We can't recover R directly, so recompute R:
    //   R = g^s - c·Y
    GroupElement gs; scalarMultBase(gs, pi.s);
    GroupElement cY; scalarMult(cY, pi.c, Y);
    // R = gs - cY. Ristretto255 has an add; we need subtract.
    // Use add with negation: cY_neg
    // libsodium: crypto_core_ristretto255_sub is available.
    GroupElement R;
    if (crypto_core_ristretto255_sub(R.data(), gs.data(), cY.data()) != 0)
        return false;

    // Recompute c' from R
    std::vector<uint8_t> tr;
    appendLP(tr, Y);
    appendLP(tr, R);
    Scalar cprime = hashToScalarCtx(kPrefSchnorr, ctx, tr);

    // Check c' == pi.c
    return sodium_memcmp(cprime.data(), pi.c.data(), 32) == 0;
}

// ---------------------------------------------------------------------------
// Chaum-Pedersen DLEQ { k : Y = g^k ∧ V = U^k }
// ---------------------------------------------------------------------------

DLEQProof dleqProve(const Scalar& k,
                    const GroupElement& Y,
                    const GroupElement& U,
                    const GroupElement& V,
                    const Context& ctx) {
    // r ← random; A = g^r; B = U^r
    Scalar r; randomScalar(r);
    GroupElement A; scalarMultBase(A, r);
    GroupElement B; scalarMult(B, r, U);

    // c = H(LP(g) || LP(Y) || LP(U) || LP(V) || LP(A) || LP(B))
    std::vector<uint8_t> tr;
    GroupElement g = generatorBase();
    appendLP(tr, g);
    appendLP(tr, Y);
    appendLP(tr, U);
    appendLP(tr, V);
    appendLP(tr, A);
    appendLP(tr, B);
    Scalar c = hashToScalarCtx(kPrefDleq, ctx, tr);

    // s = r + c·k
    Scalar ck;
    crypto_core_ristretto255_scalar_mul(ck.data(), c.data(), k.data());
    Scalar s;
    crypto_core_ristretto255_scalar_add(s.data(), r.data(), ck.data());

    return { c, s };
}

bool dleqVerify(const GroupElement& Y,
                const GroupElement& U,
                const GroupElement& V,
                const DLEQProof& pi,
                const Context& ctx) {
    if (!isValidPoint(Y) || !isValidPoint(U) || !isValidPoint(V)) return false;
    // Recover A = g^s - c·Y, B = U^s - c·V
    GroupElement gs; scalarMultBase(gs, pi.s);
    GroupElement cY; scalarMult(cY, pi.c, Y);
    GroupElement A;
    if (crypto_core_ristretto255_sub(A.data(), gs.data(), cY.data()) != 0) return false;

    GroupElement Us; scalarMult(Us, pi.s, U);
    GroupElement cV; scalarMult(cV, pi.c, V);
    GroupElement B;
    if (crypto_core_ristretto255_sub(B.data(), Us.data(), cV.data()) != 0) return false;

    // Recompute c'
    std::vector<uint8_t> tr;
    GroupElement g = generatorBase();
    appendLP(tr, g);
    appendLP(tr, Y);
    appendLP(tr, U);
    appendLP(tr, V);
    appendLP(tr, A);
    appendLP(tr, B);
    Scalar cprime = hashToScalarCtx(kPrefDleq, ctx, tr);

    return sodium_memcmp(cprime.data(), pi.c.data(), 32) == 0;
}

// ---------------------------------------------------------------------------
// Threshold DKG
// ---------------------------------------------------------------------------

// Helper: compute SHA-256(Y2 || pi2.c || pi2.s).
static Hash256 dkgCommitHash(const GroupElement& Y2, const SchnorrProof& pi2) {
    std::vector<uint8_t> buf;
    buf.reserve(96);
    // Bind with prefix
    buf.insert(buf.end(), kPrefDkgCommit.begin(), kPrefDkgCommit.end());
    buf.insert(buf.end(), Y2.begin(), Y2.end());
    buf.insert(buf.end(), pi2.c.begin(), pi2.c.end());
    buf.insert(buf.end(), pi2.s.begin(), pi2.s.end());
    Hash256 h;
    crypto_hash_sha256(h.data(), buf.data(), buf.size());
    return h;
}

DkgS2Prep dkgS2Prepare(const Context& ctx) {
    DkgS2Prep out{};
    randomScalar(out.k2);
    scalarMultBase(out.Y2, out.k2);
    out.pi2 = schnorrProve(out.k2, out.Y2, ctx);
    out.commit.commit = dkgCommitHash(out.Y2, out.pi2);
    return out;
}

DkgS1Msg1 dkgS1SendHop1(const Context& ctx, Scalar& out_k1) {
    DkgS1Msg1 out{};
    randomScalar(out_k1);
    scalarMultBase(out.Y1, out_k1);
    out.pi1 = schnorrProve(out_k1, out.Y1, ctx);
    return out;
}

DkgHop2Final dkgS2Finalize(const Context& ctx,
                           const DkgS2Prep& prep,
                           const DkgHop1& hop1,
                           DkgS2State& out_state) {
    // Verify pi1 from S1
    if (!schnorrVerify(hop1.Y1, hop1.pi1, ctx))
        throw std::runtime_error("dkgS2Finalize: pi1 verify failed");

    // Y = Y1^k2
    GroupElement Y;
    scalarMult(Y, prep.k2, hop1.Y1);

    // DLEQ_ctx{ k2 : Y2 = g^k2 ∧ Y = Y1^k2 }
    DLEQProof piY = dleqProve(prep.k2, prep.Y2, hop1.Y1, Y, ctx);

    out_state.k2 = prep.k2;
    out_state.Y  = Y;
    out_state.Y1 = hop1.Y1;
    out_state.Y2 = prep.Y2;

    DkgHop2Final msg;
    msg.Y2  = prep.Y2;
    msg.pi2 = prep.pi2;
    msg.Y   = Y;
    msg.piY = piY;
    return msg;
}

bool dkgS1Finalize(const Context& ctx,
                   const DkgCommit& commit_received,
                   const Scalar& k1,
                   const GroupElement& Y1,
                   const DkgHop2Final& final_msg,
                   DkgS1State& out_state) {
    // Verify commit opening: SHA-256(Y2 || pi2) == commit
    Hash256 h = dkgCommitHash(final_msg.Y2, final_msg.pi2);
    if (sodium_memcmp(h.data(), commit_received.commit.data(), 32) != 0)
        return false;
    // Verify pi2
    if (!schnorrVerify(final_msg.Y2, final_msg.pi2, ctx)) return false;
    // Verify DLEQ against (Y2, Y1, Y)
    if (!dleqVerify(final_msg.Y2, Y1, final_msg.Y, final_msg.piY, ctx)) return false;

    out_state.k1 = k1;
    out_state.Y1 = Y1;
    out_state.Y2 = final_msg.Y2;
    out_state.Y  = final_msg.Y;
    return true;
}

// ---------------------------------------------------------------------------
// OPRF server hops
// ---------------------------------------------------------------------------

OprfHop1Response oprfServerHop1(const DkgS1State& s1, const GroupElement& U,
                                const Context& ctx) {
    if (!isValidPoint(U)) throw std::runtime_error("oprfServerHop1: invalid U");
    OprfHop1Response resp;
    scalarMult(resp.V1, s1.k1, U);
    resp.dleq = dleqProve(s1.k1, s1.Y1, U, resp.V1, ctx);
    return resp;
}

OprfHop2Response oprfServerHop2(const DkgS2State& s2, const GroupElement& V1,
                                const Context& ctx) {
    if (!isValidPoint(V1)) throw std::runtime_error("oprfServerHop2: invalid V1");
    OprfHop2Response resp;
    scalarMult(resp.V2, s2.k2, V1);
    resp.dleq = dleqProve(s2.k2, s2.Y2, V1, resp.V2, ctx);
    return resp;
}

// ---------------------------------------------------------------------------
// Party-side DeriveEntityKey
// ---------------------------------------------------------------------------

EntityKeyResult deriveEntityKey(
    const std::string& id_type, const std::string& canonical_id,
    const Context& ctx,
    const GroupElement& Y1, const GroupElement& Y2, const GroupElement& Y,
    const std::function<OprfHop1Response(const GroupElement&)>& hop1_call,
    const std::function<OprfHop2Response(const GroupElement&)>& hop2_call) {
    EntityKeyResult res{};
    res.ok = false;

    // M = H1( LP("REAL|...........") || LP(id_type) || LP(canonical_id) )
    std::vector<uint8_t> mbuf;
    mbuf.insert(mbuf.end(), kPrefReal.begin(), kPrefReal.end());
    appendLP(mbuf, id_type);
    appendLP(mbuf, canonical_id);
    GroupElement M; hashToGroup(M, mbuf);

    // Blind: r ← random; U = M^r
    Scalar r; randomScalar(r);
    GroupElement U; scalarMult(U, r, M);

    // Hop 1
    OprfHop1Response h1 = hop1_call(U);
    if (!dleqVerify(Y1, U, h1.V1, h1.dleq, ctx)) return res;

    // Hop 2
    OprfHop2Response h2 = hop2_call(h1.V1);
    if (!dleqVerify(Y2, h1.V1, h2.V2, h2.dleq, ctx)) return res;

    // Sanity: chain-consistent with Y
    // (verifying Y == g^{k1 k2} was already done at DKG time; we trust it now)

    // Unblind: W = V2^{r^{-1}}
    Scalar rinv; scalarInvert(rinv, r);
    scalarMult(res.W, rinv, h2.V2);
    res.ok = true;
    return res;
}

// ---------------------------------------------------------------------------
// Row tag derivation
// ---------------------------------------------------------------------------

RowTag deriveRowTag(const std::string& id_type, const std::string& canonical_id,
                    uint32_t period, const EntityKey& W, const Context& ctx) {
    // t = H2( LP("ALIGN|...........") || LP(ctx) || LP(id_type) ||
    //          LP(canonical_id) || FixedWidth(p) || LP(Ser(W)) )
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), kPrefAlign.begin(), kPrefAlign.end());
    appendLP(buf, ctx);
    appendLP(buf, id_type);
    appendLP(buf, canonical_id);
    appendFixedWidthU32(buf, period);
    appendLP(buf, W);

    RowTag out;
    crypto_hash_sha256(out.t.data(), buf.data(), buf.size());
    return out;
}

RowTag dummyRowTag() {
    RowTag out;
    randombytes_buf(out.t.data(), out.t.size());
    return out;
}

uint64_t RowTag::bin(int beta_bits) const {
    // Extract the TOP beta_bits from the tag treated as a big-endian bit array.
    // Per Rev 7 §3: bin = t[0:β] — first β bits.
    if (beta_bits <= 0 || beta_bits > 64) return 0;
    uint64_t v = 0;
    int bytes = (beta_bits + 7) / 8;
    for (int i = 0; i < bytes; ++i) {
        v = (v << 8) | t[i];
    }
    int excess = bytes * 8 - beta_bits;
    if (excess > 0) v >>= excess;
    return v;
}

std::vector<uint8_t> RowTag::key(int beta_bits, int tau_bits) const {
    // key = bits [beta_bits, beta_bits + tau_bits) of t.
    // For simplicity: extract byte-aligned windows; caller aligns beta if
    // needed. Assume beta_bits multiple of 8 in this prototype.
    if (beta_bits % 8 != 0)
        throw std::runtime_error("RowTag::key: beta_bits must be byte-aligned in prototype");
    int start_byte = beta_bits / 8;
    int tau_bytes = (tau_bits + 7) / 8;
    if (start_byte + tau_bytes > (int)t.size())
        throw std::runtime_error("RowTag::key: not enough tag bits");
    std::vector<uint8_t> k(t.begin() + start_byte, t.begin() + start_byte + tau_bytes);
    // Mask off high bits in last byte if tau isn't byte-aligned
    if (tau_bits % 8 != 0) {
        int last_bits = tau_bits % 8;
        uint8_t mask = static_cast<uint8_t>((1 << last_bits) - 1) << (8 - last_bits);
        k.back() &= mask;
    }
    return k;
}

} // namespace mpsvs
} // namespace volePSI
