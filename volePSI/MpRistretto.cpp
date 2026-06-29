#include "MpRistretto.h"

#include <sodium.h>
#include <cstring>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

// libsodium requires sodium_init() to be called before any other API.
// Idempotent.
void ensureSodiumInit() {
    static bool inited = []() {
        if (sodium_init() < 0)
            throw std::runtime_error("ensureSodiumInit: sodium_init failed");
        return true;
    }();
    (void)inited;
}

} // namespace

R255Scalar R255Scalar::random()
{
    ensureSodiumInit();
    R255Scalar s;
    crypto_core_ristretto255_scalar_random(s.bytes.data());
    return s;
}

R255Scalar R255Scalar::fromBytes(const uint8_t* p, size_t len)
{
    if (len != 32) throw std::runtime_error("R255Scalar::fromBytes: len must be 32");
    R255Scalar s;
    std::memcpy(s.bytes.data(), p, 32);
    return s;
}

R255Scalar scalarAdd(const R255Scalar& a, const R255Scalar& b)
{
    ensureSodiumInit();
    R255Scalar z;
    crypto_core_ristretto255_scalar_add(z.bytes.data(), a.bytes.data(), b.bytes.data());
    return z;
}

R255Scalar scalarSub(const R255Scalar& a, const R255Scalar& b)
{
    ensureSodiumInit();
    R255Scalar z;
    crypto_core_ristretto255_scalar_sub(z.bytes.data(), a.bytes.data(), b.bytes.data());
    return z;
}

R255Scalar scalarMul(const R255Scalar& a, const R255Scalar& b)
{
    ensureSodiumInit();
    R255Scalar z;
    crypto_core_ristretto255_scalar_mul(z.bytes.data(), a.bytes.data(), b.bytes.data());
    return z;
}

R255Scalar scalarNegate(const R255Scalar& a)
{
    ensureSodiumInit();
    R255Scalar z;
    crypto_core_ristretto255_scalar_negate(z.bytes.data(), a.bytes.data());
    return z;
}

R255Scalar scalarInvert(const R255Scalar& a)
{
    ensureSodiumInit();
    R255Scalar z;
    if (crypto_core_ristretto255_scalar_invert(z.bytes.data(), a.bytes.data()) != 0)
        throw std::runtime_error("scalarInvert: zero or non-invertible scalar");
    return z;
}

R255Point R255Point::random()
{
    ensureSodiumInit();
    R255Point p;
    crypto_core_ristretto255_random(p.bytes.data());
    return p;
}

R255Point R255Point::generator()
{
    return scalarMultBase(R255Scalar::one());
}

R255Point R255Point::pedersenH()
{
    // Independent generator: hash a fixed domain-separator to a curve
    // point. The discrete log of H w.r.t. G is unknown — the soundness
    // of Pedersen commitments depends on this.
    static R255Point cached = []() {
        ensureSodiumInit();
        const char domSep[] = "mpstar.pedersen.H.v1";
        std::vector<uint8_t> msg(std::begin(domSep), std::end(domSep) - 1);
        return hashToPoint(msg);
    }();
    return cached;
}

R255Point scalarMultBase(const R255Scalar& s)
{
    ensureSodiumInit();
    R255Point p;
    if (crypto_scalarmult_ristretto255_base(p.bytes.data(), s.bytes.data()) != 0) {
        throw std::runtime_error("scalarMultBase: failed (likely zero scalar?)");
    }
    return p;
}

R255Point scalarMult(const R255Scalar& s, const R255Point& base)
{
    ensureSodiumInit();
    R255Point p;
    int rc = crypto_scalarmult_ristretto255(p.bytes.data(), s.bytes.data(), base.bytes.data());
    if (rc != 0) {
        // Zero result is valid (s == 0 or base = identity). libsodium returns
        // -1 only for INVALID points; treat as failure.
        throw std::runtime_error(
            "scalarMult: failed (rc=" + std::to_string(rc) + ")");
    }
    return p;
}

R255Point pointAdd(const R255Point& p, const R255Point& q)
{
    ensureSodiumInit();
    R255Point r;
    if (crypto_core_ristretto255_add(r.bytes.data(), p.bytes.data(), q.bytes.data()) != 0) {
        throw std::runtime_error("pointAdd: failed (invalid point?)");
    }
    return r;
}

R255Point pointSub(const R255Point& p, const R255Point& q)
{
    ensureSodiumInit();
    R255Point r;
    if (crypto_core_ristretto255_sub(r.bytes.data(), p.bytes.data(), q.bytes.data()) != 0) {
        throw std::runtime_error("pointSub: failed (invalid point?)");
    }
    return r;
}

R255Point hashToPoint(const std::vector<uint8_t>& msg)
{
    ensureSodiumInit();
    // hash-then-from_hash: SHA-512 the message, then map to the curve.
    std::array<uint8_t, crypto_core_ristretto255_HASHBYTES> hash{};
    crypto_hash_sha512(hash.data(), msg.data(), msg.size());
    R255Point p;
    if (crypto_core_ristretto255_from_hash(p.bytes.data(), hash.data()) != 0) {
        throw std::runtime_error("hashToPoint: from_hash failed");
    }
    return p;
}

R255Scalar hashToScalar(const std::vector<uint8_t>& msg)
{
    ensureSodiumInit();
    // SHA-512 → 64 bytes → reduce mod L using the non-reduced scalar API.
    std::array<uint8_t, crypto_core_ristretto255_NONREDUCEDSCALARBYTES> hash{};
    crypto_hash_sha512(hash.data(), msg.data(), msg.size());
    R255Scalar s;
    crypto_core_ristretto255_scalar_reduce(s.bytes.data(), hash.data());
    return s;
}

} // namespace mpstar
} // namespace volePSI
