#pragma once

// Thin RAII wrapper around libsodium's Ristretto255 primitives. Used by
// the NIZK shuffle proof (R27) for Pedersen commitments and the
// Schwartz-Zippel argument. Ristretto255 is a prime-order group built
// on Curve25519; libsodium ships a constant-time, well-audited
// implementation.
//
// All scalar arithmetic is mod L (the prime order of the group, ≈ 2^252).

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpstar {

// 32-byte little-endian scalar in [0, L). The convention matches
// libsodium's crypto_core_ristretto255_scalar_* API.
struct R255Scalar {
    std::array<uint8_t, 32> bytes{};

    R255Scalar() = default;
    static R255Scalar zero() { return {}; }
    static R255Scalar one()  { R255Scalar s; s.bytes[0] = 1; return s; }
    static R255Scalar random();
    static R255Scalar fromU64(uint64_t v) {
        R255Scalar s;
        std::memcpy(s.bytes.data(), &v, sizeof(v));
        return s;
    }
    static R255Scalar fromBytes(const uint8_t* p, size_t len);

    bool operator==(const R255Scalar& o) const {
        return bytes == o.bytes;
    }
};

R255Scalar scalarAdd(const R255Scalar& a, const R255Scalar& b);
R255Scalar scalarSub(const R255Scalar& a, const R255Scalar& b);
R255Scalar scalarMul(const R255Scalar& a, const R255Scalar& b);
R255Scalar scalarNegate(const R255Scalar& a);
R255Scalar scalarInvert(const R255Scalar& a);  // throws on 0

// 32-byte Ristretto255 point (compressed encoding).
struct R255Point {
    std::array<uint8_t, 32> bytes{};

    R255Point() = default;
    static R255Point identity() { return {}; }  // additive identity = all zeros (Ristretto255 convention)
    static R255Point random();

    // Deterministic generator G. Defined as scalarBase(1).
    static R255Point generator();

    // Deterministic "independent" generator H for Pedersen commitments.
    // Derived by hash-to-curve with a fixed domain separator so the
    // discrete-log relation between G and H is unknown.
    static R255Point pedersenH();

    bool operator==(const R255Point& o) const {
        return bytes == o.bytes;
    }
};

// G * s (base-point scalar multiplication).
R255Point scalarMultBase(const R255Scalar& s);

// P * s (variable-base scalar multiplication).
R255Point scalarMult(const R255Scalar& s, const R255Point& p);

// P + Q.
R255Point pointAdd(const R255Point& p, const R255Point& q);

// P - Q.
R255Point pointSub(const R255Point& p, const R255Point& q);

// Hash arbitrary bytes to a Ristretto255 point. Used for the Pedersen H
// generator and for Fiat-Shamir challenges that need to be points.
R255Point hashToPoint(const std::vector<uint8_t>& msg);

// Hash arbitrary bytes to a Ristretto255 scalar (mod L). Used for
// Fiat-Shamir challenges that need to be scalars.
R255Scalar hashToScalar(const std::vector<uint8_t>& msg);

} // namespace mpstar
} // namespace volePSI
