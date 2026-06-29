#include "MpSecretShare.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

SharedU64 shareU64(uint32_t N, uint64_t value, oc::PRNG& prng)
{
    if (N < 2) throw std::runtime_error("shareU64: N must be >= 2");
    SharedU64 out(N);
    uint64_t accum = 0;
    for (uint32_t i = 1; i < N; ++i) {
        out.shares[i] = prng.get<uint64_t>();
        accum += out.shares[i];
    }
    out.shares[0] = value - accum;  // wraps mod 2^64
    return out;
}

SharedU64 addShared(const SharedU64& a, const SharedU64& b)
{
    if (a.N() != b.N())
        throw std::runtime_error("addShared: N mismatch");
    SharedU64 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i) {
        out.shares[i] = a.shares[i] + b.shares[i];
    }
    return out;
}

SharedU64 subShared(const SharedU64& a, const SharedU64& b)
{
    if (a.N() != b.N())
        throw std::runtime_error("subShared: N mismatch");
    SharedU64 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i) {
        out.shares[i] = a.shares[i] - b.shares[i];
    }
    return out;
}

SharedU64 addConst(const SharedU64& a, uint64_t c)
{
    SharedU64 out = a;
    out.shares[0] += c;
    return out;
}

SharedU64 mulConst(const SharedU64& a, uint64_t c)
{
    SharedU64 out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i) {
        out.shares[i] = a.shares[i] * c;
    }
    return out;
}

SharedBit shareBit(uint32_t N, uint8_t value, oc::PRNG& prng)
{
    if (N < 2) throw std::runtime_error("shareBit: N must be >= 2");
    SharedBit out(N);
    uint8_t accum = 0;
    for (uint32_t i = 1; i < N; ++i) {
        out.shares[i] = prng.get<uint8_t>() & 1;
        accum ^= out.shares[i];
    }
    out.shares[0] = (value & 1) ^ accum;
    return out;
}

SharedBit xorShared(const SharedBit& a, const SharedBit& b)
{
    if (a.N() != b.N())
        throw std::runtime_error("xorShared: N mismatch");
    SharedBit out(a.N());
    for (uint32_t i = 0; i < a.N(); ++i) {
        out.shares[i] = (a.shares[i] ^ b.shares[i]) & 1;
    }
    return out;
}

SharedBit xorConst(const SharedBit& a, uint8_t c)
{
    SharedBit out = a;
    out.shares[0] = (out.shares[0] ^ (c & 1)) & 1;
    return out;
}

} // namespace mpstar
} // namespace volePSI
