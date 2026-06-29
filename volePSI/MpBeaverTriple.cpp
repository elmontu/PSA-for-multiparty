#include "MpBeaverTriple.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

BeaverTripleU64 generateBeaverTriple(uint32_t N, oc::PRNG& prng)
{
    if (N < 2) throw std::runtime_error("generateBeaverTriple: N must be >= 2");
    uint64_t u_val = prng.get<uint64_t>();
    uint64_t v_val = prng.get<uint64_t>();
    uint64_t w_val = u_val * v_val;  // mod 2^64
    BeaverTripleU64 t;
    t.u = shareU64(N, u_val, prng);
    t.v = shareU64(N, v_val, prng);
    t.w = shareU64(N, w_val, prng);
    return t;
}

std::vector<BeaverTripleU64>
generateBeaverTriples(uint32_t N, size_t count, oc::PRNG& prng)
{
    std::vector<BeaverTripleU64> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(generateBeaverTriple(N, prng));
    }
    return out;
}

SharedU64 secureMultiply(const SharedU64& x,
                         const SharedU64& y,
                         const BeaverTripleU64& triple)
{
    if (x.N() != y.N() || x.N() != triple.u.N())
        throw std::runtime_error("secureMultiply: N mismatch");

    // <d> = <x> - <u>, opened.
    auto d_shared = subShared(x, triple.u);
    auto e_shared = subShared(y, triple.v);
    uint64_t d = d_shared.reconstruct();
    uint64_t e = e_shared.reconstruct();

    // <xy> = <w> + d·<v> + e·<u> + d·e.
    // The last term d·e is a public constant added to the share.
    auto t1 = mulConst(triple.v, d);   // d * <v>
    auto t2 = mulConst(triple.u, e);   // e * <u>
    auto step1 = addShared(triple.w, t1);
    auto step2 = addShared(step1, t2);
    return addConst(step2, d * e);     // d·e is public, added to party 0
}

BeaverTripleBit generateBeaverTripleBit(uint32_t N, oc::PRNG& prng)
{
    if (N < 2) throw std::runtime_error("generateBeaverTripleBit: N must be >= 2");
    uint8_t u = prng.get<uint8_t>() & 1;
    uint8_t v = prng.get<uint8_t>() & 1;
    uint8_t w = u & v;
    BeaverTripleBit t;
    t.u = shareBit(N, u, prng);
    t.v = shareBit(N, v, prng);
    t.w = shareBit(N, w, prng);
    return t;
}

std::vector<BeaverTripleBit>
generateBeaverTripleBits(uint32_t N, size_t count, oc::PRNG& prng)
{
    std::vector<BeaverTripleBit> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(generateBeaverTripleBit(N, prng));
    }
    return out;
}

SharedBit secureAnd(const SharedBit& x,
                    const SharedBit& y,
                    const BeaverTripleBit& triple)
{
    if (x.N() != y.N() || x.N() != triple.u.N())
        throw std::runtime_error("secureAnd: N mismatch");

    // <d> = <x> XOR <u>, opened.
    auto d_shared = xorShared(x, triple.u);
    auto e_shared = xorShared(y, triple.v);
    uint8_t d = d_shared.reconstruct();
    uint8_t e = e_shared.reconstruct();

    // <xy> = <w> XOR d·<v> XOR e·<u> XOR d·e.
    // Over Z_2: multiplication by a public bit is AND with that bit
    // applied to each party's share.
    SharedBit t1(x.N()), t2(x.N());
    for (uint32_t i = 0; i < x.N(); ++i) {
        t1.shares[i] = triple.v.shares[i] & d;  // d · v share
        t2.shares[i] = triple.u.shares[i] & e;  // e · u share
    }
    auto step1 = xorShared(triple.w, t1);
    auto step2 = xorShared(step1, t2);
    return xorConst(step2, (d & e));
}

} // namespace mpstar
} // namespace volePSI
