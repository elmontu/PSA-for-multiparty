#include "MpPedersen.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

PedersenCommitment pedersenCommit(const R255Scalar& m, const R255Scalar& r)
{
    // c = g^m * h^r. Compute as scalarMultBase(m) + scalarMult(r, H).
    auto gm = scalarMultBase(m);
    auto hr = scalarMult(r, R255Point::pedersenH());
    PedersenCommitment c;
    c.c = pointAdd(gm, hr);
    return c;
}

bool pedersenVerify(const PedersenCommitment& c,
                    const R255Scalar& m,
                    const R255Scalar& r)
{
    auto expected = pedersenCommit(m, r);
    return expected.c == c.c;
}

PedersenCommitment pedersenAdd(const PedersenCommitment& a,
                               const PedersenCommitment& b)
{
    PedersenCommitment out;
    out.c = pointAdd(a.c, b.c);
    return out;
}

PedersenCommitment pedersenScalarMul(const R255Scalar& k,
                                     const PedersenCommitment& c)
{
    PedersenCommitment out;
    out.c = scalarMult(k, c.c);
    return out;
}

std::vector<PedersenCommitment> pedersenCommitVector(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openings)
{
    if (messages.size() != openings.size())
        throw std::runtime_error("pedersenCommitVector: size mismatch");
    std::vector<PedersenCommitment> out;
    out.reserve(messages.size());
    for (size_t i = 0; i < messages.size(); ++i) {
        out.push_back(pedersenCommit(messages[i], openings[i]));
    }
    return out;
}

std::vector<R255Scalar> freshOpenings(size_t count)
{
    std::vector<R255Scalar> out(count);
    for (auto& s : out) s = R255Scalar::random();
    return out;
}

} // namespace mpstar
} // namespace volePSI
