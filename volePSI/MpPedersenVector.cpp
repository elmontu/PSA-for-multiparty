#include "MpPedersenVector.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace volePSI {
namespace mpstar {

R255Point pedersenVectorGenerator(size_t i)
{
    // Cached deterministic generators. Domain separator binds them to
    // this specific commitment scheme.
    static std::mutex mu;
    static std::unordered_map<size_t, R255Point> cache;
    std::lock_guard<std::mutex> lock(mu);
    auto it = cache.find(i);
    if (it != cache.end()) return it->second;

    std::string domSep = "mpstar.pedersen.vector.G." + std::to_string(i);
    std::vector<uint8_t> bytes(domSep.begin(), domSep.end());
    auto p = hashToPoint(bytes);
    cache.emplace(i, p);
    return p;
}

PedersenVectorCommitment pedersenVectorCommit(
    const std::vector<R255Scalar>& messages,
    const R255Scalar& opening)
{
    PedersenVectorCommitment out;
    out.c = R255Point::identity();
    // C = sum_i g_i^{m_i} + h^r  (additive group notation)
    for (size_t i = 0; i < messages.size(); ++i) {
        auto g_i = pedersenVectorGenerator(i);
        out.c = pointAdd(out.c, scalarMult(messages[i], g_i));
    }
    out.c = pointAdd(out.c, scalarMult(opening, R255Point::pedersenH()));
    return out;
}

bool pedersenVectorVerify(
    const PedersenVectorCommitment& commit,
    const std::vector<R255Scalar>& messages,
    const R255Scalar& opening)
{
    auto expected = pedersenVectorCommit(messages, opening);
    return commit.c == expected.c;
}

PedersenVectorCommitment pedersenVectorAdd(
    const PedersenVectorCommitment& a,
    const PedersenVectorCommitment& b)
{
    PedersenVectorCommitment out;
    out.c = pointAdd(a.c, b.c);
    return out;
}

namespace {

// Same transcript builder as R27b but with a different domain
// separator so the challenge is bound to this proof variant.
std::vector<uint8_t> buildFsTranscript_audit(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime)
{
    std::vector<uint8_t> out;
    const char dom[] = "mpstar.shuffleAudit.v1";
    out.insert(out.end(), std::begin(dom), std::end(dom) - 1);
    auto pushU32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };
    pushU32(static_cast<uint32_t>(C.size()));
    for (const auto& c : C) out.insert(out.end(), c.c.bytes.begin(), c.c.bytes.end());
    pushU32(static_cast<uint32_t>(Cprime.size()));
    for (const auto& c : Cprime) out.insert(out.end(), c.c.bytes.begin(), c.c.bytes.end());
    return out;
}

R255Scalar sumScalars(const std::vector<R255Scalar>& xs) {
    R255Scalar acc = R255Scalar::zero();
    for (const auto& x : xs) acc = scalarAdd(acc, x);
    return acc;
}

} // namespace

R255Scalar fsChallengeY_audit(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime)
{
    return hashToScalar(buildFsTranscript_audit(C, Cprime));
}

namespace {

R255Scalar fsChallengeZ_audit(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime,
    const R255Scalar& y)
{
    auto t = buildFsTranscript_audit(C, Cprime);
    // Include y and a distinct domain byte to derive z ≠ y.
    t.push_back(0x7A);  // 'z'
    t.insert(t.end(), y.bytes.begin(), y.bytes.end());
    return hashToScalar(t);
}

std::vector<R255Scalar> powersOf(const R255Scalar& z, size_t n) {
    std::vector<R255Scalar> out(n);
    if (n == 0) return out;
    out[0] = R255Scalar::one();
    for (size_t i = 1; i < n; ++i) out[i] = scalarMul(out[i - 1], z);
    return out;
}

R255Scalar scalarDot(const std::vector<R255Scalar>& a,
                     const std::vector<R255Scalar>& b)
{
    R255Scalar acc = R255Scalar::zero();
    for (size_t i = 0; i < a.size(); ++i)
        acc = scalarAdd(acc, scalarMul(a[i], b[i]));
    return acc;
}

} // namespace

ShuffleProofAudit shuffleProveAudit(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openingsOrig,
    const std::vector<R255Scalar>& openingsShuf,
    const std::vector<int>& permutation,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    const size_t n = messages.size();
    if (openingsOrig.size() != n || openingsShuf.size() != n
        || permutation.size() != n || commitmentsOrig.size() != n
        || commitmentsShuf.size() != n) {
        throw std::runtime_error("shuffleProveAudit: input size mismatch");
    }

    ShuffleProofAudit proof;
    proof.challengeY = fsChallengeY_audit(commitmentsOrig, commitmentsShuf);
    proof.challengeZ = fsChallengeZ_audit(commitmentsOrig, commitmentsShuf,
                                          proof.challengeY);
    proof.shiftedOrig.resize(n);
    proof.shiftedShuf.resize(n);
    for (size_t i = 0; i < n; ++i) {
        proof.shiftedOrig[i] = scalarAdd(messages[i], proof.challengeY);
        proof.shiftedShuf[i] = scalarAdd(messages[permutation[i]], proof.challengeY);
    }
    // Random-linear-combination openings via z-powers. Bind PER-ELEMENT
    // (not just sum): Σ z^i · r_i.
    auto z_pow = powersOf(proof.challengeZ, n);
    proof.weightedOpeningOrig = scalarDot(z_pow, openingsOrig);
    proof.weightedOpeningShuf = scalarDot(z_pow, openingsShuf);
    return proof;
}

bool shuffleVerifyAudit(
    const ShuffleProofAudit& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    const size_t n = commitmentsOrig.size();
    if (commitmentsShuf.size() != n) return false;
    if (proof.shiftedOrig.size() != n || proof.shiftedShuf.size() != n) return false;

    R255Scalar y = fsChallengeY_audit(commitmentsOrig, commitmentsShuf);
    if (!(y == proof.challengeY)) return false;
    R255Scalar z = fsChallengeZ_audit(commitmentsOrig, commitmentsShuf, y);
    if (!(z == proof.challengeZ)) return false;

    // MULTISET-EQUALITY CHECK: sort both shifted vectors and compare.
    auto sortedOrig = proof.shiftedOrig;
    auto sortedShuf = proof.shiftedShuf;
    auto cmp = [](const R255Scalar& a, const R255Scalar& b) {
        return std::lexicographical_compare(
            a.bytes.begin(), a.bytes.end(),
            b.bytes.begin(), b.bytes.end());
    };
    std::sort(sortedOrig.begin(), sortedOrig.end(), cmp);
    std::sort(sortedShuf.begin(), sortedShuf.end(), cmp);
    for (size_t i = 0; i < n; ++i) {
        if (!(sortedOrig[i] == sortedShuf[i])) return false;
    }

    // PER-ELEMENT BINDING via random-linear-combination:
    //   c_i = commit(m_i, r_i) = g^{m_i} · h^{r_i}
    //   Homomorphic weighted product: Π c_i^{z^i} = g^{Σ z^i m_i} · h^{Σ z^i r_i}
    //   Prover's revealed shifted_i = m_i + y ⇒ m_i = shifted_i - y
    //   So Σ z^i m_i = Σ z^i · (shifted_i - y) = (Σ z^i shifted_i) - y · (Σ z^i)
    //   Verifier checks:
    //     Π c_i^{z^i} == commit(Σ z^i · shifted_i - y · Σ z^i, weightedOpening)
    auto z_pow = powersOf(z, n);

    auto verifySide = [&](const std::vector<PedersenCommitment>& C,
                          const std::vector<R255Scalar>& shifted,
                          const R255Scalar& weightedOpen) -> bool {
        // Weighted product of commitments: Σ z^i · c_i
        R255Point weightedC = R255Point::identity();
        for (size_t i = 0; i < n; ++i) {
            weightedC = pointAdd(weightedC, scalarMult(z_pow[i], C[i].c));
        }
        R255Scalar sumZ = R255Scalar::zero();
        R255Scalar sumZShifted = R255Scalar::zero();
        for (size_t i = 0; i < n; ++i) {
            sumZ = scalarAdd(sumZ, z_pow[i]);
            sumZShifted = scalarAdd(sumZShifted, scalarMul(z_pow[i], shifted[i]));
        }
        // expected_msg = sumZShifted - y * sumZ
        R255Scalar expectedMsg = scalarSub(sumZShifted, scalarMul(y, sumZ));
        R255Point expected = pointAdd(
            scalarMultBase(expectedMsg),
            scalarMult(weightedOpen, R255Point::pedersenH()));
        return weightedC == expected;
    };

    if (!verifySide(commitmentsOrig, proof.shiftedOrig, proof.weightedOpeningOrig))
        return false;
    if (!verifySide(commitmentsShuf, proof.shiftedShuf, proof.weightedOpeningShuf))
        return false;

    return true;
}

} // namespace mpstar
} // namespace volePSI
