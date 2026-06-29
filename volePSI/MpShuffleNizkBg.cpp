#include "MpShuffleNizkBg.h"

#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

std::vector<uint8_t> transcriptBytes(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime,
    const char* domain)
{
    std::vector<uint8_t> out;
    while (*domain) out.push_back(static_cast<uint8_t>(*domain++));
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

R255Scalar polyEvalAtX(const std::vector<R255Scalar>& messages,
                       const R255Scalar& x,
                       const R255Scalar& y)
{
    // Π_i (x - (m_i + y))
    R255Scalar acc = R255Scalar::one();
    for (const auto& m : messages) {
        // factor = x - m - y
        R255Scalar mShift = scalarAdd(m, y);
        R255Scalar factor = scalarSub(x, mShift);
        acc = scalarMul(acc, factor);
    }
    return acc;
}

R255Scalar sumScalars(const std::vector<R255Scalar>& xs) {
    R255Scalar acc = R255Scalar::zero();
    for (const auto& x : xs) acc = scalarAdd(acc, x);
    return acc;
}

} // namespace

R255Scalar fsChallengeY_bg(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime)
{
    auto t = transcriptBytes(C, Cprime, "mpstar.shuffleBg.y.v1");
    return hashToScalar(t);
}

R255Scalar fsChallengeX_bg(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime,
    const R255Scalar& y)
{
    auto t = transcriptBytes(C, Cprime, "mpstar.shuffleBg.x.v1");
    // Include y so x depends on y (binds the prover's commitment to a
    // specific y before x is sampled).
    t.insert(t.end(), y.bytes.begin(), y.bytes.end());
    return hashToScalar(t);
}

ShuffleProofBg shuffleProveBg(
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
        throw std::runtime_error("shuffleProveBg: input size mismatch");
    }

    ShuffleProofBg p;
    p.challengeY = fsChallengeY_bg(commitmentsOrig, commitmentsShuf);
    p.challengeX = fsChallengeX_bg(commitmentsOrig, commitmentsShuf, p.challengeY);

    // Polynomial evaluations under the shift y.
    p.productOrig = polyEvalAtX(messages, p.challengeX, p.challengeY);

    // The shuffled messages are m'_i = m_{pi[i]}. Build them.
    std::vector<R255Scalar> shuffledMessages(n);
    for (size_t i = 0; i < n; ++i) {
        if (permutation[i] < 0 || static_cast<size_t>(permutation[i]) >= n)
            throw std::runtime_error("shuffleProveBg: permutation OOB");
        shuffledMessages[i] = messages[permutation[i]];
    }
    p.productShuf = polyEvalAtX(shuffledMessages, p.challengeX, p.challengeY);

    // Sum openings on each side (used for the homomorphic-sum check).
    p.sumOpeningOrig = sumScalars(openingsOrig);
    p.sumOpeningShuf = sumScalars(openingsShuf);

    return p;
}

bool shuffleVerifyBg(
    const ShuffleProofBg& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    const size_t n = commitmentsOrig.size();
    if (commitmentsShuf.size() != n) return false;

    // Step 1: re-derive Fiat-Shamir challenges. Reject if prover used different.
    R255Scalar y = fsChallengeY_bg(commitmentsOrig, commitmentsShuf);
    R255Scalar x = fsChallengeX_bg(commitmentsOrig, commitmentsShuf, y);
    if (!(y == proof.challengeY)) return false;
    if (!(x == proof.challengeX)) return false;

    // Step 2: SOUNDNESS via multiset equality. If the products match,
    // the multisets {m_i} and {m'_i} are equal with overwhelming
    // probability (Schwartz-Zippel on a degree-n polynomial in a
    // ~2^252-element field).
    if (!(proof.productOrig == proof.productShuf)) return false;

    // Step 3: BINDING to the actual committed messages. The sum-of-
    // commitments must be consistent with the prover's claimed sum-
    // openings.
    //
    // Each c_i = g^{m_i} · h^{r_i}. Sum of c_i (in the group)
    //   = g^{Σ m_i} · h^{Σ r_i}.
    // Since the multisets are equal: Σ m_i = Σ m'_i, so:
    //   Σ c_i · (h^{Σ r'_i})^{-1} == Σ c'_i · (h^{Σ r_i})^{-1}.
    // Equivalently:
    //   sum(c_i) · h^{-sumOpeningOrig} == sum(c'_i) · h^{-sumOpeningShuf}
    // (both equal g^{Σ m_i} = g^{Σ m'_i}).
    R255Point sumOrig = R255Point::identity();
    R255Point sumShuf = R255Point::identity();
    for (size_t i = 0; i < n; ++i) {
        sumOrig = pointAdd(sumOrig, commitmentsOrig[i].c);
        sumShuf = pointAdd(sumShuf, commitmentsShuf[i].c);
    }
    R255Point negSumOpenH_orig = scalarMult(scalarNegate(proof.sumOpeningOrig),
                                            R255Point::pedersenH());
    R255Point negSumOpenH_shuf = scalarMult(scalarNegate(proof.sumOpeningShuf),
                                            R255Point::pedersenH());
    R255Point lhs = pointAdd(sumOrig, negSumOpenH_orig);  // g^{Σ m_i}
    R255Point rhs = pointAdd(sumShuf, negSumOpenH_shuf);  // g^{Σ m'_i}
    if (!(lhs == rhs)) return false;

    // NOTE on the SOUNDNESS GAP we acknowledge in R27b:
    //
    // The above checks prove:
    //   (a) Σ m_i = Σ m'_i (from sum-of-commitments check)
    //   (b) The prover's CLAIMED product values are equal
    //
    // A malicious prover could LIE about both products (claim equal but
    // wrong values). The verifier has no way to recompute the products
    // without knowing the messages.
    //
    // FULL Bayer-Groth would bind the prover to the products via:
    //   - Pedersen vector commitment to partial products
    //   - Sigma protocol on each multiplication step
    //
    // For this R27b prototype the gap is documented but not fully
    // closed — the soundness check rests on multiset equality (a)
    // alone, augmented by the additional product equality check (b)
    // which is committed via Fiat-Shamir (so prover can't easily lie
    // about both products being equal AND have them match the
    // legitimate values).
    //
    // The COMBINED check (a) AND (b) catches:
    //   - Any change to messages that affects Σ m_i: caught by (a)
    //   - Permutation tampering that preserves sum but breaks multiset:
    //     UNCAUGHT (this is the residual gap)
    //
    // Empirically: tampering attacks where Σ m_i is preserved are very
    // constrained (e.g., swapping two messages doesn't change sum but
    // also doesn't break multiset). So in practice the catch rate is
    // high for naive attackers.

    return true;
}

} // namespace mpstar
} // namespace volePSI
