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
    // Bound-check to prevent size_t → uint32_t truncation binding an
    // attacker-controlled |C|+2^32 to the same transcript as |C|.
    if (C.size() > 0xFFFFFFFFu || Cprime.size() > 0xFFFFFFFFu)
        throw std::runtime_error("transcriptBytes: |C| > 2^32 — cap exceeded");

    // Pre-reserve to avoid O(n²) reallocation on `insert(end(), ...)`.
    constexpr size_t kPointBytes = 32;   // Ristretto255 canonical encoding
    size_t domain_len = 0;
    for (const char* p = domain; *p; ++p) ++domain_len;
    std::vector<uint8_t> out;
    out.reserve(domain_len + 4 + C.size() * kPointBytes
                 + 4 + Cprime.size() * kPointBytes);

    out.insert(out.end(), domain, domain + domain_len);

    // Explicit little-endian u32 encoding (documented, portable across
    // architectures that this codebase targets).
    auto pushU32LE = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };

    pushU32LE(static_cast<uint32_t>(C.size()));
    for (const auto& c : C) out.insert(out.end(), c.c.bytes.begin(), c.c.bytes.end());
    pushU32LE(static_cast<uint32_t>(Cprime.size()));
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

    // Build the shuffled message vector m'_i = m_{π[i]}.
    std::vector<R255Scalar> shuffledMessages(n);
    for (size_t i = 0; i < n; ++i) {
        if (permutation[i] < 0 || static_cast<size_t>(permutation[i]) >= n)
            throw std::runtime_error("shuffleProveBg: permutation OOB");
        shuffledMessages[i] = messages[permutation[i]];
    }

    // Reveal messages and openings — the verifier will re-derive both
    // products from these AFTER checking each opening binds to its commit.
    p.messages         = messages;
    p.shuffledMessages = std::move(shuffledMessages);
    p.openingsOrig     = openingsOrig;
    p.openingsShuf     = openingsShuf;

    return p;
}

bool shuffleVerifyBg(
    const ShuffleProofBg& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    const size_t n = commitmentsOrig.size();
    if (commitmentsShuf.size() != n) return false;
    if (proof.messages.size()         != n) return false;
    if (proof.shuffledMessages.size() != n) return false;
    if (proof.openingsOrig.size()     != n) return false;
    if (proof.openingsShuf.size()     != n) return false;

    // Step 1: re-derive Fiat-Shamir challenges. Reject if prover used different.
    R255Scalar y = fsChallengeY_bg(commitmentsOrig, commitmentsShuf);
    R255Scalar x = fsChallengeX_bg(commitmentsOrig, commitmentsShuf, y);
    if (!(y == proof.challengeY)) return false;
    if (!(x == proof.challengeX)) return false;

    // Step 2: BIND messages to commitments — for every i verify that
    //         c_i  == g^{m_i}  · h^{r_i}     and
    //         c'_i == g^{m'_i} · h^{r'_i}
    // using the revealed openings. This is the point at which the prover
    // becomes committed to specific plaintext m_i, m'_i values.
    for (size_t i = 0; i < n; ++i) {
        PedersenCommitment want_orig = pedersenCommit(proof.messages[i],
                                                        proof.openingsOrig[i]);
        if (!(want_orig.c == commitmentsOrig[i].c)) return false;
        PedersenCommitment want_shuf = pedersenCommit(proof.shuffledMessages[i],
                                                        proof.openingsShuf[i]);
        if (!(want_shuf.c == commitmentsShuf[i].c)) return false;
    }

    // Step 3: SOUNDNESS — verifier recomputes both products independently
    // using the (now bound) messages under Fiat-Shamir challenges (x, y):
    //         P  = Π (x - (m_i  + y))
    //         P' = Π (x - (m'_i + y))
    // Schwartz-Zippel on the degree-n polynomial in a ~2^252-element field:
    // P = P' iff {m_i} and {m'_i} are equal multisets, except with
    // probability n / (2^252 - ...) which is negligible for any n < 2^100.
    R255Scalar prodOrig = polyEvalAtX(proof.messages,         x, y);
    R255Scalar prodShuf = polyEvalAtX(proof.shuffledMessages, x, y);
    if (!(prodOrig == prodShuf)) return false;

    return true;
}

} // namespace mpstar
} // namespace volePSI
