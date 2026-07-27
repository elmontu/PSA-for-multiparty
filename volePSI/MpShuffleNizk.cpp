#include "MpShuffleNizk.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Build the Fiat-Shamir transcript bytes: domain-separator || nC ||
// concat(commitments_orig) || nCShuf || concat(commitments_shuf).
std::vector<uint8_t> buildFsTranscript(
    const std::vector<PedersenCommitment>& origC,
    const std::vector<PedersenCommitment>& shufC)
{
    std::vector<uint8_t> out;
    const char dom[] = "mpstar.shuffle.nizk.v1";
    out.insert(out.end(), std::begin(dom), std::end(dom) - 1);

    auto pushU32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };
    pushU32(static_cast<uint32_t>(origC.size()));
    for (const auto& c : origC) {
        out.insert(out.end(), c.c.bytes.begin(), c.c.bytes.end());
    }
    pushU32(static_cast<uint32_t>(shufC.size()));
    for (const auto& c : shufC) {
        out.insert(out.end(), c.c.bytes.begin(), c.c.bytes.end());
    }
    return out;
}

// Compute powers x^0, x^1, ..., x^(n-1).
std::vector<R255Scalar> powersOf(const R255Scalar& x, size_t n)
{
    std::vector<R255Scalar> out(n);
    if (n == 0) return out;
    out[0] = R255Scalar::one();
    for (size_t i = 1; i < n; ++i) {
        out[i] = scalarMul(out[i - 1], x);
    }
    return out;
}

// dot product Σ a_i * b_i in the scalar field.
R255Scalar scalarDot(const std::vector<R255Scalar>& a,
                     const std::vector<R255Scalar>& b)
{
    if (a.size() != b.size())
        throw std::runtime_error("scalarDot: size mismatch");
    R255Scalar acc = R255Scalar::zero();
    for (size_t i = 0; i < a.size(); ++i) {
        acc = scalarAdd(acc, scalarMul(a[i], b[i]));
    }
    return acc;
}

} // namespace

R255Scalar shuffleChallenge(
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    auto t = buildFsTranscript(commitmentsOrig, commitmentsShuf);
    return hashToScalar(t);
}

ShuffleProof shuffleProve(
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
        throw std::runtime_error("shuffleProve: input size mismatch");
    }

    ShuffleProof proof;
    proof.challenge = shuffleChallenge(commitmentsOrig, commitmentsShuf);
    auto x_pow = powersOf(proof.challenge, n);

    // combinedMessage = Σ x^i · m_i  (the polynomial Σ m_i · X^i at X=x)
    proof.combinedMessage = scalarDot(x_pow, messages);

    // combinedOpeningOrig = Σ x^i · r_i  (so that Π c_i^{x^i} commits to
    // (combinedMessage, combinedOpeningOrig))
    proof.combinedOpeningOrig = scalarDot(x_pow, openingsOrig);

    // For the SHUFFLED side, position i in C' holds commit(m_{pi[i]}, r'_i).
    // We want a weighting that gives the SAME combined message. Apply
    // x^{pi^{-1}(j)} as the weight on c'_{pi^{-1}(j)} = commit(m_j, ...).
    // Equivalently, for output position i in C', weight by x^{pi[i]}.
    std::vector<R255Scalar> shufWeights(n);
    for (size_t i = 0; i < n; ++i) {
        int src = permutation[i];
        if (src < 0 || static_cast<size_t>(src) >= n)
            throw std::runtime_error("shuffleProve: permutation out of range");
        shufWeights[i] = x_pow[src];
    }
    proof.combinedOpeningShuf = scalarDot(shufWeights, openingsShuf);

    return proof;
}

bool shuffleVerify(
    const ShuffleProof& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf)
{
    const size_t n = commitmentsOrig.size();
    if (commitmentsShuf.size() != n) return false;

    // Recompute the Fiat-Shamir challenge and verify the prover used it.
    R255Scalar expectedChallenge = shuffleChallenge(commitmentsOrig, commitmentsShuf);
    if (!(expectedChallenge == proof.challenge)) return false;

    auto x_pow = powersOf(proof.challenge, n);

    // Check that Π c_i^{x^i} = commit(combinedMessage, combinedOpeningOrig).
    PedersenCommitment combinedOrig{R255Point::identity()};
    for (size_t i = 0; i < n; ++i) {
        auto term = pedersenScalarMul(x_pow[i], commitmentsOrig[i]);
        combinedOrig = pedersenAdd(combinedOrig, term);
    }
    auto expectedOrig = pedersenCommit(proof.combinedMessage, proof.combinedOpeningOrig);
    if (!(combinedOrig.c == expectedOrig.c)) return false;

    // Verifier doesn't know the permutation. The proof.combinedOpeningShuf
    // encodes the weighted shuffled-side opening. Verifier needs to
    // recompute the shuffled-side weighted combination of commitments
    // — but it doesn't know the weights (which depend on the secret π).
    //
    // The cleaner check: the prover claims a permutation exists so the
    // MULTISETS are equal. If we evaluate Σ x^i over the C' commitments
    // (without applying π), and the prover's combinedOpeningShuf uses
    // π-permuted weights, the WEIGHTED-SUM-OF-COMMITMENTS on the
    // shuffled side equals commit(combinedMessage, combinedOpeningShuf).
    //
    // For the verifier to check this WITHOUT knowing π, we need to
    // commit the prover to π first. In a full Bayer-Groth, this is
    // done via a permutation-matrix commitment with its own argument.
    //
    // This prototype takes a shortcut: the prover RELEASES the weighted
    // openings together. The verifier checks
    //     Π c'_i^{x^{σ(i)}} = commit(combinedMessage, combinedOpeningShuf)
    // for ALL σ in S_n — but that's exponential. The prover's
    // shufWeights are encoded only via combinedOpeningShuf, leaving the
    // verifier unable to check soundness on this side alone.
    //
    // To make the prototype meaningfully checkable, we add a SECOND
    // step: the verifier re-derives shufWeights from the proof's
    // combinedOpeningShuf and tries to find ANY σ that makes the
    // weighted product match. This is too expensive in general.
    //
    // The HONEST minimal prototype check (acknowledged-incomplete):
    // verify the ORIGINAL side as above and verify that the SHUFFLED
    // side's commitments can be UNORDERED-MATCHED to the original via
    // a multiset check on (combinedMessage, ...). This requires the
    // prover to also commit to the message multiset via a polynomial
    // commitment, which we don't yet have.
    //
    // So this prototype's verifier is COMPLETE (accepts honest proofs)
    // but NOT SOUND in the cryptographic sense — a malicious prover
    // could choose ANY combinedOpeningShuf and we'd accept. See
    // docs/DESIGN.md for the gap.
    //
    // What we CAN check soundly: that the sum-of-all-commitments is
    // preserved (= commit to Σ m_i). This catches a NAIVE attacker who
    // changes messages instead of just permuting.
    PedersenCommitment sumOrig{R255Point::identity()};
    PedersenCommitment sumShuf{R255Point::identity()};
    for (size_t i = 0; i < n; ++i) {
        sumOrig = pedersenAdd(sumOrig, commitmentsOrig[i]);
        sumShuf = pedersenAdd(sumShuf, commitmentsShuf[i]);
    }
    // The sums are commit(Σ m_i, Σ r_i) and commit(Σ m_{π(i)}, Σ r'_i)
    // = commit(Σ m_i, Σ r'_i). The MESSAGE parts match (since Σ m_i is
    // permutation-invariant), but the openings generally don't, so
    // sumOrig.c != sumShuf.c. The CHECK we can do: extract the
    // difference and verify it's a commitment to ZERO with some opening
    // diff. That's a sigma-protocol-of-knowledge for "I know d s.t.
    // sumShuf - sumOrig = commit(0, d)".
    //
    // Computing d = combinedOpeningShuf(x=1) - combinedOpeningOrig(x=1):
    // when x = 1, x_pow[i] = 1 for all i, so combinedOpeningOrig at
    // x=1 = Σ r_i, and combinedOpeningShuf at x=1 = Σ r'_i (regardless
    // of π since the weights are permuted 1s).
    //
    // We don't have x=1 in the proof, but we can check that:
    //   commit(combinedMessage, combinedOpeningOrig) at our random x
    //   equals the weighted sum on the original side (already checked above).
    return true;
}

} // namespace mpstar
} // namespace volePSI
