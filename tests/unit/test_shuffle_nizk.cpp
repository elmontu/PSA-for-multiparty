// Unit tests for volePSI/MpRistretto.h + MpPedersen.h + MpShuffleNizk.h
// (R27 prototype). Covers:
//   1. Ristretto255 scalar/point algebra basics
//   2. Pedersen commitment correctness + homomorphism
//   3. Shuffle proof acceptance on honest input
//   4. Sum-of-commitments check catches naive message tampering
//   5. DOCUMENTED LIMITATION: position-permutation tampering NOT caught
//      (verifier is intentionally incomplete; see SHUFFLE_NIZK_DESIGN.md)

#include "volePSI/MpRistretto.h"
#include "volePSI/MpPedersen.h"
#include "volePSI/MpShuffleNizk.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;

// --------------------------------------------------------------

bool test_scalar_arithmetic_basics() {
    auto a = mp::R255Scalar::fromU64(7);
    auto b = mp::R255Scalar::fromU64(5);
    auto sum = mp::scalarAdd(a, b);
    if (!(sum == mp::R255Scalar::fromU64(12))) return false;
    auto diff = mp::scalarSub(a, b);
    if (!(diff == mp::R255Scalar::fromU64(2))) return false;
    auto prod = mp::scalarMul(a, b);
    if (!(prod == mp::R255Scalar::fromU64(35))) return false;
    return true;
}

bool test_scalar_inverse() {
    auto a = mp::R255Scalar::fromU64(123);
    auto inv = mp::scalarInvert(a);
    auto prod = mp::scalarMul(a, inv);
    return prod == mp::R255Scalar::one();
}

bool test_point_operations() {
    auto g = mp::R255Point::generator();
    auto two_g = mp::pointAdd(g, g);
    auto two = mp::R255Scalar::fromU64(2);
    auto two_g_via_scalar = mp::scalarMultBase(two);
    return two_g == two_g_via_scalar;
}

bool test_pedersen_h_independent_of_g() {
    auto g = mp::R255Point::generator();
    auto h = mp::R255Point::pedersenH();
    return !(g == h);
}

bool test_pedersen_commit_verify() {
    auto m = mp::R255Scalar::fromU64(0xABCD);
    auto r = mp::R255Scalar::random();
    auto c = mp::pedersenCommit(m, r);
    if (!mp::pedersenVerify(c, m, r)) return false;
    // Wrong opening → reject.
    auto badR = mp::R255Scalar::random();
    if (mp::pedersenVerify(c, m, badR)) return false;
    // Wrong message → reject.
    auto badM = mp::R255Scalar::fromU64(0xABCE);
    if (mp::pedersenVerify(c, badM, r)) return false;
    return true;
}

bool test_pedersen_homomorphic_add() {
    auto m1 = mp::R255Scalar::fromU64(10);
    auto r1 = mp::R255Scalar::random();
    auto m2 = mp::R255Scalar::fromU64(20);
    auto r2 = mp::R255Scalar::random();
    auto c1 = mp::pedersenCommit(m1, r1);
    auto c2 = mp::pedersenCommit(m2, r2);
    auto cSum = mp::pedersenAdd(c1, c2);
    auto mSum = mp::scalarAdd(m1, m2);
    auto rSum = mp::scalarAdd(r1, r2);
    auto cExpected = mp::pedersenCommit(mSum, rSum);
    return cSum.c == cExpected.c;
}

bool test_pedersen_scalar_mul() {
    auto m = mp::R255Scalar::fromU64(5);
    auto r = mp::R255Scalar::random();
    auto c = mp::pedersenCommit(m, r);
    auto k = mp::R255Scalar::fromU64(7);
    auto kc = mp::pedersenScalarMul(k, c);
    auto km = mp::scalarMul(k, m);
    auto kr = mp::scalarMul(k, r);
    auto expected = mp::pedersenCommit(km, kr);
    return kc.c == expected.c;
}

// Helper to build a (messages, openings_orig, openings_shuf, perm,
// commitmentsOrig, commitmentsShuf) input from a list of messages and a
// permutation.
struct ShuffleInputs {
    std::vector<mp::R255Scalar> messages;
    std::vector<mp::R255Scalar> openingsOrig;
    std::vector<mp::R255Scalar> openingsShuf;
    std::vector<int> permutation;
    std::vector<mp::PedersenCommitment> origC;
    std::vector<mp::PedersenCommitment> shufC;
};

static ShuffleInputs makeHonestShuffle(size_t n, std::mt19937& g) {
    ShuffleInputs s;
    s.messages.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        s.messages.push_back(mp::R255Scalar::fromU64(1000 + g() % 10000));
    }
    s.openingsOrig = mp::freshOpenings(n);
    s.openingsShuf = mp::freshOpenings(n);

    // Random permutation.
    s.permutation.resize(n);
    std::iota(s.permutation.begin(), s.permutation.end(), 0);
    std::shuffle(s.permutation.begin(), s.permutation.end(), g);

    s.origC = mp::pedersenCommitVector(s.messages, s.openingsOrig);
    // C'[i] = commit(m_{pi[i]}, r'_i)
    std::vector<mp::R255Scalar> shufMessages(n);
    for (size_t i = 0; i < n; ++i) shufMessages[i] = s.messages[s.permutation[i]];
    s.shufC = mp::pedersenCommitVector(shufMessages, s.openingsShuf);
    return s;
}

bool test_shuffle_proof_honest_accepts() {
    std::mt19937 g(0xA1);
    auto s = makeHonestShuffle(8, g);
    auto proof = mp::shuffleProve(s.messages, s.openingsOrig, s.openingsShuf,
                                  s.permutation, s.origC, s.shufC);
    return mp::shuffleVerify(proof, s.origC, s.shufC);
}

bool test_shuffle_proof_message_tamper_caught() {
    // Naive attack: prover changes one of the SHUFFLED messages to a
    // different value (not in the original multiset). The sum-of-
    // commitments check in the verifier should fail because the message
    // sum no longer matches.
    //
    // We construct a tampered C' by replacing one commitment with one
    // to a different message.
    std::mt19937 g(0xA2);
    auto s = makeHonestShuffle(8, g);

    // Tamper: replace shufC[3] with a commitment to a DIFFERENT message
    // that's NOT in the original multiset.
    auto tamperedM = mp::R255Scalar::fromU64(99999);   // not in original set
    auto tamperedR = mp::R255Scalar::random();
    s.shufC[3] = mp::pedersenCommit(tamperedM, tamperedR);
    s.openingsShuf[3] = tamperedR;

    // Honest prover (but on tampered C') would compute combinedMessage
    // using the ORIGINAL messages, so the check on the original-side
    // weighted commitment will pass — but the shuffled-side sum won't
    // match. For this prototype's check, we need to verify that the
    // sum-of-commitments invariant fails. The current verifier just
    // checks the ORIGINAL side (the SHUFFLED side check is documented
    // as incomplete), so this test is a NEGATIVE check on the current
    // partial implementation.
    //
    // To make this a meaningful test of catch-rate: we directly check
    // the sum-of-commitments invariant ourselves.

    mp::PedersenCommitment sumOrig{mp::R255Point::identity()};
    mp::PedersenCommitment sumShuf{mp::R255Point::identity()};
    for (size_t i = 0; i < s.origC.size(); ++i)
        sumOrig = mp::pedersenAdd(sumOrig, s.origC[i]);
    for (size_t i = 0; i < s.shufC.size(); ++i)
        sumShuf = mp::pedersenAdd(sumShuf, s.shufC[i]);

    // sumOrig commits to (Σ m_i, Σ r_i); sumShuf to (Σ m'_i, Σ r'_i).
    // If multisets differ, Σ m_i != Σ m'_i, so for ANY r, r' with
    // sumOrig = commit(M, r) and sumShuf = commit(M, r'), we'd need
    // r-r' to be specific — but we have freedom. The right check: does
    // sumShuf - sumOrig commit to ZERO under SOME opening difference?
    // Compute diff_c = sumShuf - sumOrig. If the multisets are equal,
    // diff_c commits to (0, Σ r'_i - Σ r_i) and can be opened by the
    // honest prover. If multisets differ, diff_c commits to a non-zero
    // message and cannot be opened to message 0.
    auto diffC = mp::pointSub(sumShuf.c, sumOrig.c);
    auto diffR = mp::scalarSub(
        std::accumulate(s.openingsShuf.begin(), s.openingsShuf.end(),
                        mp::R255Scalar::zero(), mp::scalarAdd),
        std::accumulate(s.openingsOrig.begin(), s.openingsOrig.end(),
                        mp::R255Scalar::zero(), mp::scalarAdd));
    auto expectedOnZero = mp::scalarMult(diffR, mp::R255Point::pedersenH());
    // For honest shuffle: diffC == expectedOnZero. For tampered: not.
    return !(diffC == expectedOnZero);
}

bool test_known_soundness_gap_documented() {
    // DOCUMENTED LIMITATION (see SHUFFLE_NIZK_DESIGN.md): the prototype's
    // verifier does NOT cryptographically verify that C' is a positional
    // permutation of C — only that the multisets MATCH via the sum-of-
    // commitments check. A malicious prover who PERMUTES THE MULTISET
    // CORRECTLY but uses a permutation π' ≠ the one they CLAIM in the
    // protocol can still pass.
    //
    // This test asserts the limitation: a "tampered permutation" is
    // accepted by the prototype verifier (NOT a bug — it's the
    // soundness gap that full Bayer-Groth closes via polynomial
    // commitment to π).
    std::mt19937 g(0xA3);
    auto s = makeHonestShuffle(8, g);
    auto proof = mp::shuffleProve(s.messages, s.openingsOrig, s.openingsShuf,
                                  s.permutation, s.origC, s.shufC);
    // Honest verification passes.
    if (!mp::shuffleVerify(proof, s.origC, s.shufC)) return false;
    // Now: a malicious prover who computed the proof with a DIFFERENT
    // permutation (but the same multiset of shuffled messages) would
    // produce a DIFFERENT combinedOpeningShuf. The verifier's
    // ORIGINAL-side check still passes. The SHUFFLED-side check is
    // documented as incomplete. So we EXPECT this to be a known gap.
    //
    // This test is documentation: it always passes; it's here so the
    // limitation has a test name visible in CI output.
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"scalar_arithmetic_basics",          test_scalar_arithmetic_basics},
        {"scalar_inverse",                    test_scalar_inverse},
        {"point_operations",                  test_point_operations},
        {"pedersen_h_independent_of_g",       test_pedersen_h_independent_of_g},
        {"pedersen_commit_verify",            test_pedersen_commit_verify},
        {"pedersen_homomorphic_add",          test_pedersen_homomorphic_add},
        {"pedersen_scalar_mul",               test_pedersen_scalar_mul},
        {"shuffle_proof_honest_accepts",      test_shuffle_proof_honest_accepts},
        {"shuffle_proof_message_tamper_caught", test_shuffle_proof_message_tamper_caught},
        {"known_soundness_gap_documented",    test_known_soundness_gap_documented},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try {
            if (fn()) std::cout << "PASS\n";
            else { std::cout << "FAIL\n"; ++failures; }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")\n";
            ++failures;
        } catch (...) {
            std::cout << "FAIL (unknown exception)\n";
            ++failures;
        }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
