// R37/R27c: Pedersen vector commit + audit-mode shuffle proof tests.

#include "volePSI/MpPedersenVector.h"
#include "volePSI/MpPedersen.h"
#include "volePSI/MpRistretto.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;

struct Setup {
    std::vector<mp::R255Scalar> messages;
    std::vector<mp::R255Scalar> openingsOrig;
    std::vector<mp::R255Scalar> openingsShuf;
    std::vector<int> permutation;
    std::vector<mp::PedersenCommitment> origC;
    std::vector<mp::PedersenCommitment> shufC;
};

static Setup makeHonest(size_t n, std::mt19937& g) {
    Setup s;
    // Keep values small so we can craft targeted-tamper cases later.
    for (size_t i = 0; i < n; ++i)
        s.messages.push_back(mp::R255Scalar::fromU64(g() % 10000 + 1));
    s.openingsOrig = mp::freshOpenings(n);
    s.openingsShuf = mp::freshOpenings(n);
    s.permutation.resize(n);
    std::iota(s.permutation.begin(), s.permutation.end(), 0);
    std::shuffle(s.permutation.begin(), s.permutation.end(), g);
    s.origC = mp::pedersenCommitVector(s.messages, s.openingsOrig);
    std::vector<mp::R255Scalar> shufMsg(n);
    for (size_t i = 0; i < n; ++i) shufMsg[i] = s.messages[s.permutation[i]];
    s.shufC = mp::pedersenCommitVector(shufMsg, s.openingsShuf);
    return s;
}

// --------------------------------------------------------------
// Pedersen vector commit primitives
// --------------------------------------------------------------

bool test_vector_generators_distinct() {
    auto g0 = mp::pedersenVectorGenerator(0);
    auto g1 = mp::pedersenVectorGenerator(1);
    auto g0_again = mp::pedersenVectorGenerator(0);
    return !(g0 == g1) && (g0 == g0_again);
}

bool test_vector_commit_verify_open() {
    std::vector<mp::R255Scalar> msg = {
        mp::R255Scalar::fromU64(3),
        mp::R255Scalar::fromU64(5),
        mp::R255Scalar::fromU64(7),
    };
    auto r = mp::R255Scalar::random();
    auto c = mp::pedersenVectorCommit(msg, r);
    if (!mp::pedersenVectorVerify(c, msg, r)) return false;
    // Tampered opening or message → verify fails.
    auto badR = mp::R255Scalar::random();
    if (mp::pedersenVectorVerify(c, msg, badR)) return false;
    auto badMsg = msg;
    badMsg[1] = mp::R255Scalar::fromU64(42);
    if (mp::pedersenVectorVerify(c, badMsg, r)) return false;
    return true;
}

bool test_vector_homomorphic_add() {
    std::vector<mp::R255Scalar> m1 = {
        mp::R255Scalar::fromU64(1), mp::R255Scalar::fromU64(2)};
    std::vector<mp::R255Scalar> m2 = {
        mp::R255Scalar::fromU64(10), mp::R255Scalar::fromU64(20)};
    auto r1 = mp::R255Scalar::random();
    auto r2 = mp::R255Scalar::random();
    auto c1 = mp::pedersenVectorCommit(m1, r1);
    auto c2 = mp::pedersenVectorCommit(m2, r2);
    auto csum = mp::pedersenVectorAdd(c1, c2);
    std::vector<mp::R255Scalar> msum = {
        mp::scalarAdd(m1[0], m2[0]),
        mp::scalarAdd(m1[1], m2[1])};
    auto rsum = mp::scalarAdd(r1, r2);
    return mp::pedersenVectorVerify(csum, msum, rsum);
}

// --------------------------------------------------------------
// Audit-mode shuffle proof
// --------------------------------------------------------------

bool test_audit_shuffle_honest_accepts() {
    std::mt19937 g(0xA1);
    auto s = makeHonest(8, g);
    auto proof = mp::shuffleProveAudit(
        s.messages, s.openingsOrig, s.openingsShuf, s.permutation,
        s.origC, s.shufC);
    return mp::shuffleVerifyAudit(proof, s.origC, s.shufC);
}

bool test_audit_shuffle_message_swap_caught() {
    // Sum-preserving multiset tampering: replace (a, b) with (a+1, b-1).
    // R27b was documented to MISS this. R27c/audit should CATCH it.
    std::mt19937 g(0xA2);
    auto s = makeHonest(8, g);
    // Prover claims the ACTUAL shuffled messages, but the SHUFFLED
    // COMMITMENTS get tampered so their sum matches but multiset differs.
    auto orig = s.messages[s.permutation[0]];
    auto shifted_m0 = mp::scalarAdd(orig, mp::R255Scalar::fromU64(1));
    auto shifted_m1 = mp::scalarSub(s.messages[s.permutation[1]],
                                    mp::R255Scalar::fromU64(1));
    auto newR0 = mp::R255Scalar::random();
    auto newR1 = mp::R255Scalar::random();
    s.shufC[0] = mp::pedersenCommit(shifted_m0, newR0);
    s.shufC[1] = mp::pedersenCommit(shifted_m1, newR1);
    s.openingsShuf[0] = newR0;
    s.openingsShuf[1] = newR1;

    // Honest prover computes proof from ORIGINAL messages + permutation,
    // but the verifier sees the tampered shufC. The prover's
    // shiftedShuf values (m_{π(i)} + y) will match the sorted multiset
    // of orig (because prover uses actual permuted messages) but the
    // verifier will discover mismatch when checking against the
    // tampered commitments.
    auto proof = mp::shuffleProveAudit(
        s.messages, s.openingsOrig, s.openingsShuf, s.permutation,
        s.origC, s.shufC);
    return !mp::shuffleVerifyAudit(proof, s.origC, s.shufC);
}

bool test_audit_shuffle_random_corruption_caught() {
    std::mt19937 g(0xA3);
    auto s = makeHonest(8, g);
    auto badM = mp::R255Scalar::random();
    auto badR = mp::R255Scalar::random();
    s.shufC[3] = mp::pedersenCommit(badM, badR);
    s.openingsShuf[3] = badR;

    auto proof = mp::shuffleProveAudit(
        s.messages, s.openingsOrig, s.openingsShuf, s.permutation,
        s.origC, s.shufC);
    return !mp::shuffleVerifyAudit(proof, s.origC, s.shufC);
}

bool test_audit_shuffle_fs_tamper_caught() {
    std::mt19937 g(0xA4);
    auto s = makeHonest(8, g);
    auto proof = mp::shuffleProveAudit(
        s.messages, s.openingsOrig, s.openingsShuf, s.permutation,
        s.origC, s.shufC);
    proof.challengeY = mp::scalarAdd(proof.challengeY, mp::R255Scalar::one());
    return !mp::shuffleVerifyAudit(proof, s.origC, s.shufC);
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"vector_generators_distinct",       test_vector_generators_distinct},
        {"vector_commit_verify_open",        test_vector_commit_verify_open},
        {"vector_homomorphic_add",           test_vector_homomorphic_add},
        {"audit_shuffle_honest_accepts",     test_audit_shuffle_honest_accepts},
        {"audit_shuffle_message_swap_caught", test_audit_shuffle_message_swap_caught},
        {"audit_shuffle_random_corruption_caught", test_audit_shuffle_random_corruption_caught},
        {"audit_shuffle_fs_tamper_caught",   test_audit_shuffle_fs_tamper_caught},
    };
    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try { std::cout << (fn() ? "PASS" : "FAIL") << "\n"; if (!fn()) ++failures; }
        catch (const std::exception& e) { std::cout << "FAIL (" << e.what() << ")\n"; ++failures; }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
