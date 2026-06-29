// Unit tests for volePSI/MpAuthCascade.h — in-memory simulation of the
// MAC-propagating cascade. Exercises:
//   1. Single-round propagation: invariant survives permutation + re-MAC
//   2. Multi-round (N-1 rounds): final reconstruction equals composite perm
//   3. Tampering by a malicious peer mid-cascade is detected at the next
//      round's verifyAuthShares (before any output leaks)
//   4. Tampering at the END is detected by finalVerify

#include "volePSI/MpAuthCascade.h"
#include "volePSI/MpMac.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static bool blocksEq(const block& a, const block& b) {
    return std::memcmp(&a, &b, sizeof(block)) == 0;
}

static block makeSeed(uint8_t b) {
    block out;
    std::memset(&out, b, sizeof(out));
    return out;
}

static std::vector<block> randomVec(oc::PRNG& prng, size_t n) {
    std::vector<block> v(n);
    for (auto& b : v) b = prng.get<block>();
    return v;
}

// Construct an initial CascadeColumn with random data and valid MAC under α.
// Returns the underlying plaintext for cross-checking the cascade output.
static std::vector<block> initColumn(oc::PRNG& prng, size_t C,
                                     const block& alpha,
                                     mp::CascadeColumn& col)
{
    auto plain = randomVec(prng, C);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);
    col.sp   = std::move(s1);
    col.peer = std::move(s2);
    return plain;
}

// Apply a permutation to a vector (matches permuteAuth semantics:
// out[i] = in[dest[i]]).
static std::vector<block> applyPerm(const std::vector<block>& in,
                                    const std::vector<int>& dest)
{
    std::vector<block> out(in.size());
    for (size_t i = 0; i < in.size(); ++i) out[i] = in[dest[i]];
    return out;
}

// --------------------------------------------------------------

bool test_single_round_preserves_plaintext() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0x10));

    const size_t N = 3, C = 8;
    std::vector<mp::CascadeColumn> incoming(N);
    std::vector<std::vector<block>> plains(N);

    block alphaOld = prng.get<block>();
    for (size_t c = 0; c < N; ++c)
        plains[c] = initColumn(prng, C, alphaOld, incoming[c]);

    block roundSeed = prng.get<block>();
    auto perm = mp::randomPermutation(C, roundSeed);
    block alphaNew = prng.get<block>();

    oc::PRNG sharingPrng;
    sharingPrng.SetSeed(prng.get<block>());

    mp::CascadeRoundOutput out;
    if (!mp::cascadeRound(incoming, perm, alphaOld, alphaNew, sharingPrng, out)) return false;

    // Verify each output column's invariant under alphaNew.
    for (size_t c = 0; c < N; ++c) {
        if (!mp::verifyAuthShares(out.spState[c], out.peerHandoff[c], alphaNew)) return false;
        // Joint reconstruction must equal applyPerm(plain).
        auto expected = applyPerm(plains[c], perm);
        for (size_t i = 0; i < C; ++i) {
            block joint = out.spState[c].data[i] ^ out.peerHandoff[c].data[i];
            if (!blocksEq(joint, expected[i])) return false;
        }
    }
    return true;
}

bool test_multi_round_cascade_composes() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0x20));

    const size_t N = 4, C = 16;  // N-1 = 3 cascade rounds
    std::vector<mp::CascadeColumn> state(N);
    std::vector<std::vector<block>> plains(N);

    std::array<uint8_t, 32> spKeyBytes;
    std::array<uint8_t, 32> sessionId;
    auto fillRand = [&](std::array<uint8_t, 32>& arr) {
        for (auto& b : arr) b = prng.get<uint8_t>();
    };
    fillRand(spKeyBytes);
    fillRand(sessionId);

    block alpha0 = mp::deriveMacKey(spKeyBytes, sessionId, 0);
    for (size_t c = 0; c < N; ++c)
        plains[c] = initColumn(prng, C, alpha0, state[c]);

    // Capture the composite permutation as we go for cross-check.
    std::vector<int> compositePerm(C);
    std::iota(compositePerm.begin(), compositePerm.end(), 0);

    oc::PRNG sharingPrng;
    sharingPrng.SetSeed(prng.get<block>());

    block currentAlpha = alpha0;
    for (uint32_t k = 0; k < N - 1; ++k) {
        block roundSeed = mp::deriveMacKey(spKeyBytes, sessionId, 100 + k);  // unrelated key for the dest
        auto perm = mp::randomPermutation(C, roundSeed);
        block nextAlpha = mp::deriveMacKey(spKeyBytes, sessionId, k + 1);

        mp::CascadeRoundOutput out;
        if (!mp::cascadeRound(state, perm, currentAlpha, nextAlpha, sharingPrng, out)) return false;

        // Rebuild `state` for the next iteration: SP keeps spState, the
        // active sender hands peerHandoff to the next sender (in our
        // simulation that's just the same vector slot — only one peer at
        // a time).
        for (size_t c = 0; c < N; ++c) {
            state[c].sp   = std::move(out.spState[c]);
            state[c].peer = std::move(out.peerHandoff[c]);
        }
        currentAlpha = nextAlpha;

        // Composite perm so far: applyPerm gives out[i] = in[perm[i]].
        // Composing two rounds: row at position i AFTER round k+1 came
        // from position perm_{k+1}[i] AFTER round k, which itself came
        // from position compositePerm[perm_{k+1}[i]] in the original.
        std::vector<int> newComp(C);
        for (size_t i = 0; i < C; ++i) newComp[i] = compositePerm[perm[i]];
        compositePerm = std::move(newComp);
    }

    // Final verification.
    std::vector<mp::AuthShare> spStateFinal(N), peerStateFinal(N);
    for (size_t c = 0; c < N; ++c) {
        spStateFinal[c]   = std::move(state[c].sp);
        peerStateFinal[c] = std::move(state[c].peer);
    }
    std::vector<std::vector<block>> outPlain;
    if (!mp::finalVerify(spStateFinal, peerStateFinal, currentAlpha, outPlain)) return false;

    // Each output column should equal compositePerm applied to the original plain.
    for (size_t c = 0; c < N; ++c) {
        for (size_t i = 0; i < C; ++i) {
            block expected = plains[c][compositePerm[i]];
            if (!blocksEq(outPlain[c][i], expected)) return false;
        }
    }
    return true;
}

bool test_tampering_caught_at_next_round() {
    // Setup: simulate cascade round 0 honestly, then have the peer tamper
    // with its handed-off state before round 1 begins. Round 1's incoming
    // verification should fail.
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0x30));

    const size_t N = 2, C = 8;
    std::vector<mp::CascadeColumn> state(N);
    block alpha0 = prng.get<block>();
    for (size_t c = 0; c < N; ++c) initColumn(prng, C, alpha0, state[c]);

    auto perm0 = mp::randomPermutation(C, prng.get<block>());
    block alpha1 = prng.get<block>();
    oc::PRNG sharingPrng;
    sharingPrng.SetSeed(prng.get<block>());

    mp::CascadeRoundOutput round0;
    if (!mp::cascadeRound(state, perm0, alpha0, alpha1, sharingPrng, round0)) return false;

    // Malicious peer flips one bit of data in column 0, row 3 — without
    // updating the tag. The MAC invariant for round 0's output is now broken.
    auto* p = reinterpret_cast<uint8_t*>(&round0.peerHandoff[0].data[3]);
    p[0] ^= 0x40;

    // Stage for round 1.
    for (size_t c = 0; c < N; ++c) {
        state[c].sp   = std::move(round0.spState[c]);
        state[c].peer = std::move(round0.peerHandoff[c]);
    }

    auto perm1 = mp::randomPermutation(C, prng.get<block>());
    block alpha2 = prng.get<block>();
    mp::CascadeRoundOutput round1;
    bool ok = mp::cascadeRound(state, perm1, alpha1, alpha2, sharingPrng, round1);

    // We EXPECT round 1 to refuse to proceed (return false).
    return !ok;
}

bool test_tampering_at_final_reveal_caught() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0x40));

    const size_t N = 2, C = 8;
    std::vector<mp::CascadeColumn> state(N);
    block alpha = prng.get<block>();
    for (size_t c = 0; c < N; ++c) initColumn(prng, C, alpha, state[c]);

    std::vector<mp::AuthShare> spState(N), peerState(N);
    for (size_t c = 0; c < N; ++c) {
        spState[c]   = std::move(state[c].sp);
        peerState[c] = std::move(state[c].peer);
    }

    // Tamper: flip a bit in peerState's data without updating tag.
    auto* p = reinterpret_cast<uint8_t*>(&peerState[1].data[2]);
    p[1] ^= 0x01;

    std::vector<std::vector<block>> outPlain;
    bool ok = mp::finalVerify(spState, peerState, alpha, outPlain);
    if (ok) return false;             // must reject
    if (!outPlain.empty()) return false;  // and not leak partial output
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"single_round_preserves_plaintext",  test_single_round_preserves_plaintext},
        {"multi_round_cascade_composes",      test_multi_round_cascade_composes},
        {"tampering_caught_at_next_round",    test_tampering_caught_at_next_round},
        {"tampering_at_final_reveal_caught",  test_tampering_at_final_reveal_caught},
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
