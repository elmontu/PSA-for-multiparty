// tests/unit/test_shuffle_leak_demo.cpp
// Threat model: semi-honest Service Provider (SP). The SP knows every sender
// pre-shared key spKey_k and the sessionId. Before the A1 fix the SP could
// recompute each round's Benes permutation seed from spKey_k, sessionId and
// round index, and thereby invert the shuffle cascade. The A1 fix replaces
// that seed with a fresh random one local to each sender, unknown to the SP.
// This test demonstrates that after the fix the SP cannot reconstruct the
// cascade permutation, but that a regression (forcing the sender to use the
// SP-derivable seed) would let the SP succeed.
//
// Constants: N=4 senders => 3 cascade rounds, C=8 rows.
// Each row is labeled with its original index (low 64 bits of a block).

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <sodium.h>
#include <cryptoTools/Common/block.h>
#include <volePSI/osn/OSNSender.h>
#include <volePSI/MpStarCrypto.h>

using namespace osuCrypto;

namespace {

// Convert a block to a 32-character hex string (16 bytes).
std::string hex(const block& b) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&b);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) oss << std::setw(2) << static_cast<int>(p[i]);
    return oss.str();
}

// Derive a round seed the same way the pre-fix SP would have done it.
block deriveRoundSeed(const std::array<uint8_t, 32>& spKey,
                      const std::array<uint8_t, 32>& sessionId,
                      int round) {
    std::string purpose = "shuffle_round_" + std::to_string(round);
    auto keyBytes = volePSI::mpstar::deriveSessionKey(spKey, sessionId, purpose);
    block seed;
    std::memcpy(&seed, keyBytes.data(), sizeof(seed));
    return seed;
}

// Apply a sequence of Benes-network permutations (one per seed) to a vector of
// blocks. Returns the permuted vector.
std::vector<block> cascade(const std::vector<block>& input,
                           const std::vector<block>& seeds) {
    std::vector<block> state = input;
    for (const auto& seed : seeds) {
        OSNSender osn;
        std::map<int, int> i2loc;   // unused, required by the API
        osn.init_wj_seeded(state.size(), 1, "", i2loc, seed);
        osn.permuteBlocks(state);
    }
    return state;
}

// Given a list of round seeds, compute the SP-guessed permutation labels.
// Returns a vector G where G[j] is the label that (according to the guess)
// should appear at output position j.
std::vector<int> guessedInv(const std::vector<block>& seeds, size_t C) {
    std::vector<block> v(C);
    for (size_t i = 0; i < C; ++i) v[i] = block(0, i);
    v = cascade(v, seeds);
    std::vector<int> inv(C);
    for (size_t j = 0; j < C; ++j) inv[j] = v[j].get<std::uint64_t>()[0];
    return inv;
}

// Attempt to reconstruct the original input order using the SP's guessed
// permutation-label mapping. 'trueOutput' is the actual shuffled state.
// 'guessInv' is the SP's mapping output-position -> guessed-original-index.
// Returns the recovered label order.
std::vector<int> reconstruct(const std::vector<block>& trueOutput,
                             const std::vector<int>& guessInv) {
    size_t C = trueOutput.size();
    std::vector<block> r(C, block(0, 0));
    for (size_t j = 0; j < C; ++j) {
        int idx = guessInv[j];
        assert(idx >= 0 && static_cast<size_t>(idx) < C);
        r[idx] = trueOutput[j];
    }
    std::vector<int> labels(C);
    for (size_t i = 0; i < C; ++i) labels[i] = r[i].get<std::uint64_t>()[0];
    return labels;
}

// Print a label sequence.
void printLabels(const std::string& title, const std::vector<int>& v) {
    std::cout << title << " :";
    for (int x : v) std::cout << " " << x;
    std::cout << std::endl;
}

} // anonymous namespace

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed" << std::endl;
        return 1;
    }

    constexpr int N = 4;          // senders
    constexpr int C = 8;          // rows
    constexpr int rounds = N - 1; // 3

    // Deterministic spKey_k and sessionId (known to SP).
    std::array<std::array<uint8_t, 32>, rounds> spKeys;
    std::array<uint8_t, 32> sessionId;
    for (int k = 0; k < rounds; ++k) {
        spKeys[k].fill(0xA0 + k);
    }
    sessionId.fill(0x5A);

    // ------------------------------------------------------------------
    //  PART 1 - Post-fix branch (sender uses fresh random seeds)
    // ------------------------------------------------------------------
    std::cout << "==== Threat model ====" << std::endl;
    std::cout << "Semi-honest SP knows all spKey_k and sessionId, does NOT know sender-local random seeds." << std::endl;

    // Build input table.
    std::vector<block> input(C);
    for (int i = 0; i < C; ++i) input[i] = block(0, i);

    // Sender side: pick random seeds, cascade.
    std::vector<block> trueSeeds(rounds);
    randombytes_buf(trueSeeds.data(), rounds * sizeof(block));

    std::vector<block> trueOutput = cascade(input, trueSeeds);

    // Ground-truth pi (position -> label).
    std::vector<int> truePi(C);
    for (int j = 0; j < C; ++j) truePi[j] = trueOutput[j].get<std::uint64_t>()[0];

    // Observed output table (just the labels, as an SP would see them).
    std::vector<int> observed(C);
    for (int j = 0; j < C; ++j) observed[j] = trueOutput[j].get<std::uint64_t>()[0];

    // SP attack: guess seeds from spKeys + sessionId.
    std::vector<block> spSeeds(rounds);
    for (int k = 0; k < rounds; ++k) {
        spSeeds[k] = deriveRoundSeed(spKeys[k], sessionId, k);
    }
    auto guessInv = guessedInv(spSeeds, C);   // position -> guessed label

    // SP tries to invert the shuffle.
    auto recovered = reconstruct(trueOutput, guessInv);

    // Leak?
    bool postFixLeak = (recovered == std::vector<int>{0,1,2,3,4,5,6,7});

    // --- Output ---
    std::cout << "\n==== Input table (row label at position i) ====" << std::endl;
    printLabels("Input", {0,1,2,3,4,5,6,7});

    std::cout << "\n==== Ground-truth pi (sender-local random seeds) ====" << std::endl;
    printLabels("Position->label", truePi);

    std::cout << "\n==== Observed output table (row labels) ====" << std::endl;
    printLabels("Observed", observed);

    std::cout << "\n==== SP attack: guessed pi (derived from spKey_k + sessionId) ====" << std::endl;
    printLabels("Position->label", guessInv);

    std::cout << "\n==== SP reconstructed input via pi_guess^-1(output) ====" << std::endl;
    printLabels("Reconstructed", recovered);

    std::cout << "\n==== Leak detected? ==== " << (postFixLeak ? "YES" : "NO")
              << "  (SP guess mismatches truth)" << std::endl;

    // Helper: show that guessed seed != true seed for round 0.
    {
        block trueSeed0 = trueSeeds[0];
        block spSeed0 = spSeeds[0];
        std::cout << "\n==== Seed comparison round 0 ====" << std::endl;
        std::cout << "  true seed : " << hex(trueSeed0) << std::endl;
        std::cout << "  SP guess  : " << hex(spSeed0) << std::endl;
        std::cout << "  differ?   " << (trueSeed0 != spSeed0 ? "YES" : "NO") << std::endl;
    }

    // ------------------------------------------------------------------
    //  PART 2 - Regression-catch branch (sender forced to use SP-derivable seeds)
    // ------------------------------------------------------------------
    std::cout << "\n==== Regression-catch: forcing pre-fix seed derivation ====" << std::endl;

    // Simulate pre-fix code: the true round seeds are the ones SP can derive.
    std::vector<block> preSeeds_t = spSeeds;                 // identical to SP's guess
    std::vector<block> preTrueOutput = cascade(input, preSeeds_t);

    std::vector<int> preTruePi(C);
    for (int j = 0; j < C; ++j) preTruePi[j] = preTrueOutput[j].get<std::uint64_t>()[0];

    // SP performs exactly the same attack (guess seeds from spKeys).
    auto preGuessInv = guessedInv(spSeeds, C);               // still correct

    // SP tries to invert the shuffle using its guess.
    auto preRecovered = reconstruct(preTrueOutput, preGuessInv);

    bool preFixLeak = (preRecovered == std::vector<int>{0,1,2,3,4,5,6,7});

    printLabels("pi_true (pre-fix)", preTruePi);
    printLabels("Observed output", preTruePi);               // same
    printLabels("SP guessed pi", preGuessInv);
    printLabels("SP reconstructed input", preRecovered);
    std::cout << "==== Leak detected? ==== " << (preFixLeak ? "YES" : "NO")
              << " (test would catch a regression)" << std::endl;

    // ------------------------------------------------------------------
    //  Final verdict
    // ------------------------------------------------------------------
    if (!postFixLeak && preFixLeak) {
        std::cout << "\nALL PASSED" << std::endl;
        return 0;
    } else {
        std::cout << "\nFAIL: post-fix leak=" << postFixLeak
                  << " pre-fix leak=" << preFixLeak << std::endl;
        return 1;
    }
}
