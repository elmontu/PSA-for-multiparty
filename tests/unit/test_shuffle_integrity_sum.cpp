/*
 * test_shuffle_integrity_sum.cpp
 * Self-contained C++17 offline unit test for MpsaShuffleIntegrity
 * (A-sum shuffle integrity check).
 * See tests/unit/CMakeLists.txt for build instructions.
 */
#include <iostream>
#include <sodium.h>
#include <vector>
#include <algorithm>
#include <random>
#include <cassert>
#include <cstdint>

#include "cryptoTools/Common/Defines.h"
#include "volePSI/MpsaShuffleIntegrity.h"

int main() {
    if (sodium_init() == -1) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    auto randomBlock = []() -> oc::block {
        oc::block b;
        randombytes_buf(&b, sizeof(b));
        return b;
    };

    bool allPass = true;
    int failCount = 0;

    auto printResult = [&](int checkNum, const std::string& desc, bool testPassed) {
        std::cout << "[" << checkNum << "] " << desc << ": "
                  << (testPassed ? "PASS" : "FAIL") << "\n";
        if (!testPassed) {
            allPass = false;
            ++failCount;
        }
    };

    // -------------------------------------------------------------------
    // Check 1: Honest execution – shuffle is a permutation, witness valid.
    // -------------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        // Simulate a cascade shuffle (any permutation is fine)
        std::vector<std::vector<oc::block>> shuffledColumns = columns;
        std::random_device rd;
        std::mt19937 g(rd());
        for (size_t w = 0; w < W; ++w)
            std::shuffle(shuffledColumns[w].begin(), shuffledColumns[w].end(), g);

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit.commits, wit.claimedSums, wit.openings, shuffledColumns);
        printResult(1, "HONEST pass", verify);
    }

    // ---------------------------------------------------------------
    // Check 2: DROP a row (malicious sender loses a row).
    // ---------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        std::vector<std::vector<oc::block>> shuffledColumns = columns;
        std::random_device rd;
        std::mt19937 g(rd());
        for (size_t w = 0; w < W; ++w)
            std::shuffle(shuffledColumns[w].begin(), shuffledColumns[w].end(), g);

        // Drop a row from the first column
        shuffledColumns[0].pop_back();

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit.commits, wit.claimedSums, wit.openings, shuffledColumns);
        printResult(2, "DROP row detected", !verify);
    }

    // ---------------------------------------------------------------
    // Check 3: SUBSTITUTE a row with a fresh random block.
    // ---------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        std::vector<std::vector<oc::block>> shuffledColumns = columns;
        std::random_device rd;
        std::mt19937 g(rd());
        for (size_t w = 0; w < W; ++w)
            std::shuffle(shuffledColumns[w].begin(), shuffledColumns[w].end(), g);

        // Replace an element in column 1
        shuffledColumns[1][4] = randomBlock();

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit.commits, wit.claimedSums, wit.openings, shuffledColumns);
        printResult(3, "SUBSTITUTE row detected", !verify);
    }

    // ---------------------------------------------------------------
    // Check 4: SWAP two rows – permutation that preserves the sum,
    //          the documented A-sum gap.
    // ---------------------------------------------------------------
    {
        std::cout << "Note: Swap-within-column preserves sum -> "
                     "this is the accepted A-sum gap.\n";
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        std::vector<std::vector<oc::block>> shuffledColumns = columns;
        // Perform a true permutation: swap indices 0 and 5 in column 0
        std::swap(shuffledColumns[0][0], shuffledColumns[0][5]);

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit.commits, wit.claimedSums, wit.openings, shuffledColumns);
        printResult(4, "SWAP rows (preserves sum) PASS (gap)", verify);
    }

    // ---------------------------------------------------------------
    // Check 5: REPLAY an old opening – mixing commits from witness w0
    //          with openings from witness w1.
    // ---------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit0 =
            volePSI::mpstar::makeSenderWitness(columns);
        volePSI::mpstar::SenderColumnWitness wit1 =
            volePSI::mpstar::makeSenderWitness(columns);

        // Use commits and claimed sums from wit0, but openings from wit1
        std::vector<std::vector<oc::block>> shuffledColumns = columns;
        std::random_device rd;
        std::mt19937 g(rd());
        for (size_t w = 0; w < W; ++w)
            std::shuffle(shuffledColumns[w].begin(), shuffledColumns[w].end(), g);

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit0.commits, wit0.claimedSums, wit1.openings, shuffledColumns);
        printResult(5, "REPLAY opening detected", !verify);
    }

    // ---------------------------------------------------------------
    // Check 6: Serialisation round-trip for commitments.
    // ---------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        std::vector<uint8_t> ser =
            volePSI::mpstar::serializeCommits(wit.commits);
        std::vector<volePSI::mpstar::PedersenCommitment> deser =
            volePSI::mpstar::deserializeCommits(ser, W);

        bool roundtripOK = (wit.commits.size() == deser.size());
        for (size_t i = 0; i < wit.commits.size() && roundtripOK; ++i) {
            if (!(wit.commits[i].c.bytes == deser[i].c.bytes))
                roundtripOK = false;
        }
        printResult(6, "Serialize/Deserialize commits roundtrip", roundtripOK);
    }

    // ---------------------------------------------------------------
    // Check 7: Serialisation round-trip for openings/claimed sums.
    // ---------------------------------------------------------------
    {
        constexpr size_t W = 3;
        constexpr size_t rows = 8;
        std::vector<std::vector<oc::block>> columns(W, std::vector<oc::block>(rows));
        for (size_t w = 0; w < W; ++w)
            for (size_t r = 0; r < rows; ++r)
                columns[w][r] = randomBlock();

        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);

        std::vector<uint8_t> ser =
            volePSI::mpstar::serializeOpenings(wit.claimedSums, wit.openings);

        std::vector<volePSI::mpstar::R255Scalar> deserSums, deserOpenings;
        volePSI::mpstar::deserializeOpenings(ser, W, deserSums, deserOpenings);

        bool roundtripOK = (wit.claimedSums.size() == deserSums.size() &&
                            wit.openings.size() == deserOpenings.size());
        for (size_t i = 0; i < wit.claimedSums.size() && roundtripOK; ++i) {
            if (!(wit.claimedSums[i] == deserSums[i]) ||
                !(wit.openings[i] == deserOpenings[i]))
                roundtripOK = false;
        }
        printResult(7, "Serialize/Deserialize openings roundtrip", roundtripOK);
    }

    // ---------------------------------------------------------------
    // Check 8: Edge case W = 0.
    // ---------------------------------------------------------------
    {
        std::vector<std::vector<oc::block>> columns;   // W = 0
        volePSI::mpstar::SenderColumnWitness wit =
            volePSI::mpstar::makeSenderWitness(columns);
        std::vector<std::vector<oc::block>> shuffledColumns;

        bool verify = volePSI::mpstar::verifySenderIntegrity(
            wit.commits, wit.claimedSums, wit.openings, shuffledColumns);
        printResult(8, "W=0 edge case", verify);
    }

    // ---------------------------------------------------------------
    // Final verdict
    // ---------------------------------------------------------------
    if (allPass) {
        std::cout << "ALL PASSED\n";
        return 0;
    } else {
        std::cout << "FAIL: " << failCount << " checks failed\n";
        return 1;
    }
}
