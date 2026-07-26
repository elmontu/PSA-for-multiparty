// Offline unit test for MpsaShuffleIntegrity's A-mset-row primitives.
//
// The critical scenario is CROSS-COLUMN TAMPERING: an adversary swaps two
// column values between rows, so each column's multiset is preserved
// (A-sum passes) but a row now has "mixed provenance" — some blocks from
// input row a and some from input row b. This corrupts join semantics
// silently and must be caught. The row-hash check does that because
// hash(concat(row.bytes)) changes when any column of the row is swapped
// for a different row's value.

#include "volePSI/MpsaShuffleIntegrity.h"
#include "cryptoTools/Common/Defines.h"

#include <sodium.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

namespace mp = volePSI::mpstar;

namespace {

oc::block randomBlock() {
    oc::block b;
    randombytes_buf(&b, sizeof(b));
    return b;
}

// Build W columns of length C (each column a fresh random block vector).
std::vector<std::vector<oc::block>> makeCols(size_t W, size_t C) {
    std::vector<std::vector<oc::block>> cols(W, std::vector<oc::block>(C));
    for (size_t w = 0; w < W; ++w)
        for (size_t j = 0; j < C; ++j)
            cols[w][j] = randomBlock();
    return cols;
}

// Convert a column view (W x C) into a row view (C x W) for makeSenderRowWitness().
std::vector<std::vector<oc::block>> colsToRows(
    const std::vector<std::vector<oc::block>>& cols)
{
    if (cols.empty()) return {};
    const size_t W = cols.size();
    const size_t C = cols[0].size();
    std::vector<std::vector<oc::block>> rows(C, std::vector<oc::block>(W));
    for (size_t j = 0; j < C; ++j)
        for (size_t w = 0; w < W; ++w)
            rows[j][w] = cols[w][j];
    return rows;
}

// Apply the SAME permutation to all columns (simulates the honest cascade).
void permuteAllCols(std::vector<std::vector<oc::block>>& cols,
                    const std::vector<size_t>& perm) {
    for (auto& col : cols) {
        std::vector<oc::block> next(col.size());
        for (size_t j = 0; j < perm.size(); ++j) next[j] = col[perm[j]];
        col = std::move(next);
    }
}

} // namespace

int main() {
    if (sodium_init() == -1) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    int failures = 0;
    auto report = [&](int n, const char* desc, bool ok) {
        std::cout << "[" << n << "] " << desc << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    };

    // Check 1: honest cascade preserves row-hash sum -> verify passes.
    {
        auto cols = makeCols(3, 8);
        auto rows = colsToRows(cols);
        auto wit  = mp::makeSenderRowWitness(rows);

        std::vector<size_t> perm(8);
        std::iota(perm.begin(), perm.end(), 0);
        std::shuffle(perm.begin(), perm.end(), std::mt19937(0xC0DE));
        permuteAllCols(cols, perm);

        bool ok = mp::verifySenderRowIntegrity(
            wit.commit, wit.claimedSum, wit.opening, cols);
        report(1, "honest cascade (same perm on all cols)", ok);
    }

    // Check 2: CROSS-COLUMN TAMPERING (the case A-sum misses). Apply the
    // same shuffle to cols 0 and 1, but SWAP two rows only in col 2.
    // Column multisets are unchanged (A-sum passes trivially), but two
    // output rows are now mixed-provenance -> row-hash sum changes.
    {
        auto cols = makeCols(3, 8);
        auto rows = colsToRows(cols);
        auto wit  = mp::makeSenderRowWitness(rows);

        std::vector<size_t> perm(8);
        std::iota(perm.begin(), perm.end(), 0);
        std::shuffle(perm.begin(), perm.end(), std::mt19937(0xBEEF));
        permuteAllCols(cols, perm);

        // Now tamper: in col 2, swap rows 1 and 5. Col 2 multiset unchanged.
        std::swap(cols[2][1], cols[2][5]);

        bool verify_result = mp::verifySenderRowIntegrity(
            wit.commit, wit.claimedSum, wit.opening, cols);
        report(2, "cross-column swap detected (A-sum misses this)", !verify_result);
    }

    // Check 3: drop a row -> caught.
    {
        auto cols = makeCols(3, 8);
        auto rows = colsToRows(cols);
        auto wit  = mp::makeSenderRowWitness(rows);

        std::vector<size_t> perm(8);
        std::iota(perm.begin(), perm.end(), 0);
        std::shuffle(perm.begin(), perm.end(), std::mt19937(0x1234));
        permuteAllCols(cols, perm);
        for (auto& col : cols) col.pop_back();

        bool r = mp::verifySenderRowIntegrity(
            wit.commit, wit.claimedSum, wit.opening, cols);
        report(3, "row drop detected", !r);
    }

    // Check 4: substitute one block value -> caught.
    {
        auto cols = makeCols(3, 8);
        auto rows = colsToRows(cols);
        auto wit  = mp::makeSenderRowWitness(rows);

        std::vector<size_t> perm(8);
        std::iota(perm.begin(), perm.end(), 0);
        std::shuffle(perm.begin(), perm.end(), std::mt19937(0x5678));
        permuteAllCols(cols, perm);
        cols[1][3] = randomBlock();

        bool r = mp::verifySenderRowIntegrity(
            wit.commit, wit.claimedSum, wit.opening, cols);
        report(4, "block substitution detected", !r);
    }

    // Check 5: replay attack: reuse an old opening for a different witness.
    {
        auto cols  = makeCols(3, 8);
        auto rows  = colsToRows(cols);
        auto wit0  = mp::makeSenderRowWitness(rows);
        auto wit1  = mp::makeSenderRowWitness(rows);  // fresh opening
        // Verify with wit0's commit but wit1's opening.
        bool r = mp::verifySenderRowIntegrity(
            wit0.commit, wit0.claimedSum, wit1.opening, cols);
        report(5, "replay of different opening detected", !r);
    }

    // Check 6: serialization round-trip.
    {
        auto cols = makeCols(3, 8);
        auto rows = colsToRows(cols);
        auto wit  = mp::makeSenderRowWitness(rows);

        auto cbytes = mp::serializeRowCommit(wit.commit);
        auto obytes = mp::serializeRowOpening(wit.claimedSum, wit.opening);
        auto commit2 = mp::deserializeRowCommit(cbytes);
        mp::R255Scalar cs2, op2;
        mp::deserializeRowOpening(obytes, cs2, op2);
        bool ok = (commit2.c.bytes == wit.commit.c.bytes)
               && (cs2 == wit.claimedSum)
               && (op2 == wit.opening);
        report(6, "wire round-trip (commit + opening)", ok);
    }

    // Check 7: empty rows edge case (Ceff=0 or W=0).
    {
        std::vector<std::vector<oc::block>> emptyRows;
        auto wit = mp::makeSenderRowWitness(emptyRows);
        bool r = mp::verifySenderRowIntegrity(
            wit.commit, wit.claimedSum, wit.opening,
            /*cols=*/ std::vector<std::vector<oc::block>>{});
        report(7, "empty input edge case", r);
    }

    if (failures == 0) {
        std::cout << "ALL PASSED\n";
        std::cout << "NOTE: A-mset-row catches the cross-column swap case that\n"
                  << "A-sum's per-column sum check accepts. Use both together for\n"
                  << "full row+column integrity coverage.\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " checks failed\n";
    return 1;
}
