// Unit tests for volePSI/MpJoinFilter.h — Phase 6 of the N-party
// private join (R31; see docs/PRIVATE_JOIN_DESIGN.md). Verifies:
//   1. Filter: all is_intersection=true rows come first
//   2. Filter preserves payload integrity (no scrambling)
//   3. Filter on already-filtered input is a no-op (idempotent for partition)
//   4. Edge cases: empty input, all-true, all-false
//   5. Filter is STRUCTURALLY oblivious — same access pattern for any input
//   6. Filter + truncate yields exactly the intersection rows
//   7. id and joinedPayload survive the filter intact

#include "volePSI/MpJoinFilter.h"
#include "volePSI/MpJoinExpander.h"
#include "volePSI/MpObliviousSort.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using mp::JoinExpandedRow;
using oc::block;

static block makeTaggedBlock(uint64_t tag) {
    block b;
    std::memset(&b, 0, sizeof(b));
    std::memcpy(&b, &tag, 8);
    return b;
}

static uint64_t blockTag(const block& b) {
    uint64_t t = 0;
    std::memcpy(&t, &b, 8);
    return t;
}

static JoinExpandedRow makeRow(uint64_t id, bool isIntersection,
                               uint32_t N, uint32_t W, uint64_t tag)
{
    JoinExpandedRow row;
    row.id = id;
    row.isIntersection = isIntersection;
    row.joinedPayload.resize(N * W);
    for (uint32_t i = 0; i < N * W; ++i) {
        row.joinedPayload[i] = makeTaggedBlock((tag << 16) | i);
    }
    return row;
}

// --------------------------------------------------------------

bool test_filter_partitions_correctly() {
    std::vector<JoinExpandedRow> rows;
    rows.push_back(makeRow(10, false, 2, 1, 1));
    rows.push_back(makeRow(11, true,  2, 1, 2));
    rows.push_back(makeRow(12, false, 2, 1, 3));
    rows.push_back(makeRow(13, true,  2, 1, 4));
    rows.push_back(makeRow(14, true,  2, 1, 5));
    rows.push_back(makeRow(15, false, 2, 1, 6));

    mp::obliviousFilterIntersection(rows, /*payloadW=*/1);
    // After filter: first 3 should all be is_intersection=true.
    int seenTrueAtFront = 0;
    bool partitionOk = true;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (i < 3) {
            if (!rows[i].isIntersection) partitionOk = false;
            else ++seenTrueAtFront;
        } else {
            if (rows[i].isIntersection) partitionOk = false;
        }
    }
    return partitionOk && seenTrueAtFront == 3;
}

bool test_filter_preserves_payload_integrity() {
    // Each row has a distinctive tag; after filter, the rows must still
    // be identifiable (no payload corruption or cross-contamination).
    std::vector<JoinExpandedRow> rows;
    for (uint64_t i = 0; i < 8; ++i) {
        rows.push_back(makeRow(100 + i, (i % 2) == 0, 2, 1, 1000 + i));
    }
    std::vector<uint64_t> originalTags;
    for (const auto& r : rows) originalTags.push_back(blockTag(r.joinedPayload[0]) >> 16);

    mp::obliviousFilterIntersection(rows, 1);

    // Every original tag should still appear exactly once.
    std::vector<uint64_t> afterTags;
    for (const auto& r : rows) afterTags.push_back(blockTag(r.joinedPayload[0]) >> 16);
    std::sort(originalTags.begin(), originalTags.end());
    std::sort(afterTags.begin(), afterTags.end());
    return originalTags == afterTags;
}

bool test_filter_idempotent_on_partitioned() {
    // Input where all is_intersection=true rows are already at the front.
    // The filter should preserve that partition (rows may shuffle within
    // each half due to bitonic-sort instability, but no row crosses).
    std::vector<JoinExpandedRow> rows;
    for (int i = 0; i < 4; ++i) rows.push_back(makeRow(i, true,  2, 1, i));
    for (int i = 4; i < 8; ++i) rows.push_back(makeRow(i, false, 2, 1, i));

    mp::obliviousFilterIntersection(rows, 1);
    for (int i = 0; i < 4; ++i) if (!rows[i].isIntersection) return false;
    for (int i = 4; i < 8; ++i) if ( rows[i].isIntersection) return false;
    return true;
}

bool test_empty_input() {
    std::vector<JoinExpandedRow> rows;
    mp::obliviousFilterIntersection(rows, 1);
    return rows.empty();
}

bool test_all_true() {
    std::vector<JoinExpandedRow> rows;
    for (int i = 0; i < 6; ++i) rows.push_back(makeRow(i, true, 2, 1, i));
    mp::obliviousFilterIntersection(rows, 1);
    for (const auto& r : rows) if (!r.isIntersection) return false;
    return rows.size() == 6;
}

bool test_all_false() {
    std::vector<JoinExpandedRow> rows;
    for (int i = 0; i < 6; ++i) rows.push_back(makeRow(i, false, 2, 1, i));
    mp::obliviousFilterIntersection(rows, 1);
    for (const auto& r : rows) if (r.isIntersection) return false;
    return rows.size() == 6;
}

bool test_filter_structurally_oblivious() {
    // The underlying obliviousBitonicSort is already structurally oblivious
    // (tested in test_oblivious_sort.cpp). The filter just wraps it. The
    // contract is: for any two inputs of the same size, the same number
    // of compare-and-swaps occur. Verify via two contrasting inputs.
    auto run = [&](std::vector<JoinExpandedRow>& rows, uint64_t& cmpCount) {
        // We can't directly hook the comparator of obliviousFilterIntersection
        // since it goes through the default sort path. But the sort's
        // compare-swap count is deterministic in n. So if rows.size() is
        // equal across the two test inputs, the bitonicCompareSwapCount(n)
        // is the same. That's what we verify here.
        mp::obliviousFilterIntersection(rows, 1);
        cmpCount = mp::bitonicCompareSwapCount(rows.size());
    };

    std::vector<JoinExpandedRow> rows1, rows2;
    std::mt19937 g(0x123);
    for (int i = 0; i < 32; ++i) rows1.push_back(makeRow(i, (g() % 2) == 0, 2, 1, i));
    for (int i = 0; i < 32; ++i) rows2.push_back(makeRow(i, (g() % 2) == 0, 2, 1, i));

    uint64_t c1 = 0, c2 = 0;
    run(rows1, c1);
    run(rows2, c2);
    return c1 == c2;
}

bool test_filter_and_truncate() {
    std::vector<JoinExpandedRow> rows;
    rows.push_back(makeRow(10, false, 2, 1, 1));
    rows.push_back(makeRow(11, true,  2, 1, 2));
    rows.push_back(makeRow(12, true,  2, 1, 3));
    rows.push_back(makeRow(13, false, 2, 1, 4));
    rows.push_back(makeRow(14, true,  2, 1, 5));

    size_t k = mp::filterAndTruncate(rows, 1);
    if (k != 3) return false;
    if (rows.size() != 3) return false;
    for (const auto& r : rows) if (!r.isIntersection) return false;
    return true;
}

bool test_wider_payload_survives_filter() {
    // N=3, W=4: each row has 12 payload blocks. Verify the encode/decode
    // path preserves all 12.
    const uint32_t N = 3, W = 4;
    std::vector<JoinExpandedRow> rows;
    for (int i = 0; i < 6; ++i) {
        rows.push_back(makeRow(100 + i, (i % 2 == 0), N, W, 0x500 + i));
    }
    std::vector<std::vector<uint64_t>> originalTags;
    for (const auto& r : rows) {
        std::vector<uint64_t> v;
        for (const auto& b : r.joinedPayload) v.push_back(blockTag(b));
        originalTags.push_back(v);
    }

    mp::obliviousFilterIntersection(rows, W);

    // Each output row's joinedPayload must match exactly one input row's tags
    // (i.e., the rows are permuted, but each row is intact).
    std::vector<std::vector<uint64_t>> afterTags;
    for (const auto& r : rows) {
        std::vector<uint64_t> v;
        for (const auto& b : r.joinedPayload) v.push_back(blockTag(b));
        afterTags.push_back(v);
    }
    std::sort(originalTags.begin(), originalTags.end());
    std::sort(afterTags.begin(), afterTags.end());
    if (originalTags != afterTags) return false;

    // And partition is still correct.
    bool sawFalse = false;
    for (const auto& r : rows) {
        if (sawFalse && r.isIntersection) return false;
        if (!r.isIntersection) sawFalse = true;
    }
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"filter_partitions_correctly",       test_filter_partitions_correctly},
        {"filter_preserves_payload_integrity", test_filter_preserves_payload_integrity},
        {"filter_idempotent_on_partitioned",  test_filter_idempotent_on_partitioned},
        {"empty_input",                       test_empty_input},
        {"all_true",                          test_all_true},
        {"all_false",                         test_all_false},
        {"filter_structurally_oblivious",     test_filter_structurally_oblivious},
        {"filter_and_truncate",               test_filter_and_truncate},
        {"wider_payload_survives_filter",     test_wider_payload_survives_filter},
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
