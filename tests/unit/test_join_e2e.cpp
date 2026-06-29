// End-to-end unit tests for volePSI/MpsaJoinDriver.h (R32; see
// docs/PRIVATE_JOIN_DESIGN.md). Verifies the in-memory composition of
// Phases 1+2+3+4+5+6 produces the correct joined intersection table for
// realistic inputs.
//
// Test scenarios:
//   1. Trivial 2-party N=2, M=1: degenerates to standard single-row PSI
//   2. 2-party N=2, M=2: multiple rows per id, full join
//   3. 3-party N=3, M=2: realistic small case
//   4. No intersection (disjoint ids): empty output
//   5. Partial intersection (some ids in only some parties): only fully-
//      shared ids appear in output
//   6. Over-M input rejected
//   7. Width mismatch rejected
//   8. Cross-product completeness: every expected combination appears

#include "volePSI/MpsaJoinDriver.h"
#include "volePSI/MpJoinExpander.h"

#include "cryptoTools/Common/Defines.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using mp::JoinInputRow;
using mp::JoinInputTable;
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

static JoinInputRow makeInputRow(uint64_t id, uint32_t W, uint64_t tag) {
    JoinInputRow row;
    row.id = id;
    row.row_data.resize(W);
    for (uint32_t w = 0; w < W; ++w) {
        row.row_data[w] = makeTaggedBlock((tag << 16) | w);
    }
    return row;
}

// --------------------------------------------------------------

bool test_trivial_2party_M1() {
    // N=2, M=1 → degenerates to standard single-row PSI. Each party has
    // exactly one row per id. Intersection of ids should produce one
    // output row per shared id.
    JoinInputTable t0 = {makeInputRow(1, 1, 0xA1),
                         makeInputRow(2, 1, 0xA2),
                         makeInputRow(3, 1, 0xA3)};
    JoinInputTable t1 = {makeInputRow(2, 1, 0xB2),
                         makeInputRow(3, 1, 0xB3),
                         makeInputRow(4, 1, 0xB4)};
    // Intersection: ids 2 and 3.
    auto out = mp::executePrivateJoinInMemory(2, 1, 1, {t0, t1});

    if (out.size() != 2) return false;
    std::set<uint64_t> seenIds;
    for (const auto& r : out) {
        if (!r.isIntersection) return false;
        if (r.joinedPayload.size() != 2) return false;  // N*W = 2*1
        seenIds.insert(r.id);
    }
    return seenIds == std::set<uint64_t>{2, 3};
}

bool test_2party_M2_full_join() {
    // N=2, M=2. Both parties have 2 rows for id=10 (intersect).
    // Cross-product = M^N = 4 rows for id=10.
    const uint32_t N = 2, M = 2, W = 1;
    JoinInputTable t0 = {makeInputRow(10, W, 0xA),
                         makeInputRow(10, W, 0xB)};
    JoinInputTable t1 = {makeInputRow(10, W, 0xC),
                         makeInputRow(10, W, 0xD)};
    auto out = mp::executePrivateJoinInMemory(N, M, W, {t0, t1});

    if (out.size() != M * M) return false;  // 4
    std::set<std::pair<uint64_t, uint64_t>> combos;
    for (const auto& r : out) {
        if (!r.isIntersection || r.id != 10) return false;
        if (r.joinedPayload.size() != N * W) return false;
        uint64_t t0_tag = blockTag(r.joinedPayload[0]) >> 16;
        uint64_t t1_tag = blockTag(r.joinedPayload[1]) >> 16;
        combos.insert({t0_tag, t1_tag});
    }
    // Expected: 4 unique combinations of (t0_row, t1_row).
    return combos.size() == 4;
}

bool test_3party_M2_realistic() {
    // N=3, M=2, W=2. id=42 shared by all; each party has 2 rows for it.
    // Plus some non-shared ids that should not appear in output.
    const uint32_t N = 3, M = 2, W = 2;
    JoinInputTable t0 = {makeInputRow(42, W, 0xA0),
                         makeInputRow(42, W, 0xA1),
                         makeInputRow(99, W, 0xA9)};  // not in others
    JoinInputTable t1 = {makeInputRow(42, W, 0xB0),
                         makeInputRow(42, W, 0xB1),
                         makeInputRow(77, W, 0xB7)};  // not in others
    JoinInputTable t2 = {makeInputRow(42, W, 0xC0),
                         makeInputRow(42, W, 0xC1)};

    auto out = mp::executePrivateJoinInMemory(N, M, W, {t0, t1, t2});

    if (out.size() != M * M * M) return false;  // 8
    for (const auto& r : out) {
        if (!r.isIntersection) return false;
        if (r.id != 42) return false;
        if (r.joinedPayload.size() != N * W) return false;
    }
    return true;
}

bool test_no_intersection_empty_output() {
    // Disjoint ids → empty output.
    JoinInputTable t0 = {makeInputRow(1, 1, 0xA)};
    JoinInputTable t1 = {makeInputRow(2, 1, 0xB)};
    JoinInputTable t2 = {makeInputRow(3, 1, 0xC)};
    auto out = mp::executePrivateJoinInMemory(3, 1, 1, {t0, t1, t2});
    return out.empty();
}

bool test_partial_intersection_filters_correctly() {
    // ids: 1 (only party 0), 2 (parties 0+1 but not 2), 3 (all three).
    // Only id=3 should produce output.
    JoinInputTable t0 = {makeInputRow(1, 1, 0x10),
                         makeInputRow(2, 1, 0x20),
                         makeInputRow(3, 1, 0x30)};
    JoinInputTable t1 = {makeInputRow(2, 1, 0x21),
                         makeInputRow(3, 1, 0x31)};
    JoinInputTable t2 = {makeInputRow(3, 1, 0x32)};
    auto out = mp::executePrivateJoinInMemory(3, 1, 1, {t0, t1, t2});
    if (out.size() != 1) return false;
    return out[0].id == 3 && out[0].isIntersection;
}

bool test_over_M_input_throws() {
    // Party 0 has 3 rows for id=5; M=2 → over-cap.
    JoinInputTable t0 = {makeInputRow(5, 1, 1),
                         makeInputRow(5, 1, 2),
                         makeInputRow(5, 1, 3)};
    JoinInputTable t1 = {makeInputRow(5, 1, 4)};
    try {
        mp::executePrivateJoinInMemory(2, 2, 1, {t0, t1});
    } catch (const std::exception&) { return true; }
    return false;
}

bool test_width_mismatch_throws() {
    // Row with width 2 but payloadW=4.
    JoinInputRow bad;
    bad.id = 1;
    bad.row_data.resize(2);
    JoinInputTable t0 = {bad};
    JoinInputTable t1 = {makeInputRow(1, 4, 1)};
    try {
        mp::executePrivateJoinInMemory(2, 1, 4, {t0, t1});
    } catch (const std::exception&) { return true; }
    return false;
}

bool test_uneven_per_party_row_counts_for_same_id() {
    // id=10: party 0 has 2 rows, party 1 has 1 row. M=2.
    // Expected output rows = real(party 0) × real(party 1) = 2 × 1 = 2.
    // Combinations involving party 1's dummy slot get filtered out.
    const uint32_t N = 2, M = 2, W = 1;
    JoinInputTable t0 = {makeInputRow(10, W, 0xA0),
                         makeInputRow(10, W, 0xA1)};
    JoinInputTable t1 = {makeInputRow(10, W, 0xB0)};

    auto out = mp::executePrivateJoinInMemory(N, M, W, {t0, t1});
    // Each of party 0's 2 real rows pairs with party 1's 1 real row →
    // 2 output rows.
    if (out.size() != 2) return false;
    for (const auto& r : out) {
        if (!r.isIntersection || r.id != 10) return false;
        // joinedPayload[1] should always be party 1's row 0 (tag 0xB0).
        if ((blockTag(r.joinedPayload[1]) >> 16) != 0xB0) return false;
    }
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"trivial_2party_M1",                       test_trivial_2party_M1},
        {"2party_M2_full_join",                     test_2party_M2_full_join},
        {"3party_M2_realistic",                     test_3party_M2_realistic},
        {"no_intersection_empty_output",            test_no_intersection_empty_output},
        {"partial_intersection_filters_correctly",  test_partial_intersection_filters_correctly},
        {"over_M_input_throws",                     test_over_M_input_throws},
        {"width_mismatch_throws",                   test_width_mismatch_throws},
        {"uneven_per_party_row_counts_for_same_id", test_uneven_per_party_row_counts_for_same_id},
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
