// Unit tests for volePSI/MpJoinExpander.h — Phases 4 (window detect) + 5
// (cross-product expansion) of the N-party private join (R30; see
// docs/PRIVATE_JOIN_DESIGN.md). Verifies:
//   1. Metadata pack/unpack roundtrip
//   2. Window detection on simple ascending-with-duplicates input
//   3. Window starts agree with detected ends
//   4. Cross-product N=2, M=2 produces M^N = 4 rows per window
//   5. is_intersection AND-aggregation behaves correctly
//   6. Payload content placement: joinedPayload[party*W+w] = correct source block
//   7. Mixed window: real ⊗ dummy interactions
//   8. Pad-contract violation throws cleanly
//   9. Large-N refusal (overflow guard)

#include "volePSI/MpJoinExpander.h"
#include "volePSI/MpObliviousSort.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using mp::SortElement;
using mp::JoinExpandedRow;
using oc::block;

// Build a SortElement for the test: encode (party_idx, row_idx, is_real)
// in the first payload block, then W payload data blocks.
static SortElement makeTuple(uint64_t id, uint32_t party_idx, uint32_t row_idx,
                             bool is_real, uint32_t W, uint64_t payloadTag)
{
    SortElement e;
    e.key = id;
    e.payload.resize(1 + W);
    e.payload[0] = mp::packTupleMeta(party_idx, row_idx, is_real);
    for (uint32_t w = 0; w < W; ++w) {
        std::memset(&e.payload[1 + w], 0, 16);
        uint64_t tag = (uint64_t(party_idx) << 40)
                     | (uint64_t(row_idx)   << 24)
                     | (uint64_t(w)         << 12)
                     |  payloadTag;
        std::memcpy(&e.payload[1 + w], &tag, 8);
    }
    return e;
}

static uint64_t blockTag(const block& b) {
    uint64_t tag = 0;
    std::memcpy(&tag, &b, 8);
    return tag;
}

// --------------------------------------------------------------

bool test_meta_roundtrip() {
    for (uint32_t p : {0u, 1u, 5u, 12345u}) {
        for (uint32_t r : {0u, 1u, 9u, 65535u}) {
            for (bool real : {true, false}) {
                auto blk = mp::packTupleMeta(p, r, real);
                uint32_t p2 = 0, r2 = 0; bool real2 = !real;
                mp::unpackTupleMeta(blk, p2, r2, real2);
                if (p2 != p || r2 != r || real2 != real) return false;
            }
        }
    }
    return true;
}

bool test_window_ends_simple() {
    // Keys: 1 1 1 3 3 5 — three windows of sizes 3, 2, 1.
    std::vector<SortElement> xs;
    for (int i = 0; i < 3; ++i) xs.push_back(makeTuple(1, 0, i, true, 1, 0));
    for (int i = 0; i < 2; ++i) xs.push_back(makeTuple(3, 0, i, true, 1, 0));
    xs.push_back(makeTuple(5, 0, 0, true, 1, 0));
    auto ends = mp::detectWindowEnds(xs);
    if (ends.size() != 6) return false;
    return ends[0] == false && ends[1] == false && ends[2] == true
        && ends[3] == false && ends[4] == true
        && ends[5] == true;
}

bool test_window_starts_match_ends() {
    std::vector<SortElement> xs;
    for (int i = 0; i < 4; ++i) xs.push_back(makeTuple(10, 0, i, true, 1, 0));
    for (int i = 0; i < 2; ++i) xs.push_back(makeTuple(20, 0, i, true, 1, 0));
    for (int i = 0; i < 3; ++i) xs.push_back(makeTuple(30, 0, i, true, 1, 0));
    auto starts = mp::windowStartIndices(xs);
    auto ends   = mp::detectWindowEnds(xs);
    // Each start should correspond to: (start == 0) || ends[start-1] == true.
    if (starts.size() != 3) return false;
    for (size_t s : starts) {
        if (s == 0) continue;
        if (!ends[s - 1]) return false;
    }
    return true;
}

bool test_cross_product_N2_M2_one_window() {
    // One window, N=2 parties, M=2 rows each, W=1 payload block per party.
    // Expected: M^N = 4 output rows.
    const uint32_t N = 2, M = 2, W = 1;
    std::vector<SortElement> xs;
    // Party 0, id=42, rows 0 and 1, both real
    xs.push_back(makeTuple(42, 0, 0, true, W, 0xA0));
    xs.push_back(makeTuple(42, 0, 1, true, W, 0xA1));
    // Party 1, id=42, rows 0 and 1, both real
    xs.push_back(makeTuple(42, 1, 0, true, W, 0xB0));
    xs.push_back(makeTuple(42, 1, 1, true, W, 0xB1));

    auto out = mp::crossProductExpand(xs, N, M, W);
    if (out.size() != 4) return false;
    for (const auto& row : out) {
        if (row.id != 42) return false;
        if (row.joinedPayload.size() != N * W) return false;
        if (!row.isIntersection) return false;
    }
    return true;
}

bool test_payload_content_placement() {
    // After expansion, joinedPayload[party*W + w] must equal the chosen
    // tuple's payload data block. Verify combinatorially.
    const uint32_t N = 2, M = 2, W = 1;
    std::vector<SortElement> xs;
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t r = 0; r < M; ++r) {
            xs.push_back(makeTuple(42, p, r, true, W, 0));
        }
    }

    auto out = mp::crossProductExpand(xs, N, M, W);
    if (out.size() != 4) return false;

    // Each output row's joinedPayload[0] = party 0's pick, joinedPayload[1] = party 1's pick.
    // Each pick has a tag = (party << 40) | (row << 24) | (0 << 12) | 0
    // Verify all 4 combinations appear exactly once.
    std::vector<std::pair<uint32_t, uint32_t>> seen;
    for (const auto& row : out) {
        uint64_t t0 = blockTag(row.joinedPayload[0]);
        uint64_t t1 = blockTag(row.joinedPayload[1]);
        uint32_t p0 = (t0 >> 40) & 0xFF;
        uint32_t r0 = (t0 >> 24) & 0xFFFF;
        uint32_t p1 = (t1 >> 40) & 0xFF;
        uint32_t r1 = (t1 >> 24) & 0xFFFF;
        if (p0 != 0 || p1 != 1) return false;
        seen.push_back({r0, r1});
    }
    std::sort(seen.begin(), seen.end());
    std::vector<std::pair<uint32_t, uint32_t>> expected = {{0,0},{0,1},{1,0},{1,1}};
    return seen == expected;
}

bool test_is_intersection_and_aggregation() {
    // N=2, M=2. Party 0 has both real. Party 1 has row 0 real, row 1 dummy.
    // Expansions: (p0_0, p1_0)=real,real → true; (p0_0, p1_1)=real,dummy → false;
    //             (p0_1, p1_0)=real,real → true; (p0_1, p1_1)=real,dummy → false.
    const uint32_t N = 2, M = 2, W = 1;
    std::vector<SortElement> xs;
    xs.push_back(makeTuple(7, 0, 0, true,  W, 0));
    xs.push_back(makeTuple(7, 0, 1, true,  W, 0));
    xs.push_back(makeTuple(7, 1, 0, true,  W, 0));
    xs.push_back(makeTuple(7, 1, 1, false, W, 0));  // dummy

    auto out = mp::crossProductExpand(xs, N, M, W);
    if (out.size() != 4) return false;

    // Count is_intersection = true. Should be exactly 2.
    int trueCount = 0;
    for (const auto& row : out) if (row.isIntersection) ++trueCount;
    return trueCount == 2;
}

bool test_two_windows() {
    // Two windows of N=2 M=2 each. Total output = 8 rows, 4 per window.
    const uint32_t N = 2, M = 2, W = 1;
    std::vector<SortElement> xs;
    for (uint64_t id : {42ULL, 99ULL}) {
        for (uint32_t p = 0; p < N; ++p) {
            for (uint32_t r = 0; r < M; ++r) {
                xs.push_back(makeTuple(id, p, r, true, W, id));
            }
        }
    }
    auto out = mp::crossProductExpand(xs, N, M, W);
    if (out.size() != 8) return false;

    int c42 = 0, c99 = 0;
    for (const auto& row : out) {
        if (row.id == 42) ++c42;
        if (row.id == 99) ++c99;
    }
    return c42 == 4 && c99 == 4;
}

bool test_pad_contract_violation_throws() {
    // One window with 3 tuples but N*M = 2*2 = 4. Should throw.
    const uint32_t N = 2, M = 2, W = 1;
    std::vector<SortElement> xs;
    xs.push_back(makeTuple(11, 0, 0, true, W, 0));
    xs.push_back(makeTuple(11, 0, 1, true, W, 0));
    xs.push_back(makeTuple(11, 1, 0, true, W, 0));
    // Missing the 4th tuple — pad-contract violation.
    try {
        mp::crossProductExpand(xs, N, M, W);
    } catch (const std::exception&) { return true; }
    return false;
}

bool test_large_N_refused() {
    // Synthetically construct a "would-be" large N. Don't actually allocate
    // — just attempt the call and expect it to refuse early.
    std::vector<SortElement> xs;  // empty input
    // expansionPerWindow with N=50, M=4: 4^50 = 2^100 — way past 2^40 ceiling.
    try {
        mp::crossProductExpand(xs, /*N=*/50, /*M=*/4, /*W=*/1);
    } catch (const std::exception&) { return true; }
    return false;
}

bool test_N3_M2_realistic() {
    // N=3, M=2, W=2. Two windows. M^N=8 per window → 16 output rows total.
    const uint32_t N = 3, M = 2, W = 2;
    std::vector<SortElement> xs;
    for (uint64_t id : {100ULL, 200ULL}) {
        for (uint32_t p = 0; p < N; ++p) {
            for (uint32_t r = 0; r < M; ++r) {
                xs.push_back(makeTuple(id, p, r, true, W, id));
            }
        }
    }
    auto out = mp::crossProductExpand(xs, N, M, W);
    if (out.size() != 16) return false;
    // Verify every joinedPayload has N*W = 6 blocks.
    for (const auto& row : out) {
        if (row.joinedPayload.size() != N * W) return false;
        if (!row.isIntersection) return false;
    }
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"meta_roundtrip",                test_meta_roundtrip},
        {"window_ends_simple",            test_window_ends_simple},
        {"window_starts_match_ends",      test_window_starts_match_ends},
        {"cross_product_N2_M2_one_window", test_cross_product_N2_M2_one_window},
        {"payload_content_placement",     test_payload_content_placement},
        {"is_intersection_and_aggregation", test_is_intersection_and_aggregation},
        {"two_windows",                   test_two_windows},
        {"pad_contract_violation_throws", test_pad_contract_violation_throws},
        {"large_N_refused",               test_large_N_refused},
        {"N3_M2_realistic",               test_N3_M2_realistic},
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
