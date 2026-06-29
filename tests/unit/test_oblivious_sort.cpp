// Unit tests for volePSI/MpObliviousSort.h — in-memory bitonic sort of
// (key, payload) pairs. Foundation primitive for the N-party private
// join (R29; see docs/PRIVATE_JOIN_DESIGN.md). Verifies:
//   1. Correctness on simple/random/edge-case inputs
//   2. Payload travels with key (no scrambling)
//   3. Structural obliviousness: compare-swap count depends only on n
//   4. Idempotence (sorting an already-sorted input)
//   5. Stability is NOT guaranteed (sanity — bitonic sort is unstable)
//   6. Custom comparator hook works
//   7. Non-power-of-two input sizes handled correctly via padding

#include "volePSI/MpObliviousSort.h"

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
using mp::SortElement;
using oc::block;

static SortElement makeElem(uint64_t key, uint64_t payloadTag) {
    SortElement e;
    e.key = key;
    e.payload.resize(2);
    std::memset(&e.payload[0], 0, 16);
    std::memcpy(&e.payload[0], &payloadTag, 8);
    return e;
}

static uint64_t payloadTag(const SortElement& e) {
    uint64_t tag = 0;
    std::memcpy(&tag, &e.payload[0], 8);
    return tag;
}

// --------------------------------------------------------------

bool test_sort_simple_ascending() {
    std::vector<SortElement> xs;
    for (int k : {5, 3, 8, 1, 9, 2, 7, 4, 6}) {
        xs.push_back(makeElem(k, k));
    }
    mp::obliviousBitonicSort(xs);
    return mp::isSortedAscending(xs) && xs.size() == 9;
}

bool test_payload_follows_key() {
    // Each element's payload is uniquely tied to its key. After sort, the
    // payload at position i must equal the element whose key landed at i.
    std::vector<SortElement> xs;
    for (uint64_t k : {7, 2, 5, 9, 1, 3, 8, 4, 6}) {
        xs.push_back(makeElem(k, k * 100 + 7));  // distinctive payload encoding
    }
    mp::obliviousBitonicSort(xs);
    if (!mp::isSortedAscending(xs)) return false;
    for (size_t i = 0; i < xs.size(); ++i) {
        if (payloadTag(xs[i]) != xs[i].key * 100 + 7) return false;
    }
    return true;
}

bool test_structural_obliviousness_constant_count() {
    // The compare-swap count must depend ONLY on n, not on input values.
    // Run two different inputs of the same size; both must yield the
    // same predicted count from bitonicCompareSwapCount(n).
    std::mt19937 g(0xC0DE);
    const uint64_t n = 128;

    std::vector<SortElement> xs1, xs2;
    for (uint64_t i = 0; i < n; ++i) {
        xs1.push_back(makeElem(g(), i));
        xs2.push_back(makeElem(g(), i));
    }

    uint64_t count1 = 0, count2 = 0;
    auto cmp1 = [&](const SortElement& a, const SortElement& b) {
        ++count1; return a.key < b.key;
    };
    auto cmp2 = [&](const SortElement& a, const SortElement& b) {
        ++count2; return a.key < b.key;
    };
    mp::obliviousBitonicSortWithComparator(xs1, cmp1);
    mp::obliviousBitonicSortWithComparator(xs2, cmp2);

    if (count1 != count2) return false;
    return count1 == mp::bitonicCompareSwapCount(n);
}

bool test_compare_swap_count_grows_n_log2_n() {
    // bitonicCompareSwapCount(n) for power-of-two n should match the
    // analytic formula: n/2 · logN · (logN+1) / 2.
    for (uint64_t n : {2ULL, 4ULL, 8ULL, 16ULL, 64ULL, 256ULL, 1024ULL}) {
        uint64_t logN = 0;
        while ((1ULL << logN) < n) ++logN;
        uint64_t expected = n / 2 * logN * (logN + 1) / 2;
        if (mp::bitonicCompareSwapCount(n) != expected) return false;
    }
    return true;
}

bool test_idempotence_sorted_input() {
    std::vector<SortElement> xs;
    for (uint64_t k = 0; k < 16; ++k) xs.push_back(makeElem(k, k));
    auto before = xs;
    mp::obliviousBitonicSort(xs);
    if (xs.size() != before.size()) return false;
    for (size_t i = 0; i < xs.size(); ++i) {
        if (xs[i].key != before[i].key) return false;
        if (payloadTag(xs[i]) != payloadTag(before[i])) return false;
    }
    return true;
}

bool test_non_power_of_two_n() {
    // Padding to next power of two must not corrupt the output for
    // arbitrary n. Try several non-power-of-two sizes including n=7, 13, 31.
    std::mt19937 g(0xBEEF);
    for (uint64_t n : {7ULL, 13ULL, 31ULL, 100ULL, 333ULL}) {
        std::vector<SortElement> xs;
        for (uint64_t i = 0; i < n; ++i) xs.push_back(makeElem(g() % 1000, i));
        mp::obliviousBitonicSort(xs);
        if (xs.size() != n) return false;
        if (!mp::isSortedAscending(xs)) return false;
    }
    return true;
}

bool test_custom_comparator_descending() {
    // Custom comparator: sort DESCENDING.
    std::vector<SortElement> xs;
    for (uint64_t k : {3, 1, 4, 1, 5, 9, 2, 6}) xs.push_back(makeElem(k, k));
    auto descending = [](const SortElement& a, const SortElement& b) {
        return a.key > b.key;
    };
    mp::obliviousBitonicSortWithComparator(xs, descending);
    for (size_t i = 1; i < xs.size(); ++i) {
        if (xs[i].key > xs[i - 1].key) return false;
    }
    return true;
}

bool test_large_random_input() {
    std::mt19937_64 g(0xDEADBEEFCAFE);
    const size_t n = 4096;
    std::vector<SortElement> xs;
    xs.reserve(n);
    for (size_t i = 0; i < n; ++i) xs.push_back(makeElem(g() % (1ULL<<32), i));
    mp::obliviousBitonicSort(xs);
    return xs.size() == n && mp::isSortedAscending(xs);
}

bool test_duplicate_keys_handled() {
    // Many duplicates — should still sort correctly, payloads may end up
    // in any order WITHIN a duplicate group (bitonic is unstable).
    std::vector<SortElement> xs;
    for (int i = 0; i < 20; ++i) xs.push_back(makeElem(i / 5, i));
    mp::obliviousBitonicSort(xs);
    if (!mp::isSortedAscending(xs)) return false;
    // Group counts preserved.
    int counts[4] = {0, 0, 0, 0};
    for (const auto& e : xs) counts[e.key]++;
    for (int c : counts) if (c != 5) return false;
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"sort_simple_ascending",                test_sort_simple_ascending},
        {"payload_follows_key",                  test_payload_follows_key},
        {"structural_obliviousness_constant_count", test_structural_obliviousness_constant_count},
        {"compare_swap_count_grows_n_log2_n",    test_compare_swap_count_grows_n_log2_n},
        {"idempotence_sorted_input",             test_idempotence_sorted_input},
        {"non_power_of_two_n",                   test_non_power_of_two_n},
        {"custom_comparator_descending",         test_custom_comparator_descending},
        {"large_random_input",                   test_large_random_input},
        {"duplicate_keys_handled",               test_duplicate_keys_handled},
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
