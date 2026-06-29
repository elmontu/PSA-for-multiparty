#include "MpObliviousSort.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace volePSI {
namespace mpstar {

namespace {

// Bitonic sort works natively on power-of-two sized arrays. For arbitrary
// n we pad to the next power of two with sentinel elements (key = UINT64_MAX)
// that the sort pushes to the tail, then strip them.
uint64_t nextPowerOfTwo(uint64_t n)
{
    if (n <= 1) return 1;
    uint64_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

uint64_t log2Floor(uint64_t n)
{
    uint64_t r = 0;
    while ((1ULL << r) < n) ++r;
    return r;  // returns ceil(log2(n)) for n > 1; r=0 for n<=1
}

// Conditionally swap xs[i] and xs[j] IF the comparator says j should
// come BEFORE i (in the requested direction). The swap is performed by
// std::swap on the two SortElement values; in a real secret-shared
// implementation this becomes an MPC oblivious swap using the secret
// comparator output as the conditional.
//
// `direction` = true means "ascending in this subsequence" (smaller goes
// to lower index); false means "descending in this subsequence".
inline void compareAndSwap(std::vector<SortElement>& xs,
                           uint64_t i, uint64_t j,
                           bool ascending,
                           const Comparator& cmp)
{
    // Whether xs[i] > xs[j] in the comparator's sense.
    bool i_greater = cmp(xs[j], xs[i]);  // true iff xs[i] should come AFTER xs[j]
    bool shouldSwap = (i_greater == ascending);
    if (shouldSwap) std::swap(xs[i], xs[j]);
}

// One bitonic-merge stage: merges two bitonic halves of size 2^k into a
// single bitonic sequence of size 2^(k+1).
//
// Recursion-free iterative form: for distance d = 2^(k-1) down to 1,
// compare pairs (i, i+d) inside each block of size 2*d.
void bitonicMerge(std::vector<SortElement>& xs,
                  uint64_t low, uint64_t cnt,
                  bool ascending,
                  const Comparator& cmp,
                  uint64_t& compareCount)
{
    if (cnt <= 1) return;
    uint64_t k = cnt / 2;
    for (uint64_t i = low; i < low + k; ++i) {
        compareAndSwap(xs, i, i + k, ascending, cmp);
        ++compareCount;
    }
    bitonicMerge(xs, low,     k, ascending, cmp, compareCount);
    bitonicMerge(xs, low + k, k, ascending, cmp, compareCount);
}

void bitonicSortHelper(std::vector<SortElement>& xs,
                       uint64_t low, uint64_t cnt,
                       bool ascending,
                       const Comparator& cmp,
                       uint64_t& compareCount)
{
    if (cnt <= 1) return;
    uint64_t k = cnt / 2;
    bitonicSortHelper(xs, low,     k, true,  cmp, compareCount);
    bitonicSortHelper(xs, low + k, k, false, cmp, compareCount);
    bitonicMerge(xs, low, cnt, ascending, cmp, compareCount);
}

bool defaultLess(const SortElement& a, const SortElement& b)
{
    return a.key < b.key;
}

} // namespace

void obliviousBitonicSort(std::vector<SortElement>& xs)
{
    obliviousBitonicSortWithComparator(xs, defaultLess);
}

void obliviousBitonicSortWithComparator(std::vector<SortElement>& xs,
                                        const Comparator& cmp)
{
    const uint64_t n = xs.size();
    if (n <= 1) return;

    const uint64_t paddedN = nextPowerOfTwo(n);

    // Determine the width of any one payload to make padding elements
    // structurally indistinguishable. (We assume all payloads have the
    // same width; the sort tolerates differing widths but pad-stripping
    // becomes ambiguous.)
    size_t payloadW = xs.empty() ? 0 : xs[0].payload.size();

    // Pad with sentinel ∞-keyed elements.
    if (paddedN > n) {
        xs.reserve(paddedN);
        SortElement sentinel;
        sentinel.key = std::numeric_limits<uint64_t>::max();
        sentinel.payload.assign(payloadW, oc::block{});
        for (uint64_t i = n; i < paddedN; ++i) {
            xs.push_back(sentinel);
        }
    }

    uint64_t compareCount = 0;
    bitonicSortHelper(xs, 0, paddedN, true, cmp, compareCount);

    // Strip the sentinels. They must all be at the tail since
    // UINT64_MAX-keyed elements are largest under defaultLess. For
    // custom comparators this assumption may not hold — caller's
    // responsibility.
    xs.resize(n);
}

uint64_t bitonicCompareSwapCount(uint64_t n)
{
    if (n <= 1) return 0;
    const uint64_t padded = nextPowerOfTwo(n);
    const uint64_t logN = log2Floor(padded);
    // Bitonic sort: for k = 1..logN, the k-th stage has k merge phases
    // each touching padded/2 pairs. Total = padded/2 · logN · (logN+1) / 2.
    return padded / 2 * logN * (logN + 1) / 2;
}

bool isSortedAscending(const std::vector<SortElement>& xs)
{
    for (size_t i = 1; i < xs.size(); ++i) {
        if (xs[i].key < xs[i - 1].key) return false;
    }
    return true;
}

} // namespace mpstar
} // namespace volePSI
