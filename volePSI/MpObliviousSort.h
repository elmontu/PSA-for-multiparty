#pragma once

// In-memory simulation of a data-oblivious bitonic sort of (key, payload)
// pairs. Foundation of the N-party private-join protocol — see
// docs/HISTORY.md, Phase 3.
//
// Properties this implementation guarantees:
//   1. STRUCTURAL OBLIVIOUSNESS: the sequence of compare-and-swap
//      operations is determined ONLY by the input length n. For any two
//      inputs of the same n, the access pattern is identical.
//   2. CORRECTNESS: output is sorted ascending by key.
//   3. STABILITY: not guaranteed (bitonic sort is unstable; OK for our
//      use because the cascade shuffles the output anyway).
//
// What this module does NOT do:
//   - SECRET-SHARED COMPARATOR. The current implementation uses a
//     plaintext comparator (the key is observable to the sorter). The
//     interface is designed so this can later be replaced with an
//     MPC-based comparator using Beaver triples (R28 dependency).
//   - SOCKET-DRIVEN MULTI-PARTY EXECUTION. This is the in-memory variant
//     for protocol validation. The wire-protocol port reuses the
//     comparator interface against per-party secret-shared inputs.

#include "cryptoTools/Common/Defines.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace volePSI {
namespace mpstar {

// An element in the sort domain: a 64-bit key (the join id, hashed) plus
// a "payload" of opaque blocks (the row data + per-tuple metadata bits
// like is_real and party_idx). The payload is opaque to the sort itself —
// it travels with the key but never affects ordering.
struct SortElement {
    uint64_t key;
    std::vector<oc::block> payload;
};

// Sort `xs` in ascending order by key, in place. Uses the bitonic-sort
// network; total compare-and-swap count is O(n · log² n).
//
//   - For n a power of two, performs n · (log₂ n) · (log₂ n + 1) / 2
//     compare-and-swaps.
//   - For arbitrary n, the input is conceptually padded to the next
//     power of two with sentinel ∞-keyed elements (which do not move into
//     the prefix and are discarded after sort).
void obliviousBitonicSort(std::vector<SortElement>& xs);

// Variant that takes an explicit comparator. The comparator returns true
// iff its second argument should be ordered BEFORE the first (i.e., the
// pair should be swapped). This is the seam where a future MPC-based
// secret-shared comparator plugs in.
using Comparator = std::function<bool(const SortElement&, const SortElement&)>;

void obliviousBitonicSortWithComparator(std::vector<SortElement>& xs,
                                        const Comparator& cmp);

// Diagnostic / verification helpers ----------------------------------

// Returns the exact compare-and-swap count the sort would perform on an
// input of length n. Used by tests to assert structural obliviousness:
// the count depends ONLY on n, not on input values.
uint64_t bitonicCompareSwapCount(uint64_t n);

// Sanity: returns true iff `xs` is in ascending order by key.
bool isSortedAscending(const std::vector<SortElement>& xs);

} // namespace mpstar
} // namespace volePSI
