#pragma once

// Phase 6 of the N-party private-join protocol (R31). See
// docs/HISTORY.md.
//
// After Phase 5 cross-product expansion, the output contains |windows| ·
// M^N rows of which only |I| · M^N (intersection windows) have
// is_intersection = true. We need to obliviously SORT all rows so the
// intersection rows come first, then truncate to a public ceiling.
//
// "Obliviously" here means structurally — the sort uses the bitonic
// network from MpObliviousSort, so the compare-swap access pattern
// depends only on the input length, not on any is_intersection value.
//
// Cardinality leakage: the TRUNCATION step reveals the intersection
// cardinality K (= number of intersection rows after expansion) if the
// caller calls truncateToK with the actual K. To hide K, pad to a
// public ceiling Cmax >= |I| · M^N (the same Cmax pattern used in T17
// cardinality hiding for the existing MPSA cascade).

#include "MpJoinExpander.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// Sort `rows` in place so all is_intersection=true rows come before all
// is_intersection=false rows. Within each group, ordering is
// unspecified (bitonic sort is unstable; for filter purposes any
// tie-breaking is fine). Structurally oblivious.
void obliviousFilterIntersection(std::vector<JoinExpandedRow>& rows,
                                 uint32_t payloadW);

// Truncate to K rows (drop the rest). After obliviousFilterIntersection
// with K = intersection count, the remaining rows are exactly the
// intersection rows.
//
// CAVEAT: passing the *actual* intersection count K leaks it. To hide
// the count, choose K = Cmax (a public ceiling) and pad the output up
// to Cmax with dummies (mirroring the T17 cardinality-hiding pattern).
// This module exposes the leakage explicitly — the caller decides the
// privacy trade-off.
void truncateToK(std::vector<JoinExpandedRow>& rows, size_t K);

// Counts is_intersection=true rows. Observable to whoever counts; do not
// reveal directly if cardinality hiding is desired.
size_t countIntersection(const std::vector<JoinExpandedRow>& rows);

// Convenience: filter + truncate to actual intersection count. Returns
// the actual K (count of intersection rows). Equivalent to:
//   obliviousFilterIntersection(rows, W); truncateToK(rows, countIntersection(rows))
// Leaks K to the caller.
size_t filterAndTruncate(std::vector<JoinExpandedRow>& rows, uint32_t payloadW);

} // namespace mpstar
} // namespace volePSI
