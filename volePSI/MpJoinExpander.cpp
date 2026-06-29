#include "MpJoinExpander.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

oc::block packTupleMeta(uint32_t party_idx, uint32_t row_idx, bool is_real)
{
    oc::block out;
    std::memset(&out, 0, sizeof(out));
    auto* p = reinterpret_cast<uint8_t*>(&out);
    std::memcpy(p + 0, &party_idx, 4);
    std::memcpy(p + 4, &row_idx,   4);
    p[8] = is_real ? 1 : 0;
    return out;
}

void unpackTupleMeta(const oc::block& meta,
                     uint32_t& out_party_idx,
                     uint32_t& out_row_idx,
                     bool& out_is_real)
{
    const auto* p = reinterpret_cast<const uint8_t*>(&meta);
    std::memcpy(&out_party_idx, p + 0, 4);
    std::memcpy(&out_row_idx,   p + 4, 4);
    out_is_real = (p[8] != 0);
}

std::vector<bool> detectWindowEnds(const std::vector<SortElement>& sorted)
{
    const size_t n = sorted.size();
    std::vector<bool> ends(n, false);
    if (n == 0) return ends;
    for (size_t i = 0; i + 1 < n; ++i) {
        ends[i] = (sorted[i + 1].key != sorted[i].key);
    }
    ends[n - 1] = true;
    return ends;
}

std::vector<size_t> windowStartIndices(const std::vector<SortElement>& sorted)
{
    std::vector<size_t> starts;
    if (sorted.empty()) return starts;
    starts.push_back(0);
    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i].key != sorted[i - 1].key) starts.push_back(i);
    }
    return starts;
}

std::vector<JoinExpandedRow> crossProductExpand(
    const std::vector<SortElement>& sorted,
    uint32_t N, uint32_t M, uint32_t payloadW)
{
    if (N == 0 || M == 0)
        throw std::runtime_error("crossProductExpand: N and M must be >= 1");

    // Estimate output size to reserve. M^N can overflow for large N — guard.
    // M=10, N=18 → ~6e17. We refuse N*log2(M) > 40 (~1 trillion output rows
    // ceiling); this is well past anything testable in-memory.
    long double estLog2 = static_cast<long double>(N)
                        * std::log2(static_cast<long double>(M));
    if (estLog2 > 40.0L)
        throw std::runtime_error("crossProductExpand: M^N exceeds 2^40 — refuse");

    uint64_t expansionPerWindow = 1;
    for (uint32_t p = 0; p < N; ++p) expansionPerWindow *= M;

    auto starts = windowStartIndices(sorted);
    std::vector<JoinExpandedRow> out;
    out.reserve(starts.size() * expansionPerWindow);

    for (size_t w = 0; w < starts.size(); ++w) {
        size_t start = starts[w];
        size_t end   = (w + 1 < starts.size()) ? starts[w + 1] : sorted.size();
        size_t window_size = end - start;

        // Pad-input contract: every (party, id) pair has exactly M tuples
        // → every window contains exactly N*M tuples.
        if (window_size != static_cast<size_t>(N) * M) {
            throw std::runtime_error(
                "crossProductExpand: window at id-key "
                + std::to_string(sorted[start].key)
                + " has " + std::to_string(window_size)
                + " tuples, expected N*M = " + std::to_string(static_cast<size_t>(N) * M)
                + " (pad-input contract violated)");
        }

        // Group tuples by party_idx for fast picking. byParty[p] is a list
        // of indices into `sorted` for party p's M tuples.
        std::vector<std::vector<size_t>> byParty(N);
        for (auto& v : byParty) v.reserve(M);
        for (size_t i = start; i < end; ++i) {
            uint32_t p_idx = 0, r_idx = 0; bool is_real = false;
            unpackTupleMeta(sorted[i].payload[0], p_idx, r_idx, is_real);
            if (p_idx >= N) {
                throw std::runtime_error(
                    "crossProductExpand: party_idx " + std::to_string(p_idx)
                    + " out of range for N=" + std::to_string(N));
            }
            byParty[p_idx].push_back(i);
        }
        for (uint32_t p = 0; p < N; ++p) {
            if (byParty[p].size() != M) {
                throw std::runtime_error(
                    "crossProductExpand: party " + std::to_string(p)
                    + " has " + std::to_string(byParty[p].size())
                    + " tuples in window at id "
                    + std::to_string(sorted[start].key)
                    + ", expected M=" + std::to_string(M));
            }
        }

        // Enumerate M^N combinations. Use mixed-radix counter: digit p
        // ranges over [0, M).
        std::vector<uint32_t> digits(N, 0);
        for (uint64_t combo = 0; combo < expansionPerWindow; ++combo) {
            JoinExpandedRow row;
            row.id = sorted[start].key;
            row.joinedPayload.resize(static_cast<size_t>(N) * payloadW);
            bool all_real = true;
            for (uint32_t p = 0; p < N; ++p) {
                size_t src = byParty[p][digits[p]];
                // Verify the source payload has metadata + payloadW blocks.
                if (sorted[src].payload.size() < 1 + payloadW) {
                    throw std::runtime_error(
                        "crossProductExpand: tuple payload too short ("
                        + std::to_string(sorted[src].payload.size())
                        + " < 1+W=" + std::to_string(1 + payloadW) + ")");
                }
                uint32_t p2 = 0, r2 = 0; bool real = false;
                unpackTupleMeta(sorted[src].payload[0], p2, r2, real);
                if (!real) all_real = false;
                // Copy the payload portion (blocks 1..1+W) into the joined slot.
                for (uint32_t w_blk = 0; w_blk < payloadW; ++w_blk) {
                    row.joinedPayload[p * payloadW + w_blk] =
                        sorted[src].payload[1 + w_blk];
                }
            }
            row.isIntersection = all_real;
            out.push_back(std::move(row));

            // Increment the mixed-radix counter.
            for (uint32_t p = 0; p < N; ++p) {
                if (++digits[p] < M) break;
                digits[p] = 0;
            }
        }
    }

    return out;
}

} // namespace mpstar
} // namespace volePSI
