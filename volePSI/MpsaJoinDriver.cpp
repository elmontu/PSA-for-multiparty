#include "MpsaJoinDriver.h"
#include "MpObliviousSort.h"
#include "MpJoinExpander.h"
#include "MpJoinFilter.h"

#include "cryptoTools/Common/Defines.h"

#include <map>
#include <set>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

// Phase 1: per-party pad+commit, simulated in-memory.
//
// For each party i, take its input table T_i. The distinct ids in T_i
// form one part of the universe; we also need to cover ids that this
// party doesn't have but OTHER parties do (so the cross-product produces
// proper "missing-party" rows that fall out at Phase 6 filtering).
//
// "ids universe" = union of ids across all parties.
//
// For each (party i, id u in universe):
//   - if i has k rows for u (k <= M): output M tuples; first k are real,
//     last M-k are dummies (is_real = 0, payload zeros).
//   - if i has 0 rows for u: output M all-dummy tuples.
//
// Result: total bag size = N * |universe| * M tuples. Each tuple is a
// SortElement with key = id and a metadata-packed payload.
std::vector<SortElement> padAndAggregate(
    uint32_t N, uint32_t M, uint32_t payloadW,
    const std::vector<JoinInputTable>& perParty)
{
    // Build the universe of ids.
    std::set<uint64_t> universe;
    for (const auto& table : perParty) {
        for (const auto& row : table) universe.insert(row.id);
    }

    // Group each party's rows by id for fast lookup.
    std::vector<std::map<uint64_t, std::vector<const JoinInputRow*>>> byId(N);
    for (uint32_t i = 0; i < N; ++i) {
        for (const auto& row : perParty[i]) {
            if (row.row_data.size() != payloadW) {
                throw std::runtime_error(
                    "executePrivateJoinInMemory: party " + std::to_string(i)
                    + " row has width " + std::to_string(row.row_data.size())
                    + ", expected W=" + std::to_string(payloadW));
            }
            byId[i][row.id].push_back(&row);
        }
        for (const auto& [id, vec] : byId[i]) {
            if (vec.size() > M) {
                throw std::runtime_error(
                    "executePrivateJoinInMemory: party " + std::to_string(i)
                    + " has " + std::to_string(vec.size())
                    + " rows for id, exceeds M=" + std::to_string(M));
            }
        }
    }

    // Emit N * |universe| * M tuples.
    std::vector<SortElement> bag;
    bag.reserve(static_cast<size_t>(N) * universe.size() * M);
    for (uint64_t u : universe) {
        for (uint32_t i = 0; i < N; ++i) {
            auto it = byId[i].find(u);
            const std::vector<const JoinInputRow*>* myRows =
                (it != byId[i].end()) ? &it->second : nullptr;
            uint32_t realCount = myRows ? static_cast<uint32_t>(myRows->size()) : 0;

            for (uint32_t r = 0; r < M; ++r) {
                SortElement e;
                e.key = u;
                e.payload.resize(1 + payloadW);
                bool isReal = (r < realCount);
                e.payload[0] = packTupleMeta(i, r, isReal);
                if (isReal) {
                    for (uint32_t w = 0; w < payloadW; ++w) {
                        e.payload[1 + w] = (*myRows)[r]->row_data[w];
                    }
                } else {
                    // Dummies carry zero payload. In the wire protocol
                    // these are PRNG-random to be indistinguishable from
                    // real rows on the wire; in the in-memory simulation
                    // zero is sufficient since payload is never compared
                    // until after Phase 6 filter drops them.
                    for (uint32_t w = 0; w < payloadW; ++w) {
                        std::memset(&e.payload[1 + w], 0, sizeof(oc::block));
                    }
                }
                bag.push_back(std::move(e));
            }
        }
    }

    return bag;
}

} // namespace

std::vector<JoinExpandedRow> executePrivateJoinInMemory(
    uint32_t N, uint32_t M, uint32_t payloadW,
    const std::vector<JoinInputTable>& perParty)
{
    if (N < 2)
        throw std::runtime_error("executePrivateJoinInMemory: N must be >= 2");
    if (M < 1)
        throw std::runtime_error("executePrivateJoinInMemory: M must be >= 1");
    if (payloadW < 1)
        throw std::runtime_error("executePrivateJoinInMemory: payloadW must be >= 1");
    if (perParty.size() != N)
        throw std::runtime_error("executePrivateJoinInMemory: perParty.size() != N");

    // Phase 1 + 2: pad-and-aggregate.
    auto bag = padAndAggregate(N, M, payloadW, perParty);

    // Phase 3: oblivious sort by id.
    obliviousBitonicSort(bag);

    // Phase 4 + 5: window detect (implicit inside crossProductExpand) +
    // cross-product expansion.
    auto expanded = crossProductExpand(bag, N, M, payloadW);

    // Phase 6: filter is_intersection + truncate.
    (void)filterAndTruncate(expanded, payloadW);

    return expanded;
}

} // namespace mpstar
} // namespace volePSI
