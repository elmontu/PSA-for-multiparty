#include "MpMpcWireDriver.h"

#include <cstring>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

// Construct the composite key (id << partyIdxBits) | party_idx as a
// per-party bit-shared array. id.bits[i] are already XOR-shared with
// the other party. party_idx is a public constant absorbed by party 0.
std::array<uint8_t, 64> makeCompositeMyShare(
    const std::array<uint8_t, 64>& idShare,
    uint32_t partyIdxBits, uint32_t party_idx, uint64_t partyIdx)
{
    std::array<uint8_t, 64> out{};
    // Low partyIdxBits: public constant, party 0 holds the value.
    if (partyIdx == 0) {
        for (uint32_t i = 0; i < partyIdxBits; ++i) {
            out[i] = static_cast<uint8_t>((party_idx >> i) & 1);
        }
    }
    // High 64 - partyIdxBits: shift up the id bits.
    for (uint32_t i = 0; i + partyIdxBits < 64; ++i) {
        out[i + partyIdxBits] = idShare[i];
    }
    return out;
}

} // namespace

size_t wireMpcExecutePrivateJoinTripleCost(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    size_t universeSize)
{
    (void)partyIdxBits;
    if (N == 0 || M == 0 || universeSize == 0) return 0;
    const size_t bagSize = static_cast<size_t>(N) * M * universeSize;
    // Phase 3: sort. Payload per element = 1 (is_real) + rowDataBits.
    size_t sortCost = wireMpcBitonicSortTripleCost(bagSize, 1 + static_cast<size_t>(rowDataBits));
    // Phase 5: cross-product expansion.
    size_t expandCost = wireMpcCrossProductExpandTripleCost(universeSize, N, M);
    // Phase 6: filter over M^N * universeSize rows.
    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;
    size_t totalExpanded = static_cast<size_t>(universeSize) * combosPerWindow;
    size_t filterCost = wireMpcFilterIntersectionTripleCost(totalExpanded, N, rowDataBits);
    return sortCost + expandCost + filterCost;
}

macoro::task<std::vector<WireMpcJoinRow>> wireMpcExecutePrivateJoin(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    const std::vector<std::vector<WireJoinInputRow>>& myTable,
    const std::vector<BeaverTripleBit>& triples,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (myTable.size() != N)
        throw std::runtime_error("wireMpcExecutePrivateJoin: perParty size mismatch");
    if (myTable.empty() || myTable[0].empty()) co_return std::vector<WireMpcJoinRow>{};

    const size_t perPartyCount = myTable[0].size();
    if (perPartyCount % M != 0)
        throw std::runtime_error(
            "wireMpcExecutePrivateJoin: per-party count not divisible by M");
    for (uint32_t p = 0; p < N; ++p) {
        if (myTable[p].size() != perPartyCount)
            throw std::runtime_error("wireMpcExecutePrivateJoin: table size inconsistent");
    }

    // Phase 2: aggregate into one bag. Each input tuple → WireSortElement
    // with composite key (id || party_idx) and payload [is_real | rowData].
    std::vector<WireSortElement> bag;
    bag.reserve(static_cast<size_t>(N) * perPartyCount);
    for (uint32_t p = 0; p < N; ++p) {
        for (const auto& r : myTable[p]) {
            if (r.rowData.size() != rowDataBits)
                throw std::runtime_error(
                    "wireMpcExecutePrivateJoin: rowData size mismatch");
            WireSortElement e;
            e.key = makeCompositeMyShare(r.id, partyIdxBits, p, partyIdx);
            e.payload.reserve(1 + rowDataBits);
            e.payload.push_back(r.isReal);
            for (auto b : r.rowData) e.payload.push_back(b);
            bag.push_back(std::move(e));
        }
    }

    size_t tripleIdx = 0;

    // Phase 3: MPC bitonic sort.
    co_await wireMpcBitonicSort(bag, triples, tripleIdx, partyIdx, sock);

    // Phase 5: MPC cross-product expansion.
    auto expanded = co_await wireMpcCrossProductExpand(
        bag, N, M, partyIdxBits, rowDataBits, triples, tripleIdx, partyIdx, sock);

    // Phase 6: oblivious filter on is_intersection.
    co_await wireMpcFilterIntersection(
        expanded, N, rowDataBits, triples, tripleIdx, partyIdx, sock);

    co_return expanded;
}

} // namespace mpstar
} // namespace volePSI
