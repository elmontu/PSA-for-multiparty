#include "MpJoinFilter.h"
#include "MpObliviousSort.h"

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Encode a JoinExpandedRow as a SortElement. Layout of the resulting
// payload (with N*W payload blocks plus metadata):
//   payload[0]   = metadata block where bytes 0..7 hold the id, byte 8
//                   holds the is_intersection flag (0/1). The same layout
//                   is reused via packTupleMeta-style packing — we hijack
//                   the row_idx_in_id slot to also store is_intersection.
//   payload[1..] = the joinedPayload blocks (N*W total)
//
// Key choice: rank = (0 if is_intersection else 1). Sort ascending →
// is_intersection rows come first.
SortElement encodeRow(const JoinExpandedRow& row)
{
    SortElement e;
    e.key = row.isIntersection ? 0ULL : 1ULL;

    e.payload.resize(1 + row.joinedPayload.size());
    // Pack: id (8 bytes), is_intersection (1 byte), zero pad (7 bytes).
    std::memset(&e.payload[0], 0, 16);
    auto* p = reinterpret_cast<uint8_t*>(&e.payload[0]);
    std::memcpy(p, &row.id, 8);
    p[8] = row.isIntersection ? 1 : 0;

    for (size_t i = 0; i < row.joinedPayload.size(); ++i) {
        e.payload[1 + i] = row.joinedPayload[i];
    }
    return e;
}

JoinExpandedRow decodeRow(const SortElement& e, uint32_t N, uint32_t payloadW)
{
    JoinExpandedRow row;
    if (e.payload.size() != 1 + static_cast<size_t>(N) * payloadW)
        throw std::runtime_error("decodeRow: payload size mismatch");
    const auto* p = reinterpret_cast<const uint8_t*>(&e.payload[0]);
    std::memcpy(&row.id, p, 8);
    row.isIntersection = (p[8] != 0);
    row.joinedPayload.assign(e.payload.begin() + 1, e.payload.end());
    return row;
}

} // namespace

void obliviousFilterIntersection(std::vector<JoinExpandedRow>& rows,
                                 uint32_t payloadW)
{
    if (rows.empty()) return;

    // Determine N from the first row's joinedPayload size.
    const size_t totalPayloadBlocks = rows[0].joinedPayload.size();
    if (payloadW == 0 || totalPayloadBlocks % payloadW != 0)
        throw std::runtime_error(
            "obliviousFilterIntersection: payloadW does not divide "
            "joinedPayload.size()");
    const uint32_t N = static_cast<uint32_t>(totalPayloadBlocks / payloadW);

    // Encode to SortElements.
    std::vector<SortElement> encoded;
    encoded.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.joinedPayload.size() != totalPayloadBlocks)
            throw std::runtime_error(
                "obliviousFilterIntersection: inconsistent joinedPayload size");
        encoded.push_back(encodeRow(row));
    }

    // Bitonic sort by rank (intersection rows have key=0, dummies have key=1).
    obliviousBitonicSort(encoded);

    // Decode back.
    for (size_t i = 0; i < rows.size(); ++i) {
        rows[i] = decodeRow(encoded[i], N, payloadW);
    }
}

void truncateToK(std::vector<JoinExpandedRow>& rows, size_t K)
{
    if (K < rows.size()) rows.resize(K);
}

size_t countIntersection(const std::vector<JoinExpandedRow>& rows)
{
    size_t k = 0;
    for (const auto& row : rows) if (row.isIntersection) ++k;
    return k;
}

size_t filterAndTruncate(std::vector<JoinExpandedRow>& rows, uint32_t payloadW)
{
    obliviousFilterIntersection(rows, payloadW);
    size_t k = countIntersection(rows);
    truncateToK(rows, k);
    return k;
}

} // namespace mpstar
} // namespace volePSI
