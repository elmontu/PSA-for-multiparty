#include "MpMpcJoin.h"

#include <cmath>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Compose (id_bits, party_idx_plaintext) → composite key bit-shared.
// Composite layout: high (64 - partyIdxBits) bits = id, low
// partyIdxBits bits = party_idx (public constant).
SharedU64Bin makeCompositeKey(const SharedU64Bin& id, uint32_t partyIdxBits,
                              uint32_t party_idx)
{
    if (partyIdxBits > 32)
        throw std::runtime_error("makeCompositeKey: partyIdxBits too large");
    SharedU64Bin out;
    const uint32_t N = id.N();
    // Initialize all bits to zero shares.
    for (uint32_t i = 0; i < 64; ++i) out.bits[i] = SharedBit(N);
    // Low partyIdxBits = public constant party_idx.
    for (uint32_t i = 0; i < partyIdxBits; ++i) {
        uint8_t pb = (party_idx >> i) & 1;
        // Encode public bit as a share: party 0 holds the bit, others 0.
        out.bits[i].shares[0] = pb;
    }
    // High (64 - partyIdxBits) bits = id, shifted up by partyIdxBits.
    // Only the LOW (64 - partyIdxBits) bits of id are preserved; if id
    // has bits above (64 - partyIdxBits) they're silently dropped (which
    // is fine because id_hash is uniform 64-bit and we only need
    // collision resistance among the bits we keep).
    for (uint32_t i = 0; i + partyIdxBits < 64; ++i) {
        out.bits[i + partyIdxBits] = id.bits[i];
    }
    return out;
}

// Extract the id portion (high bits) from a composite key.
SharedU64Bin extractIdFromComposite(const SharedU64Bin& composite,
                                    uint32_t partyIdxBits)
{
    SharedU64Bin out;
    const uint32_t N = composite.N();
    for (uint32_t i = 0; i < 64; ++i) out.bits[i] = SharedBit(N);
    for (uint32_t i = 0; i + partyIdxBits < 64; ++i) {
        out.bits[i] = composite.bits[i + partyIdxBits];
    }
    return out;
}

// Compute AND over a list of SharedBits via a left-fold (chain).
SharedBit secureAndChain(const std::vector<SharedBit>& bits,
                         const std::vector<BeaverTripleBit>& triples,
                         size_t& tripleIndex)
{
    if (bits.empty()) {
        throw std::runtime_error("secureAndChain: empty input");
    }
    SharedBit acc = bits[0];
    for (size_t i = 1; i < bits.size(); ++i) {
        if (tripleIndex >= triples.size())
            throw std::runtime_error("secureAndChain: triple bag exhausted");
        acc = secureAnd(acc, bits[i], triples[tripleIndex++]);
    }
    return acc;
}

} // namespace

// ----------------------------------------------------------------------
// R34g

size_t mpcWindowEndsTripleCost(size_t n)
{
    if (n <= 1) return 0;
    return (n - 1) * secureEqualTripleCost();
}

std::vector<SharedBit> mpcWindowEnds(
    const std::vector<SharedSortElement>& sorted,
    uint32_t partyIdxBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex)
{
    std::vector<SharedBit> out;
    if (sorted.empty()) return out;
    const uint32_t N = sorted[0].key.N();
    out.reserve(sorted.size());

    // Compare consecutive ids (id portion of composite key). For each
    // position i in [0, n-1): boundary_i = (id_i != id_{i+1}). Position
    // n-1 is always a boundary.
    for (size_t i = 0; i + 1 < sorted.size(); ++i) {
        auto id_i  = extractIdFromComposite(sorted[i].key,     partyIdxBits);
        auto id_ip = extractIdFromComposite(sorted[i + 1].key, partyIdxBits);
        SharedBit eq = secureEqual(id_i, id_ip, triples, tripleIndex);
        // NOT eq = boundary.
        out.push_back(xorConst(eq, 1));
    }
    // Last position is always a boundary.
    SharedBit one(N);
    one.shares[0] = 1;
    out.push_back(one);
    return out;
}

// ----------------------------------------------------------------------
// R34h

size_t mpcCrossProductExpandTripleCost(
    size_t windowCount, uint32_t N, uint32_t M)
{
    if (N <= 1) return 0;
    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;
    // Per output row: (N-1) ANDs to fold is_real bits into is_intersection.
    return windowCount * combosPerWindow * (N - 1);
}

std::vector<MpcJoinRow> mpcCrossProductExpand(
    const std::vector<SharedSortElement>& sortedBag,
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits,
    uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex)
{
    if (N == 0 || M == 0)
        throw std::runtime_error("mpcCrossProductExpand: N and M must be >= 1");
    if (sortedBag.size() % (static_cast<size_t>(N) * M) != 0) {
        throw std::runtime_error(
            "mpcCrossProductExpand: bag size " + std::to_string(sortedBag.size())
            + " not a multiple of N*M = " + std::to_string(N * M));
    }

    // Overflow guard on M^N (same as plaintext expander).
    long double estLog2 = static_cast<long double>(N)
                        * std::log2(static_cast<long double>(M));
    if (estLog2 > 40.0L)
        throw std::runtime_error("mpcCrossProductExpand: M^N exceeds 2^40");

    const size_t windowCount = sortedBag.size() / (static_cast<size_t>(N) * M);

    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;

    std::vector<MpcJoinRow> out;
    out.reserve(static_cast<size_t>(windowCount) * combosPerWindow);

    // Verify each tuple's payload has the expected length.
    const size_t expectedTupleLen = 1 + rowDataBits;
    for (size_t i = 0; i < sortedBag.size(); ++i) {
        if (sortedBag[i].payload.size() != expectedTupleLen) {
            throw std::runtime_error(
                "mpcCrossProductExpand: tuple " + std::to_string(i)
                + " has payload size " + std::to_string(sortedBag[i].payload.size())
                + ", expected " + std::to_string(expectedTupleLen));
        }
    }

    for (size_t w = 0; w < windowCount; ++w) {
        const size_t baseWindow = w * static_cast<size_t>(N) * M;
        // Enumerate combinations via mixed-radix counter.
        std::vector<uint32_t> digits(N, 0);
        for (uint64_t combo = 0; combo < combosPerWindow; ++combo) {
            MpcJoinRow row;
            // Extract id from any one of the picked tuples (they're all
            // the same id within a window). Use party 0's row 0.
            row.id = extractIdFromComposite(
                sortedBag[baseWindow + 0 * M + digits[0]].key, partyIdxBits);
            row.joinedPayload.resize(static_cast<size_t>(N) * rowDataBits);
            std::vector<SharedBit> isReals;
            isReals.reserve(N);
            for (uint32_t p = 0; p < N; ++p) {
                const size_t src = baseWindow + static_cast<size_t>(p) * M + digits[p];
                // Copy the row data (payload[1..]) into the joined slot.
                for (uint32_t b = 0; b < rowDataBits; ++b) {
                    row.joinedPayload[static_cast<size_t>(p) * rowDataBits + b]
                        = sortedBag[src].payload[1 + b];
                }
                isReals.push_back(sortedBag[src].payload[0]);
            }
            row.isIntersection = secureAndChain(isReals, triples, tripleIndex);
            out.push_back(std::move(row));

            // Increment mixed-radix counter.
            for (uint32_t p = 0; p < N; ++p) {
                if (++digits[p] < M) break;
                digits[p] = 0;
            }
        }
    }

    return out;
}

// ----------------------------------------------------------------------
// R34i

size_t mpcFilterIntersectionTripleCost(
    size_t numRows, uint32_t N, uint32_t rowDataBits)
{
    // We pack each MpcJoinRow into a SharedSortElement:
    //   key                            = 64 bits (only bit 0 carries
    //                                     NOT(is_intersection); rest zeros)
    //   payload (per element)          = 64 (id bits) + N*rowDataBits
    //                                    + 1 (is_intersection bit)
    //                                  = 65 + N*rowDataBits
    size_t payloadBits = 64 + static_cast<size_t>(N) * rowDataBits + 1;
    return mpcBitonicSortTripleCost(numRows, payloadBits);
}

void mpcFilterIntersection(
    std::vector<MpcJoinRow>& rows,
    uint32_t N, uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex)
{
    if (rows.empty()) return;
    const uint32_t partyN = rows[0].id.N();

    // Encode each MpcJoinRow → SharedSortElement.
    //   key.bits[0]   = NOT(is_intersection)
    //   key.bits[1..] = 0
    //   payload[0..63]                       = id bits
    //   payload[64..64+N*rowDataBits)        = joinedPayload bits
    //   payload[64+N*rowDataBits]            = is_intersection bit
    const size_t payloadBits = 64 + static_cast<size_t>(N) * rowDataBits + 1;
    std::vector<SharedSortElement> encoded;
    encoded.reserve(rows.size());
    for (const auto& r : rows) {
        if (r.joinedPayload.size() != static_cast<size_t>(N) * rowDataBits) {
            throw std::runtime_error(
                "mpcFilterIntersection: joinedPayload size mismatch");
        }
        SharedSortElement e;
        e.key.bits.resize(64);
        for (uint32_t i = 0; i < 64; ++i) e.key.bits[i] = SharedBit(partyN);
        e.key.bits[0] = xorConst(r.isIntersection, 1);  // 0 if intersection, 1 if dummy
        e.payload.reserve(payloadBits);
        for (uint32_t i = 0; i < 64; ++i)               e.payload.push_back(r.id.bits[i]);
        for (size_t i = 0; i < r.joinedPayload.size(); ++i)
            e.payload.push_back(r.joinedPayload[i]);
        e.payload.push_back(r.isIntersection);
        encoded.push_back(std::move(e));
    }

    mpcBitonicSort(encoded, triples, tripleIndex);

    // Decode back.
    for (size_t i = 0; i < rows.size(); ++i) {
        MpcJoinRow r;
        r.id.bits.resize(64);
        for (uint32_t b = 0; b < 64; ++b) r.id.bits[b] = encoded[i].payload[b];
        r.joinedPayload.assign(
            encoded[i].payload.begin() + 64,
            encoded[i].payload.begin() + 64 + static_cast<size_t>(N) * rowDataBits);
        r.isIntersection = encoded[i].payload[64 + static_cast<size_t>(N) * rowDataBits];
        rows[i] = std::move(r);
    }
}

// ----------------------------------------------------------------------
// R34j — end-to-end driver

size_t mpcExecutePrivateJoinInMemoryTripleCost(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    size_t universeSize)
{
    if (N == 0 || M == 0 || universeSize == 0) return 0;
    const size_t bagSize = static_cast<size_t>(N) * M * universeSize;
    // Phase 3: bitonic sort. Payload bits per element = 1 (is_real) +
    // rowDataBits.
    size_t sortCost = mpcBitonicSortTripleCost(
        bagSize, 1 + static_cast<size_t>(rowDataBits));
    // Phase 5: cross-product expansion. windowCount = universeSize.
    size_t expandCost = mpcCrossProductExpandTripleCost(universeSize, N, M);
    // Phase 6: filter.
    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;
    size_t totalExpanded = static_cast<size_t>(universeSize) * combosPerWindow;
    size_t filterCost = mpcFilterIntersectionTripleCost(
        totalExpanded, N, rowDataBits);
    (void)partyIdxBits;
    return sortCost + expandCost + filterCost;
}

std::vector<MpcJoinRow> mpcExecutePrivateJoinInMemory(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    const std::vector<std::vector<JoinInputRowShared>>& perParty,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex)
{
    if (perParty.size() != N)
        throw std::runtime_error("mpcExecutePrivateJoinInMemory: perParty size mismatch");
    if (perParty.empty() || perParty[0].empty()) return {};

    const uint32_t partyN = perParty[0][0].id.N();

    // Verify pad-contract: every party has the same number of tuples,
    // and that count is divisible by M (= N's M tuples per id-in-universe).
    const size_t perPartyCount = perParty[0].size();
    if (perPartyCount % M != 0)
        throw std::runtime_error(
            "mpcExecutePrivateJoinInMemory: per-party count not divisible by M");
    const size_t universeSize = perPartyCount / M;
    for (uint32_t i = 0; i < N; ++i) {
        if (perParty[i].size() != perPartyCount)
            throw std::runtime_error(
                "mpcExecutePrivateJoinInMemory: party " + std::to_string(i)
                + " has " + std::to_string(perParty[i].size())
                + " tuples; expected " + std::to_string(perPartyCount));
    }

    // Phase 2: aggregate into one bag. Each tuple → SharedSortElement
    // with composite key (id || party_idx).
    std::vector<SharedSortElement> bag;
    bag.reserve(static_cast<size_t>(N) * perPartyCount);
    for (uint32_t i = 0; i < N; ++i) {
        for (const auto& r : perParty[i]) {
            if (r.rowData.size() != rowDataBits)
                throw std::runtime_error(
                    "mpcExecutePrivateJoinInMemory: rowData size mismatch");
            SharedSortElement e;
            e.key = makeCompositeKey(r.id, partyIdxBits, i);
            e.payload.reserve(1 + rowDataBits);
            e.payload.push_back(r.isReal);
            for (const auto& b : r.rowData) e.payload.push_back(b);
            bag.push_back(std::move(e));
        }
    }

    // Phase 3: MPC bitonic sort.
    mpcBitonicSort(bag, triples, tripleIndex);

    // Phase 5: cross-product expansion.
    auto expanded = mpcCrossProductExpand(
        bag, N, M, partyIdxBits, rowDataBits, triples, tripleIndex);

    // Phase 6: oblivious filter on is_intersection.
    mpcFilterIntersection(expanded, N, rowDataBits, triples, tripleIndex);

    (void)partyN;
    (void)universeSize;
    return expanded;
}

} // namespace mpstar
} // namespace volePSI
