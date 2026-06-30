#include "MpMpcWireOps.h"

#include "MpObliviousSort.h"  // for bitonicCompareSwapCount + helper formula

#include <stdexcept>
#include <utility>

namespace volePSI {
namespace mpstar {

namespace {

uint64_t nextPow2u(uint64_t n) {
    if (n <= 1) return 1;
    uint64_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

} // namespace

macoro::task<void> wireConditionalSwap(
    WireSortElement& a,
    WireSortElement& b,
    uint8_t selector,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (a.payload.size() != b.payload.size())
        throw std::runtime_error("wireConditionalSwap: payload size mismatch");

    auto swapOneBit = [&](uint8_t& aBit, uint8_t& bBit) -> macoro::task<void> {
        uint8_t diff = static_cast<uint8_t>((aBit ^ bBit) & 1);
        if (tripleIdx >= triples.size())
            throw std::runtime_error("wireConditionalSwap: triple bag exhausted");
        const auto& triple = triples[tripleIdx++];
        // maskedDiff = selector AND diff
        uint8_t maskedDiff = co_await wireSecureAndT(selector, diff, triple, partyIdx, sock);
        // a_new = a XOR maskedDiff; b_new = b XOR maskedDiff
        aBit = static_cast<uint8_t>((aBit ^ maskedDiff) & 1);
        bBit = static_cast<uint8_t>((bBit ^ maskedDiff) & 1);
        co_return;
    };

    for (uint32_t i = 0; i < 64; ++i) {
        co_await swapOneBit(a.key[i], b.key[i]);
    }
    for (size_t i = 0; i < a.payload.size(); ++i) {
        co_await swapOneBit(a.payload[i], b.payload[i]);
    }
}

size_t wireMpcBitonicSortTripleCost(size_t n, size_t payloadBits) {
    if (n <= 1) return 0;
    size_t padded = nextPow2u(n);
    uint64_t swaps = bitonicCompareSwapCount(padded);
    size_t perSwap = wireSecureLessThanTripleCost() + 64 + payloadBits;
    return static_cast<size_t>(swaps) * perSwap;
}

namespace {

macoro::task<void> wireMpcCompareAndSwap(
    WireSortElement& a, WireSortElement& b,
    bool ascending,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    // ascending=true → swap iff a > b, i.e., secureLessThan(b, a) = 1
    // ascending=false → swap iff a < b, i.e., secureLessThan(a, b) = 1
    uint8_t selector;
    if (ascending) {
        selector = co_await wireSecureLessThan(b.key, a.key, triples, tripleIdx, partyIdx, sock);
    } else {
        selector = co_await wireSecureLessThan(a.key, b.key, triples, tripleIdx, partyIdx, sock);
    }
    co_await wireConditionalSwap(a, b, selector, triples, tripleIdx, partyIdx, sock);
}

macoro::task<void> wireMpcBitonicMerge(
    std::vector<WireSortElement>& xs,
    size_t low, size_t cnt, bool ascending,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (cnt <= 1) co_return;
    size_t k = cnt / 2;
    for (size_t i = low; i < low + k; ++i) {
        co_await wireMpcCompareAndSwap(xs[i], xs[i + k], ascending, triples, tripleIdx, partyIdx, sock);
    }
    co_await wireMpcBitonicMerge(xs, low,     k, ascending, triples, tripleIdx, partyIdx, sock);
    co_await wireMpcBitonicMerge(xs, low + k, k, ascending, triples, tripleIdx, partyIdx, sock);
}

macoro::task<void> wireMpcBitonicSortHelper(
    std::vector<WireSortElement>& xs,
    size_t low, size_t cnt, bool ascending,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (cnt <= 1) co_return;
    size_t k = cnt / 2;
    co_await wireMpcBitonicSortHelper(xs, low,     k, true,  triples, tripleIdx, partyIdx, sock);
    co_await wireMpcBitonicSortHelper(xs, low + k, k, false, triples, tripleIdx, partyIdx, sock);
    co_await wireMpcBitonicMerge(xs, low, cnt, ascending, triples, tripleIdx, partyIdx, sock);
}

} // namespace

macoro::task<void> wireMpcBitonicSort(
    std::vector<WireSortElement>& xs,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    size_t n = xs.size();
    if (n <= 1) co_return;
    size_t padded = nextPow2u(n);

    // Pad with sentinels (all-1 key for ascending sort; payload zeros).
    // Sentinel shares: party 0 contributes all-1 key bits, party 1
    // contributes all-0. XOR-joint = all-1 (max u64).
    if (padded > n) {
        size_t payloadLen = xs[0].payload.size();
        WireSortElement sentinel;
        sentinel.key.fill(0);
        if (partyIdx == 0) sentinel.key.fill(1);
        sentinel.payload.assign(payloadLen, 0);
        xs.reserve(padded);
        for (size_t i = n; i < padded; ++i) xs.push_back(sentinel);
    }

    co_await wireMpcBitonicSortHelper(xs, 0, padded, true, triples, tripleIdx, partyIdx, sock);

    // Strip sentinels (sorted to tail).
    xs.resize(n);
}

// ----------------------------------------------------------------------
// R36c: wire cross-product expansion + filter

size_t wireMpcCrossProductExpandTripleCost(size_t windowCount, uint32_t N, uint32_t M)
{
    if (N <= 1) return 0;
    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;
    return windowCount * combosPerWindow * (N - 1);
}

namespace {

// Extract id portion (high bits) from composite key (id || party_idx).
std::array<uint8_t, 64> extractIdBits(const std::array<uint8_t, 64>& composite,
                                      uint32_t partyIdxBits)
{
    std::array<uint8_t, 64> out{};
    for (uint32_t i = 0; i + partyIdxBits < 64; ++i) {
        out[i] = composite[i + partyIdxBits];
    }
    return out;
}

} // namespace

macoro::task<std::vector<WireMpcJoinRow>> wireMpcCrossProductExpand(
    const std::vector<WireSortElement>& sortedBag,
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits,
    uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (N == 0 || M == 0)
        throw std::runtime_error("wireMpcCrossProductExpand: N and M must be >= 1");
    if (sortedBag.size() % (static_cast<size_t>(N) * M) != 0)
        throw std::runtime_error("wireMpcCrossProductExpand: bag size not multiple of N*M");

    const size_t windowCount = sortedBag.size() / (static_cast<size_t>(N) * M);
    uint64_t combosPerWindow = 1;
    for (uint32_t i = 0; i < N; ++i) combosPerWindow *= M;

    std::vector<WireMpcJoinRow> out;
    out.reserve(static_cast<size_t>(windowCount) * combosPerWindow);

    // Per-tuple payload layout: [is_real bit][row data bits ...]
    const size_t expectedTupleBits = 1 + rowDataBits;
    for (size_t i = 0; i < sortedBag.size(); ++i) {
        if (sortedBag[i].payload.size() != expectedTupleBits)
            throw std::runtime_error("wireMpcCrossProductExpand: tuple payload size mismatch");
    }

    for (size_t w = 0; w < windowCount; ++w) {
        const size_t baseWindow = w * static_cast<size_t>(N) * M;
        std::vector<uint32_t> digits(N, 0);

        for (uint64_t combo = 0; combo < combosPerWindow; ++combo) {
            WireMpcJoinRow row;
            // Extract id from party 0's row 0 (all same id within window).
            row.id = extractIdBits(sortedBag[baseWindow + 0 * M + digits[0]].key, partyIdxBits);
            row.joinedPayload.resize(static_cast<size_t>(N) * rowDataBits);

            // Collect is_real bits to AND together.
            std::vector<uint8_t> isReals;
            isReals.reserve(N);

            for (uint32_t p = 0; p < N; ++p) {
                const size_t src = baseWindow + static_cast<size_t>(p) * M + digits[p];
                // Copy payload bits 1..1+rowDataBits into joined slot.
                for (uint32_t b = 0; b < rowDataBits; ++b) {
                    row.joinedPayload[static_cast<size_t>(p) * rowDataBits + b]
                        = sortedBag[src].payload[1 + b];
                }
                isReals.push_back(sortedBag[src].payload[0]);
            }

            // AND-chain via wireSecureAndT (N-1 ANDs).
            uint8_t acc = isReals[0];
            for (size_t i = 1; i < isReals.size(); ++i) {
                if (tripleIdx >= triples.size())
                    throw std::runtime_error("wireMpcCrossProductExpand: triple bag exhausted");
                acc = co_await wireSecureAndT(acc, isReals[i], triples[tripleIdx++], partyIdx, sock);
            }
            row.isIntersection = acc;
            out.push_back(std::move(row));

            // Increment mixed-radix counter.
            for (uint32_t p = 0; p < N; ++p) {
                if (++digits[p] < M) break;
                digits[p] = 0;
            }
        }
    }
    co_return out;
}

size_t wireMpcFilterIntersectionTripleCost(
    size_t numRows, uint32_t N, uint32_t rowDataBits)
{
    // We encode each row as WireSortElement: key = 64 bits (only bit 0 holds
    // NOT(is_intersection)); payload = 64 (id) + N*rowDataBits + 1 (is_intersection) bits.
    size_t payloadBits = 64 + static_cast<size_t>(N) * rowDataBits + 1;
    return wireMpcBitonicSortTripleCost(numRows, payloadBits);
}

macoro::task<void> wireMpcFilterIntersection(
    std::vector<WireMpcJoinRow>& rows,
    uint32_t N, uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (rows.empty()) co_return;

    // Encode each WireMpcJoinRow → WireSortElement with key bit 0 =
    // NOT(is_intersection). This sorts is_intersection=1 rows to the
    // front in ascending order.
    const size_t payloadBits = 64 + static_cast<size_t>(N) * rowDataBits + 1;
    std::vector<WireSortElement> encoded;
    encoded.reserve(rows.size());
    for (const auto& r : rows) {
        if (r.joinedPayload.size() != static_cast<size_t>(N) * rowDataBits)
            throw std::runtime_error("wireMpcFilterIntersection: joinedPayload size mismatch");
        WireSortElement e;
        e.key.fill(0);
        // NOT(is_intersection) = is_intersection ^ 1 on party 0 only.
        e.key[0] = (partyIdx == 0) ? static_cast<uint8_t>((r.isIntersection ^ 1) & 1)
                                   : static_cast<uint8_t>(r.isIntersection & 1);
        e.payload.reserve(payloadBits);
        for (uint32_t i = 0; i < 64; ++i) e.payload.push_back(r.id[i]);
        for (size_t i = 0; i < r.joinedPayload.size(); ++i) e.payload.push_back(r.joinedPayload[i]);
        e.payload.push_back(r.isIntersection);
        encoded.push_back(std::move(e));
    }

    co_await wireMpcBitonicSort(encoded, triples, tripleIdx, partyIdx, sock);

    // Decode back.
    for (size_t i = 0; i < rows.size(); ++i) {
        WireMpcJoinRow r;
        for (uint32_t b = 0; b < 64; ++b) r.id[b] = encoded[i].payload[b];
        r.joinedPayload.assign(
            encoded[i].payload.begin() + 64,
            encoded[i].payload.begin() + 64 + static_cast<size_t>(N) * rowDataBits);
        r.isIntersection = encoded[i].payload[64 + static_cast<size_t>(N) * rowDataBits];
        rows[i] = std::move(r);
    }
}

} // namespace mpstar
} // namespace volePSI
