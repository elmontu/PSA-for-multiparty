#include "MpMpcSort.h"
#include "MpObliviousSort.h"   // for bitonicCompareSwapCount and helpers

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Like obliviousBitonicSort's iterative helper, but each compareAndSwap
// is an MPC compare + MPC conditional swap.
void mpcCompareAndSwap(SharedSortElement& a,
                       SharedSortElement& b,
                       bool ascending,
                       const std::vector<BeaverTripleBit>& triples,
                       size_t& tripleIndex)
{
    // ascending == true → swap iff a.key > b.key, i.e., secureLessThan(b, a) = 1
    // ascending == false → swap iff a.key < b.key, i.e., secureLessThan(a, b) = 1
    SharedBit selector = ascending
        ? secureLessThan(b.key, a.key, triples, tripleIndex)
        : secureLessThan(a.key, b.key, triples, tripleIndex);
    conditionalSwap(a, b, selector, triples, tripleIndex);
}

void mpcBitonicMerge(std::vector<SharedSortElement>& xs,
                     size_t low, size_t cnt,
                     bool ascending,
                     const std::vector<BeaverTripleBit>& triples,
                     size_t& tripleIndex)
{
    if (cnt <= 1) return;
    size_t k = cnt / 2;
    for (size_t i = low; i < low + k; ++i) {
        mpcCompareAndSwap(xs[i], xs[i + k], ascending, triples, tripleIndex);
    }
    mpcBitonicMerge(xs, low,     k, ascending, triples, tripleIndex);
    mpcBitonicMerge(xs, low + k, k, ascending, triples, tripleIndex);
}

void mpcBitonicSortHelper(std::vector<SharedSortElement>& xs,
                          size_t low, size_t cnt,
                          bool ascending,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex)
{
    if (cnt <= 1) return;
    size_t k = cnt / 2;
    mpcBitonicSortHelper(xs, low,     k, true,  triples, tripleIndex);
    mpcBitonicSortHelper(xs, low + k, k, false, triples, tripleIndex);
    mpcBitonicMerge(xs, low, cnt, ascending, triples, tripleIndex);
}

uint64_t nextPow2(uint64_t n) {
    if (n <= 1) return 1;
    uint64_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

} // namespace

size_t conditionalSwapTripleCost(size_t payloadBits)
{
    return 64 + payloadBits;
}

void conditionalSwap(SharedSortElement& a,
                     SharedSortElement& b,
                     const SharedBit& selector,
                     const std::vector<BeaverTripleBit>& triples,
                     size_t& tripleIndex)
{
    if (a.payload.size() != b.payload.size())
        throw std::runtime_error("conditionalSwap: payload size mismatch");
    if (a.key.N() != b.key.N() || a.key.N() != selector.N())
        throw std::runtime_error("conditionalSwap: N mismatch");

    // For each bit position: one secureAnd to compute maskedDiff =
    // selector AND (a XOR b), then two XORs to apply it to both sides.
    // When selector=0: maskedDiff=0, no change. When selector=1:
    // maskedDiff=diff, so new_a = a XOR diff = b and new_b = b XOR diff = a.

    auto swapOneBit = [&](SharedBit& aBit, SharedBit& bBit) {
        SharedBit diff = xorShared(aBit, bBit);
        if (tripleIndex >= triples.size())
            throw std::runtime_error("conditionalSwap: triple bag exhausted");
        SharedBit maskedDiff = secureAnd(selector, diff, triples[tripleIndex++]);
        SharedBit newA = xorShared(aBit, maskedDiff);
        SharedBit newB = xorShared(bBit, maskedDiff);
        aBit = newA;
        bBit = newB;
    };

    for (uint32_t i = 0; i < 64; ++i) {
        swapOneBit(a.key.bits[i], b.key.bits[i]);
    }
    for (size_t i = 0; i < a.payload.size(); ++i) {
        swapOneBit(a.payload[i], b.payload[i]);
    }
}

size_t mpcBitonicSortTripleCost(size_t n, size_t payloadBits)
{
    if (n <= 1) return 0;
    size_t padded = nextPow2(n);
    uint64_t swaps = bitonicCompareSwapCount(padded);
    size_t perSwap = secureLessThanTripleCost()
                   + conditionalSwapTripleCost(payloadBits);
    return swaps * perSwap;
}

void mpcBitonicSort(std::vector<SharedSortElement>& xs,
                    const std::vector<BeaverTripleBit>& triples,
                    size_t& tripleIndex)
{
    const size_t n = xs.size();
    if (n <= 1) return;
    const size_t padded = nextPow2(n);

    // Pad with sentinel ∞-keyed elements (all bits = 1 → max uint64).
    // Sentinels have empty/zero payload of the same length as real
    // elements.
    if (padded > n) {
        size_t payloadLen = xs[0].payload.size();
        uint32_t N = xs[0].key.N();
        SharedSortElement sentinel;
        sentinel.key.bits.resize(64);
        for (uint32_t i = 0; i < 64; ++i) {
            sentinel.key.bits[i] = SharedBit(N);
            sentinel.key.bits[i].shares[0] = 1;  // bit value = 1 (XOR-shared)
        }
        sentinel.payload.resize(payloadLen);
        for (size_t i = 0; i < payloadLen; ++i) sentinel.payload[i] = SharedBit(N);
        xs.reserve(padded);
        for (size_t i = n; i < padded; ++i) xs.push_back(sentinel);
    }

    mpcBitonicSortHelper(xs, 0, padded, true, triples, tripleIndex);

    // Strip sentinels (they sorted to the tail).
    xs.resize(n);
}

} // namespace mpstar
} // namespace volePSI
