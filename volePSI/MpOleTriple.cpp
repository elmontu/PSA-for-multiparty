#include "MpOleTriple.h"

#include "libOTe/Triple/SilentOtTriple/SilentOtTriple.h"
#include "cryptoTools/Common/Defines.h"

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Pack libOTe's per-block triple output into BeaverTripleBit array.
// Each block carries 128 bit triples. block i bit j of A holds the
// party's share of triple (i*128 + j).u.
void unpackBlocksToTriples(
    uint64_t partyIdx,
    const std::vector<oc::block>& A,
    const std::vector<oc::block>& B,
    const std::vector<oc::block>& C,
    size_t count,
    std::vector<BeaverTripleBit>& outTriples)
{
    if (A.size() != B.size() || A.size() != C.size())
        throw std::runtime_error("unpackBlocksToTriples: A/B/C size mismatch");
    const size_t cap = A.size() * 128;
    if (count > cap)
        throw std::runtime_error(
            "unpackBlocksToTriples: count " + std::to_string(count)
            + " exceeds block capacity " + std::to_string(cap));

    // We need: outTriples[i].u.shares[partyIdx] = bit i of A[i/128]
    //         outTriples[i].v.shares[partyIdx] = bit i of B[i/128]
    //         outTriples[i].w.shares[partyIdx] = bit i of C[i/128]
    // The OTHER party's share comes from THEIR run of expand() and is
    // merged on their side; the structure is set up to have N=2 shares
    // total per triple.
    outTriples.resize(count);
    for (size_t i = 0; i < count; ++i) {
        size_t blkIdx = i / 128;
        size_t bitIdx = i % 128;
        const auto* aBytes = reinterpret_cast<const uint8_t*>(&A[blkIdx]);
        const auto* bBytes = reinterpret_cast<const uint8_t*>(&B[blkIdx]);
        const auto* cBytes = reinterpret_cast<const uint8_t*>(&C[blkIdx]);
        uint8_t ab = (aBytes[bitIdx / 8] >> (bitIdx % 8)) & 1;
        uint8_t bb = (bBytes[bitIdx / 8] >> (bitIdx % 8)) & 1;
        uint8_t cb = (cBytes[bitIdx / 8] >> (bitIdx % 8)) & 1;

        // Each SharedBit has N=2 shares; we fill in OUR share at
        // partyIdx; the OTHER party fills in theirs.
        outTriples[i].u = SharedBit(/*N=*/2);
        outTriples[i].v = SharedBit(/*N=*/2);
        outTriples[i].w = SharedBit(/*N=*/2);
        outTriples[i].u.shares[partyIdx] = ab;
        outTriples[i].v.shares[partyIdx] = bb;
        outTriples[i].w.shares[partyIdx] = cb;
    }
}

} // namespace

macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriples(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock)
{
    if (partyIdx > 1)
        throw std::runtime_error("oleGenerateTriples: partyIdx must be 0 or 1");

    // SilentOtTriple sizing matches the libOTe internal test
    // (SilentOT_Tests.cpp::SilentOtTriple_triple_test): mN = number of
    // triples directly, with A/B/C span size = divCeil(mN, 128). Each
    // block carries 128 triples bit-by-bit.
    //
    // libOTe has a MINIMUM-SIZE constraint internally (the silent OT
    // setup needs at least a few hundred OTs to function); for tiny
    // counts we round up.
    const size_t minTriples = 256;   // empirical minimum from libOTe tests
    const size_t mN = std::max<size_t>(count, minTriples);
    const size_t blocks = (mN + 127) / 128;

    osuCrypto::SilentOtTriple triple;
    triple.init(partyIdx, mN,
                osuCrypto::SilentSecType::SemiHonest,
                osuCrypto::SilentOtTriple::Type::Triple);

    // Generate base OTs over the same socket. This is a separate
    // sub-protocol within libOTe.
    co_await triple.genBaseOts(prng, sock);

    // Allocate the per-party share buffers and run expand().
    std::vector<oc::block> A(blocks), B(blocks), C(blocks);
    co_await triple.expand(
        osuCrypto::span<oc::block>(A.data(), A.size()),
        osuCrypto::span<oc::block>(B.data(), B.size()),
        osuCrypto::span<oc::block>(C.data(), C.size()),
        prng, sock);

    std::vector<BeaverTripleBit> out;
    unpackBlocksToTriples(partyIdx, A, B, C, count, out);
    co_return out;
}

bool verifyBeaverTripleBatch(const std::vector<BeaverTripleBit>& triples)
{
    for (size_t i = 0; i < triples.size(); ++i) {
        uint8_t u = triples[i].u.reconstruct();
        uint8_t v = triples[i].v.reconstruct();
        uint8_t w = triples[i].w.reconstruct();
        if (((u & v) & 1) != (w & 1)) return false;
    }
    return true;
}

} // namespace mpstar
} // namespace volePSI
