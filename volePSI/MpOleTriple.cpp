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

namespace {

// Shared implementation for semi-honest + malicious variants; parameter
// picks the SilentSecType.
macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriplesImpl(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock,
    osuCrypto::SilentSecType secType)
{
    if (partyIdx > 1)
        throw std::runtime_error("oleGenerateTriples: partyIdx must be 0 or 1");

    const size_t minTriples = 256;
    const size_t mN = std::max<size_t>(count, minTriples);
    const size_t blocks = (mN + 127) / 128;

    osuCrypto::SilentOtTriple triple;
    triple.init(partyIdx, mN, secType, osuCrypto::SilentOtTriple::Type::Triple);
    co_await triple.genBaseOts(prng, sock);

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

} // namespace

macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriples(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock)
{
    co_return co_await oleGenerateTriplesImpl(
        partyIdx, count, prng, sock,
        osuCrypto::SilentSecType::SemiHonest);
}

macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriplesMalicious(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock)
{
    co_return co_await oleGenerateTriplesImpl(
        partyIdx, count, prng, sock,
        osuCrypto::SilentSecType::Malicious);
}

macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriplesNParty(
    uint64_t partyIdx,
    uint32_t N,
    size_t count,
    oc::PRNG& prng,
    std::vector<coproto::Socket>& sockets)
{
    if (N < 2)
        throw std::runtime_error("oleGenerateTriplesNParty: N must be >= 2");
    if (partyIdx >= N)
        throw std::runtime_error("oleGenerateTriplesNParty: partyIdx OOB");
    if (sockets.size() != N)
        throw std::runtime_error("oleGenerateTriplesNParty: sockets size != N");

    // Pairwise pattern (hub-and-spoke variant): party 0 is the hub and
    // runs an OLE with every other party. Non-hub parties only OLE with
    // party 0. Their per-triple shares get combined at party 0.
    //
    // Each pair produces N=2 triples (my share + peer share). We need to
    // OUTPUT N-party BeaverTripleBits where the shares.size() == N.
    //
    // Simplest folding for the hub (party 0):
    //   Sum triple shares from each pair (0, k). The invariant
    //     (u_0 XOR ... XOR u_{N-1}) AND (v_0 XOR ... XOR v_{N-1}) == (w_0 XOR ...)
    //   is NOT preserved by pairwise triples directly (cross terms) —
    //   this MVP N-party generation is APPROXIMATE and used only for
    //   protocol-scaffolding tests. A true N-party OLE needs a native
    //   silent OT extension for N-way; documented as R37/N-native.
    //
    // For 2-party (N==2) we fall through to the plain oleGenerateTriples
    // for correctness.
    if (N == 2) {
        // Non-hub / hub distinction reduces to partyIdx.
        uint64_t peer = 1 - partyIdx;
        auto triples = co_await oleGenerateTriples(partyIdx, count, prng, sockets[peer]);
        co_return triples;
    }

    // N > 2 is NOT supported in production. Prior scaffolding code XORed
    // pairwise triple shares without accounting for cross-terms in
    //   (⨁ Uᵢ) · (⨁ Vⱼ) = ⨁ Uᵢ · Vⱼ  (i ≠ j terms missing)
    // which produces invalid Beaver triples. MPSVS is fixed at N=2 (S1, S2)
    // by design (see Rev 7 §2 topology). Any caller reaching this branch
    // has misconfigured the deployment.
    throw std::runtime_error(
        "oleGenerateTriplesNParty: N > 2 not supported — MPSVS Rev 7 fixes "
        "the compute topology at N=2 (S1, S2). A native N-party OLE requires "
        "a different silent-OT extension and is out of scope for this build.");
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
