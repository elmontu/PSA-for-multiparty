#include "RsMpsiVole.h"

#include <stdexcept>

// HEAVY TODO: include the UPSTREAM Visa-Research/volepsi 2-party VOLE-PSI
// header here. Note the name collision: this codebase's local volePSI/RsPsi.h
// defines Simple-Hash classes (RsPsi3rdP*); the upstream volePSI/RsPsi.h
// defines VOLE-PSI classes (RsPsiSender, RsPsiReceiver). Both live in the
// `volePSI` namespace. The build will need either:
//   (a) the upstream classes renamed/moved into a sub-namespace, or
//   (b) the local RsPsi.h renamed (e.g. RsSimpleHashPsi.h) and its classes
//       re-prefixed, freeing the upstream name.
// Without that, both headers cannot coexist on the include path.

namespace volePSI {

macoro::task<std::vector<uint8_t>> RsMpsiVoleSender::runIntersection(
    oc::span<oc::block> inputs,
    coproto::Socket& spChl,
    uint32_t selfIdx,
    uint32_t senderCount)
{
    // 1) Instantiate upstream VOLE-PSI 2-party sender against SP.
    //    Expected API (verify against the upstream header pulled at build time):
    //      upstreamVolePSI::RsPsiSender sender;
    //      sender.init(senderSize, recverSize, statSecParam, seed, malicious, numThreads);
    //      co_await sender.run(inputs, spChl);
    //    The sender does NOT learn the intersection; only SP (receiver) does.

    // 2) Receive cardinality + per-sender bitvector from SP.
    //      co_await spChl.recv(mCardinality);
    //      std::vector<uint8_t> bitvec;
    //      co_await spChl.recv(bitvec);
    //      co_return bitvec;

    (void)inputs; (void)spChl; (void)selfIdx; (void)senderCount;
    throw std::runtime_error("RsMpsiVoleSender: upstream volePSI::RsPsi API not yet wired");
    co_return std::vector<uint8_t>{};
}

macoro::task<size_t> RsMpsiVoleReceiver::runIntersection(
    std::vector<coproto::Socket>& senderSocks,
    uint32_t senderCount,
    const std::vector<size_t>& perSenderSetSize)
{
    // 1) Run N upstream 2-party VOLE-PSI receivers, one per sender.
    //    Expected API:
    //      std::vector<upstreamVolePSI::RsPsiReceiver> recvs(senderCount);
    //      for i: recvs[i].init(perSenderSetSize[i], <virtual set size>, ssp, seed, false, threads);
    //      for i (in parallel): co_await recvs[i].run(<our virtual set>, senderSocks[i]);
    //
    //    Open question: SP doesn't hold inputs; what's the "virtual set"? Two
    //    candidates:
    //      (a) SP uses an empty/dummy set and only collects each sender's OPRF
    //          outputs, then intersects across senders. Requires upstream API
    //          to expose the OPRF output per sender input.
    //      (b) SP uses sender 0's set as the reference, runs pairwise PSI with
    //          senders 1..N-1, cascades intersections. Leaks intersection set
    //          to SP, which is the same trust assumption as today.

    // 2) Compute N-way intersection set H_inter from the pairwise outputs.
    //    Cascade: H = R_0; for i in 1..N-1: H = H intersect R_i (where R_i is
    //    sender i's PSI output from step 1).

    // 3) Build per-sender bitvectors mapping each sender's input rows to
    //    "in H_inter or not". Requires SP to know the (sender_i_input_index ->
    //    OPRF_output) mapping; if upstream API doesn't expose this, add an
    //    extra round where each sender ships the mapping.

    // 4) Send cardinality + bitvecs back to each sender on senderSocks[i].

    (void)senderSocks; (void)senderCount; (void)perSenderSetSize;
    throw std::runtime_error("RsMpsiVoleReceiver: upstream volePSI::RsPsi API not yet wired");
    co_return size_t{0};
}

} // namespace volePSI
