#include "RsMpsiVole.h"

#include "volePSI/upstream/volepsi/RsPsi.h"
#include "cryptoTools/Common/Defines.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_set>

// Stage B phase 3: MPSI via cascade of upstream ladnir/volepsi 2PC VOLE-PSI
// (Rindal-Schoppmann EUROCRYPT 2021). Local Simple-Hash classes were renamed
// to volePSI::RsSimpleHashPsi3rdP* in phase 1, freeing the `volePSI::RsPsi*`
// names for the vendored upstream copy under volePSI/upstream/volepsi/.
//
// PROTOCOL (this file):
//   Setup: SP fixes an integer statSecParam = 40. Every 2PC PSI call uses
//     RsPsiBase::init(senderSize, recverSize, ssp=40, seed, malicious=false,
//                     numThreads=1). No malicious security yet -- the
//     ASIACRYPT'24 (eprint 2024/1989) attack against stock OKVS applies in
//     the malicious model; a follow-on will swap to the corrected construction.
//
//   Step 1 (cascade seed): Sender 0 sends its raw set to SP under the
//     existing spKey AEAD wrapper of the outer MpsaDriver. That leak is the
//     price of the cascade approach; senders 1..N-1 remain OPRF-protected.
//     (Alternative: use MPSO's MPSICardParty for cardinality-only with no
//     per-sender leak. Documented in volePSI/upstream/README.md.)
//
//   Step 2 (cascade intersection): For i in 1..N-1:
//     SP is RsPsiReceiver holding current candidate set; sender i is
//     RsPsiSender. After run(), RsPsiReceiver::mIntersection holds indices
//     into SP's input where sender_i's set matched. SP compresses its
//     candidate set to those matched items.
//
//   Step 3 (per-sender bitvec): For each sender i (including 0):
//     SP is RsPsiSender of the FINAL intersection set; sender i is
//     RsPsiReceiver of ITS OWN set. Sender i's mIntersection is a list of
//     ITS input indices that are in the intersection. Sender i sends the
//     bitvec back to SP (SP already knows for sender 0 trivially; the round-
//     trip keeps the wire protocol uniform).
//
// THREAT MODEL:
//   - Sender 0's raw set leaks to SP by construction (design trade-off).
//   - Senders 1..N-1: SP learns only the intersection cardinality and which
//     of the CANDIDATE items each sender contributes (which reveals nothing
//     beyond intersection membership itself, standard 2PC PSI privacy).
//   - Compared to RsMpsi3rdP (default): SP still learns per-sender positional
//     bitvec (C3), so this stage does NOT close C3. It DOES close the SP
//     dictionary attack (C2) beyond the T15-salt mitigation, because the
//     OPRF fresh-per-session pseudorandomness prevents any cross-session
//     frequency profiling on senders 1..N-1.
//
//   Full C3 closure requires MPSO (2025/640) MPSIC-Sum, which fits the star
//   topology poorly today -- vendored but not wired; see
//   volePSI/upstream/README.md for the remaining redesign.

namespace volePSI {

namespace {

// AEAD-length-prefixed helpers for shipping a std::vector<block> or bitvec
// over spChl. We already trust spChl (authenticated + AEAD-wrapped by the
// outer MpsaDriver session handshake), so no extra sealing here.
constexpr uint32_t kStatSecParam = 40;

// Cap on any received count field to prevent OOM from a malicious length
// prefix. 100M items x 16 B = 1.6 GB max; adjust if needed.
constexpr uint64_t kMaxCountField = 100'000'000;

macoro::task<> sendBlockVec(coproto::Socket& chl, const std::vector<oc::block>& v) {
    uint64_t n = v.size();
    co_await chl.send(n);
    if (n > 0) {
        co_await chl.send(oc::span<const oc::block>(v.data(), n));
    }
}

macoro::task<std::vector<oc::block>> recvBlockVec(coproto::Socket& chl) {
    uint64_t n = 0;
    co_await chl.recv(n);
    if (n > kMaxCountField) {
        throw std::runtime_error("RsMpsiVole: recv block count exceeds cap ("
            + std::to_string(n) + " > " + std::to_string(kMaxCountField) + ")");
    }
    std::vector<oc::block> out(n);
    if (n > 0) {
        co_await chl.recv(oc::span<oc::block>(out.data(), n));
    }
    co_return out;
}

// Run one 2PC RsPsi with the SP acting as RECEIVER (learns mIntersection).
// SP-input is `spSet`. Returns the indices into spSet where sender's items matched.
macoro::task<std::vector<oc::u64>> runPsiSpReceiver(
    std::vector<oc::block>& spSet,
    uint64_t senderSize,
    coproto::Socket& chl)
{
    RsPsiReceiver r;
    r.init(senderSize, spSet.size(), kStatSecParam, oc::sysRandomSeed(),
           /*malicious=*/false, /*numThreads=*/1);
    co_await r.run(oc::span<oc::block>(spSet.data(), spSet.size()), chl);
    co_return std::move(r.mIntersection);
}

// Run one 2PC RsPsi with the SP acting as SENDER of `spSet`.
macoro::task<> runPsiSpSender(
    std::vector<oc::block>& spSet,
    uint64_t receiverSize,
    coproto::Socket& chl)
{
    RsPsiSender s;
    s.init(spSet.size(), receiverSize, kStatSecParam, oc::sysRandomSeed(),
           /*malicious=*/false, /*numThreads=*/1);
    co_await s.run(oc::span<oc::block>(spSet.data(), spSet.size()), chl);
}

} // anonymous namespace

// ----------------------------------------------------------------------------
// RsMpsiVoleSender (each sender's side)
// ----------------------------------------------------------------------------

macoro::task<std::vector<uint8_t>>
RsMpsiVoleSender::runIntersection(
    oc::span<oc::block> inputs,
    coproto::Socket& spChl,
    uint32_t selfIdx,
    uint32_t /*senderCount*/)
{
    setTimePoint("VOLE SENDER : begin");

    // Working buffer (may be moved into PSI which takes a span).
    std::vector<oc::block> mySet(inputs.begin(), inputs.end());

    if (selfIdx == 0) {
        // Cascade seed: ship raw set to SP. Documented leak.
        co_await sendBlockVec(spChl, mySet);
        setTimePoint("VOLE SENDER 0 : raw set sent");
    } else {
        // Step 2 cascade: act as 2PC RsPsiSender against SP's current candidate.
        RsPsiSender s;
        // Receiver-size hint: SP told us what the current candidate size is
        // beforehand (see Receiver step 2). We fetch it here.
        uint64_t recverSize = 0;
        co_await spChl.recv(recverSize);
        if (recverSize > kMaxCountField) {
            throw std::runtime_error("RsMpsiVoleSender: bogus recverSize");
        }
        s.init(mySet.size(), recverSize, kStatSecParam, oc::sysRandomSeed(),
               /*malicious=*/false, /*numThreads=*/1);
        co_await s.run(oc::span<oc::block>(mySet.data(), mySet.size()), spChl);
        setTimePoint("VOLE SENDER k : cascade PSI done");
    }

    // Step 3: bitvec pass. SP is 2PC sender of the final intersection;
    // we're the receiver of our OWN set.
    uint64_t intersectSize = 0;
    co_await spChl.recv(intersectSize);
    if (intersectSize > kMaxCountField) {
        throw std::runtime_error("RsMpsiVoleSender: bogus intersectSize");
    }
    RsPsiReceiver r;
    r.init(intersectSize, mySet.size(), kStatSecParam, oc::sysRandomSeed(),
           /*malicious=*/false, /*numThreads=*/1);
    co_await r.run(oc::span<oc::block>(mySet.data(), mySet.size()), spChl);
    setTimePoint("VOLE SENDER : bitvec PSI done");

    // Build bitvec from mIntersection indices. This bitvec stays LOCAL to
    // this sender -- it is returned to the caller (MpsaDriver) which uses it
    // to build c_i, but is NEVER shipped to SP. That is the entire C3 fix:
    // SP learns only cardinality via the cascade, not per-sender positional
    // membership.
    std::vector<uint8_t> bitvec(mySet.size(), 0);
    for (auto idx : r.mIntersection) {
        if (idx < mySet.size()) bitvec[idx] = 1;
    }

    // Cache the cardinality so callers can query it via getCardinality().
    mCardinality = intersectSize;

    setTimePoint("VOLE SENDER : done");
    co_return bitvec;
}

// ----------------------------------------------------------------------------
// RsMpsiVoleReceiver (SP side)
// ----------------------------------------------------------------------------

macoro::task<size_t>
RsMpsiVoleReceiver::runIntersection(
    std::vector<coproto::Socket>& senderSocks,
    uint32_t senderCount,
    const std::vector<size_t>& perSenderSetSize)
{
    if (senderCount == 0
        || senderSocks.size() != senderCount
        || perSenderSetSize.size() != senderCount)
    {
        throw std::runtime_error("RsMpsiVoleReceiver: parameter size mismatch");
    }

    setTimePoint("VOLE SP : begin");

    // Step 1 cascade seed: sender 0 ships raw set.
    std::vector<oc::block> candidate = co_await recvBlockVec(senderSocks[0]);
    setTimePoint("VOLE SP : sender 0 raw set received");

    // Step 2: cascade with senders 1..N-1.
    for (uint32_t i = 1; i < senderCount; ++i) {
        // Tell sender i our current candidate size so it can init RsPsiSender.
        uint64_t candSize = candidate.size();
        co_await senderSocks[i].send(candSize);

        // Run PSI: SP as receiver of `candidate`, sender_i as sender of its own set.
        auto matchIdx = co_await runPsiSpReceiver(
            candidate, perSenderSetSize[i], senderSocks[i]);

        // Compress candidate to just the matched items.
        std::vector<oc::block> next;
        next.reserve(matchIdx.size());
        for (auto idx : matchIdx) {
            if (idx < candidate.size()) next.push_back(candidate[idx]);
        }
        candidate = std::move(next);
        setTimePoint(("VOLE SP : cascade round " + std::to_string(i) + " done").c_str());
    }

    mCardinality = candidate.size();

    // Step 3 (C3 fix): per-sender OPRF pass so each sender can compute its
    // OWN bitvec LOCALLY, without ever revealing per-sender positional
    // membership to SP. SP is 2PC RsPsiSender of the final candidate set;
    // sender i is 2PC RsPsiReceiver of its own set. In VOLE-PSI the SENDER
    // learns nothing from run(), so SP genuinely gains no positional info.
    // The bitvec stays local to sender i.
    //
    // mPerSenderBitvecs is INTENTIONALLY LEFT EMPTY on the SP side -- callers
    // MUST NOT rely on it via getPerSenderBitvectors(). This is the point of
    // Stage B: SP learns only the cardinality, matching the star-topology
    // MPSA threat model.
    //
    // Sequential today; parallelization within a coroutine + N sockets is a
    // follow-on optimization.
    mPerSenderBitvecs.assign(senderCount, {});   // stays empty by design
    for (uint32_t i = 0; i < senderCount; ++i) {
        // Tell sender the intersection cardinality first (so they can init).
        uint64_t iSize = candidate.size();
        co_await senderSocks[i].send(iSize);

        // Run PSI: SP as sender of candidate, sender i as receiver of its own set.
        // SP learns nothing from run() beyond the fact of completion.
        co_await runPsiSpSender(candidate, perSenderSetSize[i], senderSocks[i]);
    }
    setTimePoint("VOLE SP : per-sender OPRF pass done");

    co_return mCardinality;
}

} // namespace volePSI
