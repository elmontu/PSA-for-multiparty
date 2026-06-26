#include "RsMpsi.h"

#include <unordered_map>
#include <unordered_set>
#include <stdexcept>

namespace volePSI {

namespace {

// Matches the NoHash pattern in RsPsi.cpp.
struct NoHash {
    size_t operator()(const block& v) const { return v.get<size_t>(0); }
};

} // anonymous namespace

// ----------------------------------------------------------------------------
// RsMpsi3rdPSender
// ----------------------------------------------------------------------------

macoro::task<std::vector<uint8_t>>
RsMpsi3rdPSender::runIntersection(
    oc::span<block> inputs,
    coproto::Socket& spChl,
    uint32_t selfIdx,
    uint32_t /*senderCount*/)
{
    setTimePoint("SENDER : intersection begin");

    block aesKey;
    co_await spChl.recv(aesKey);

    mAEShash.setKey(aesKey);
    std::vector<block> hashed(inputs.size());
    mAEShash.hashBlocks(inputs, oc::span<block>(hashed));

    co_await spChl.send(oc::span<block>(hashed));

    setTimePoint("SENDER : hashes sent");

    co_await spChl.recv(mCardinality);

    std::vector<uint8_t> bitvec(inputs.size());
    co_await spChl.recv(bitvec);

    setTimePoint("SENDER : intersection bitvec recv");
    co_return bitvec;
}

// ----------------------------------------------------------------------------
// RsMpsi3rdPReceiver (SP)
// ----------------------------------------------------------------------------

macoro::task<size_t>
RsMpsi3rdPReceiver::runIntersection(
    std::vector<coproto::Socket>& senderSocks,
    uint32_t senderCount,
    const std::vector<size_t>& perSenderSetSize)
{
    if (senderCount == 0
        || senderSocks.size() != senderCount
        || perSenderSetSize.size() != senderCount)
    {
        throw std::runtime_error("RsMpsi3rdPReceiver: parameter size mismatch");
    }

    setTimePoint("SP : intersection begin");

    // Pick AES key, broadcast.
    block aesKey = oc::sysRandomSeed();
    for (uint32_t i = 0; i < senderCount; ++i) {
        co_await senderSocks[i].send(aesKey);
    }

    // Recv each sender's hashed set (raw block stream, length pre-agreed).
    std::vector<std::vector<block>> allHashes(senderCount);
    for (uint32_t i = 0; i < senderCount; ++i) {
        allHashes[i].resize(perSenderSetSize[i]);
        co_await senderSocks[i].recv(oc::span<block>(allHashes[i]));
    }

    setTimePoint("SP : hashes received");

    // Count occurrences.
    std::unordered_map<block, uint32_t, NoHash> counts;
    for (uint32_t i = 0; i < senderCount; ++i) {
        for (const auto& h : allHashes[i]) {
            counts[h]++;
        }
    }

    // Intersection = hashes seen by all N.
    std::unordered_set<block, NoHash> intersectSet;
    for (const auto& [h, cnt] : counts) {
        if (cnt == senderCount) {
            intersectSet.insert(h);
        }
    }
    mCardinality = intersectSet.size();

    // Build per-sender bitvectors.
    mPerSenderBitvecs.assign(senderCount, {});
    for (uint32_t i = 0; i < senderCount; ++i) {
        auto& bv = mPerSenderBitvecs[i];
        bv.assign(perSenderSetSize[i], 0);
        for (size_t j = 0; j < perSenderSetSize[i]; ++j) {
            if (intersectSet.count(allHashes[i][j])) {
                bv[j] = 1;
            }
        }
    }

    // Ship cardinality + bitvec back to each sender.
    for (uint32_t i = 0; i < senderCount; ++i) {
        co_await senderSocks[i].send(mCardinality);
        co_await senderSocks[i].send(mPerSenderBitvecs[i]);
    }

    setTimePoint("SP : bitvecs sent");
    co_return mCardinality;
}

} // namespace volePSI
