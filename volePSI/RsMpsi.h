#pragma once

#include "RsPsi.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace volePSI {

class RsMpsi3rdPSender : public details::RsPsiBase, public oc::TimerAdapter {
public:
    oc::AES mAEShash;

    void initSpH_prng() {
        block seed = oc::sysRandomSeed();
        mSpH_prng.SetSeed(seed);
    }

    // Receive AES key from SP, hash own inputs, send hashes to SP, receive
    // per-sender intersection bitvector. Returns the bitvector (1 byte per input).
    macoro::task<std::vector<uint8_t>> runIntersection(
        oc::span<oc::block> inputs,
        coproto::Socket& spChl,
        uint32_t selfIdx,
        uint32_t senderCount);

    size_t getCardinality() const { return mCardinality; }

private:
    oc::PRNG mSpH_prng;
    size_t mCardinality = 0;
};

class RsMpsi3rdPReceiver : public details::RsPsiBase, public oc::TimerAdapter {
public:
    // SP role: pick AES key, broadcast, receive N hashed sets, compute
    // count-N intersection, send per-sender bitvectors back. Returns cardinality.
    macoro::task<size_t> runIntersection(
        std::vector<coproto::Socket>& senderSocks,
        uint32_t senderCount,
        const std::vector<size_t>& perSenderSetSize);

    size_t getCardinality() const { return mCardinality; }
    const std::vector<std::vector<uint8_t>>& getPerSenderBitvectors() const { return mPerSenderBitvecs; }

private:
    size_t mCardinality = 0;
    std::vector<std::vector<uint8_t>> mPerSenderBitvecs;
};

} // namespace volePSI
