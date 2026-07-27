#pragma once

#include "RsSimpleHashPsi.h"
#include "coproto/coproto.h"
#include "macoro/task.h"
#include <vector>
#include <cstdint>

namespace volePSI {

// Drop-in replacement surface for RsMpsi3rdP* using a real 2-party VOLE-PSI
// (upstream Visa-Research/volepsi RsPsi) as the underlying primitive instead
// of AES-Simple-Hash. KMPRT (CCS'17) style: N parallel 2-party PSIs with SP
// as the common party.
//
// Status: SCAFFOLD ONLY. Bodies throw at runtime until upstream API is wired.
// See docs/SECURITY.md for the integration checklist.

class RsMpsiVoleSender : public details::RsSimpleHashPsiBase, public oc::TimerAdapter {
public:
    macoro::task<std::vector<uint8_t>> runIntersection(
        oc::span<oc::block> inputs,
        coproto::Socket& spChl,
        uint32_t selfIdx,
        uint32_t senderCount);

    size_t getCardinality() const { return mCardinality; }

private:
    size_t mCardinality = 0;
};

class RsMpsiVoleReceiver : public details::RsSimpleHashPsiBase, public oc::TimerAdapter {
public:
    macoro::task<size_t> runIntersection(
        std::vector<coproto::Socket>& senderSocks,
        uint32_t senderCount,
        const std::vector<size_t>& perSenderSetSize);

    size_t getCardinality() const { return mCardinality; }

    // C3 fix (Stage B): this vector is INTENTIONALLY empty for the vole
    // backend. SP does not receive per-sender positional bitvecs — each
    // sender computes its own bitvec locally via OPRF and never ships it
    // back. The accessor is retained only for API symmetry with the
    // legacy simplehash backend (RsMpsi3rdPReceiver). Callers must NOT
    // rely on per-sender bitvec being available via the vole backend.
    const std::vector<std::vector<uint8_t>>& getPerSenderBitvectors() const {
        return mPerSenderBitvecs;
    }

private:
    size_t mCardinality = 0;
    std::vector<std::vector<uint8_t>> mPerSenderBitvecs;  // stays empty; see comment
};

} // namespace volePSI
