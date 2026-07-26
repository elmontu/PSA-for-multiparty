#pragma once

#include <iostream>
#include <volePSI/upstream/volepsi/config.h>
#include <volePSI/upstream/volepsi/Paxos.h>
#include "../offlineGen/BeaverTriplesGen.h"
#include "../shuffle/ShareCorrelationGen.h"
#include "../shuffle/MShuffle.h"
#include "PMT.h"

using namespace oc;

// [LOCAL PATCH — OIRA] optional `values` parameter, one u64 per element in
// `set`, aligned by index. If provided, non-P_0 senders contribute
// (values[i]) instead of the upstream default (set[i].mData[0]). P_0 does
// not contribute a value (it's the receiver of the sum). See docs/
// OIRA_CONSTRUCTION.md for rationale. Default nullptr reproduces original
// value=key behavior for backward compat with the test_mpsics probe.
u64 MPSICardSumParty(u32 idx, u32 numParties, u32 numElements,
                     std::vector<block> &set,
                     u32 numThreads,
                     const std::vector<u64>* values = nullptr);