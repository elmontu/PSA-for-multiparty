#pragma once

#include <iostream>
#include <volePSI/upstream/volepsi/config.h>
#include <volePSI/upstream/volepsi/Paxos.h>

#include "../offlineGen/BeaverTriplesGen.h"
#include "../shuffle/ShareCorrelationGen.h"
#include "../shuffle/MShuffle.h"
#include "PMT.h"
// using namespace oc;


std::vector<block> MPSUParty(u32 idx, u32 numParties, u32 numElements, std::vector<block> &set, u32 numThreads);
