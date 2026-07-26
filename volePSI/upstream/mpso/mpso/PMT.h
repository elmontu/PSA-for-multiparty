#pragma once

#include <volePSI/upstream/volepsi/GMW/Gmw.h>
#include <volePSI/upstream/volepsi/config.h>
#include <volePSI/upstream/volepsi/SimpleIndex.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/BitVector.h>

#include <libOTe/Vole/Silent/SilentVoleReceiver.h>
#include <libOTe/Vole/Silent/SilentVoleSender.h>

#include "ROT.h"

#include <string> 
#include <fstream>



// use for MPSU
void pmtOTSend(u32 numParties, u32 numElements, block cuckooSeed, std::vector<std::vector<block>> &simHashTable, Socket& chl, std::vector<block> &ssrotOut, std::string postfixPath, u32 numThreads = 1);
void pmtOTRecv(u32 numParties, u32 numElements, block cuckooSeed, std::vector<block> &cuckooHashTable, Socket &chl, std::vector<block> &ssrotOut, std::string postfixPath, u32 numThreads = 1);


// use for MPSI/MSPIC and part of MPSICS
void opprfSendPSI64(u32 numParties, u32 numElements, block cuckooSeed, std::vector<std::vector<block>> &simHashTable, Socket& chl, std::vector<u64> &opprfOut, std::string opprfPath, u32 numThreads = 1);
void opprfRecvPSI64(u32 numParties, u32 numElements, block cuckooSeed, std::vector<block> &cuckooHashTable, Socket &chl, std::vector<u64> &opprfOut, std::string opprfPath, u32 numThreads = 1);


// for part of MPSICS.
// [LOCAL PATCH — OIRA]: added optional simHashValues param. When non-null,
// the per-slot value fed into the OKVS is (*simHashValues)[i][p] rather than
// simHashTable[i][p].mData[1]. This lets callers separate the intersection
// key (block, hashed for OPRF matching) from the summed value (u64,
// arbitrary). Backward compatible: default nullptr reproduces the original
// value=key behavior used by the upstream test_mpsics probe.
void opprfSendPSICS64(u32 numParties, u32 numElements, block cuckooSeed,
                      std::vector<std::vector<block>> &simHashTable,
                      Socket& chl, std::vector<u64> &opprfOut,
                      std::string volePath, u32 numThreads = 1,
                      const std::vector<std::vector<u64>>* simHashValues = nullptr);
void opprfRecvPSICS64(u32 numParties, u32 numElements, block cuckooSeed, std::vector<block> &cuckooHashTable, Socket &chl, std::vector<u64> &opprfOut, std::string volePath, u32 numThreads = 1);




