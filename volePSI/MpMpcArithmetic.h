#pragma once

// Secure 64-bit addition and subtraction on XOR-shared bit representations.
// Foundations for the SP-blind vulnerability-score protocol (see
// docs/HISTORY.md).
//
// The MPC arithmetic surface prior to this file: additive shares
// (`SharedU64`) have free add/sub but no compare, and bit-shares
// (`SharedU64Bin`) have compare/equal but no arithmetic. This module fills
// the second gap. The design deliberately uses the same `SharedU64Bin`
// carrier as `MpSecureCompare` so that secure division (session 2) can
// chain `secureLessThan` + `secureSubU64Bin` in a single share domain
// without arithmetic<->binary conversions.
//
// Cost model (per call, in Beaver bit-triples):
//   secureAddU64Bin: 127 triples  (1 for bit 0 + 2 * 63 for bits 1..63)
//   secureSubU64Bin: 127 triples  (same as add via two's complement)
//
// Caller pattern matches MpSecureCompare: pre-generate a large triple bag,
// pass span + a cursor `size_t& tripleIndex` that this call bumps.

#include "MpSecureCompare.h"   // SharedU64Bin, SharedBit
#include "MpBeaverTriple.h"    // BeaverTripleBit, secureAnd

#include <cstddef>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

struct AddResult {
    SharedU64Bin sum;
    SharedBit    carryOut;   // 1 iff x + y overflowed 2^64
};

struct SubResult {
    SharedU64Bin diff;
    SharedBit    borrowOut;  // 1 iff x < y (i.e. subtraction wrapped)
};

// Full 64-bit ripple-carry addition on XOR-shared bit vectors.
// Consumes secureAddU64BinTripleCost() bit triples from `triples` starting
// at `tripleIndex`. Returns via bumped index.
AddResult secureAddU64Bin(const SharedU64Bin& x,
                          const SharedU64Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);
size_t secureAddU64BinTripleCost();

// Full 64-bit subtraction via two's complement of y then add. Consumes
// secureSubU64BinTripleCost() bit triples. borrowOut = 1 iff x < y.
SubResult secureSubU64Bin(const SharedU64Bin& x,
                          const SharedU64Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);
size_t secureSubU64BinTripleCost();

struct DivResult {
    SharedU64Bin quotient;
    SharedU64Bin remainder;
    SharedBit    divByZero;   // 1 iff denom == 0; caller must mask output if set
};

// 64-bit unsigned integer division on bit-shared values.
//
//   quotient  = num / denom  (integer division, unsigned)
//   remainder = num % denom
//   divByZero = 1 iff denom == 0. On divByZero, quotient and remainder are
//               computed as if denom == 1 (i.e., quotient=num, remainder=0) —
//               caller MUST mask/discard based on the divByZero bit.
//
// Algorithm: bit-by-bit non-restoring long division. For each bit from MSB
// to LSB: shift remainder left by 1, or-in the next numerator bit, trial-
// subtract denom, use secureSubU64Bin's borrowOut as the multiplexer to
// either accept or reject the subtraction. Quotient bit = NOT borrowOut.
//
// Consumes secureDivideU64BinTripleCost() Beaver bit triples.
DivResult secureDivideU64Bin(const SharedU64Bin& num,
                             const SharedU64Bin& denom,
                             const std::vector<BeaverTripleBit>& triples,
                             size_t& tripleIndex);
size_t secureDivideU64BinTripleCost();

} // namespace mpstar
} // namespace volePSI
