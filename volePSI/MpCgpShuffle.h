#pragma once

// In-memory simulation of the 2-party Chase-Ghosh-Poburinnaya
// "Secret-Shared Shuffle" (Asiacrypt 2020), with the preprocessing modeled
// as a trusted-dealer correlation oracle and the online phase implemented
// in full.
//
// Originally R26 (single-block rows, tests/unit/test_cgp_shuffle.cpp).
// Extended R26b/step-1 to WIDE rows so each row carries W blocks of
// payload — the operational case for PSA-with-payload deployments. The
// trusted-dealer preprocessing is unchanged in shape; the wire-protocol
// OT-based preprocessing will plug in here when R26b/step-2 lands.
//
// Reference: Chase, Ghosh, Poburinnaya. "Secret-Shared Shuffle." §4.

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// A "row" of W blocks. Wide payload is W > 1; single-block (identifier-
// only) is W == 1.
using Row = std::vector<oc::block>;

// Vector of n rows, each of width W. Outer index is the row position
// 0..n-1; inner index is the block-within-row 0..W-1.
using RowVec = std::vector<Row>;

// Correlation held by party A (input provider). All inner rows have the
// same width W.
struct CgpCorrelationA {
    RowVec a;       // uniform random mask
    RowVec alpha;   // output share for A (satisfies α = π(a) ⊕ b)
};

// Correlation held by party B (permutation owner).
struct CgpCorrelationB {
    std::vector<int> pi;   // permutation: pi[i] = source row idx mapped to position i
    RowVec b;              // uniform random row vector
};

// One-shot trusted-dealer generation of the CGP preprocessing
// correlation. In the production version this is replaced by an OT-based
// 2-party protocol; the interface returned to each party is identical so
// the rest of the system is unchanged.
//
//   n: number of rows
//   W: blocks per row (payload width). W=1 recovers the single-block case.
void cgpDealerGenerate(uint32_t n, uint32_t W,
                       oc::PRNG& prng,
                       CgpCorrelationA& outA,
                       CgpCorrelationB& outB);

// Party A's online step. Returns the message m that A must send to B.
// y_A = α is the output share A keeps.
//   x_A: A's input share (n rows of width W)
//   corrA: A's preprocessing correlation
//   outMessageToB: m = x_A ⊕ a, sent to B
//   outYa: A's output share (n rows of width W)
void cgpOnlineA(const RowVec& x_A,
                const CgpCorrelationA& corrA,
                RowVec& outMessageToB,
                RowVec& outYa);

// Party B's online step. Consumes A's message m, produces B's output
// share y_B such that y_A ⊕ y_B = π(x_A ⊕ x_B) (row-wise XOR and row-
// wise permutation).
//   x_B: B's input share (n rows of width W)
//   corrB: B's preprocessing correlation
//   messageFromA: m received from A
//   outYb: B's output share (n rows of width W)
void cgpOnlineB(const RowVec& x_B,
                const CgpCorrelationB& corrB,
                const RowVec& messageFromA,
                RowVec& outYb);

// Convenience wrapper that runs both sides of one shuffle in-memory.
// Useful for tests. Returns (y_A, y_B).
struct CgpShuffleResult {
    RowVec y_A;
    RowVec y_B;
};
CgpShuffleResult cgpRunInMemory(const RowVec& x_A,
                                const RowVec& x_B,
                                const CgpCorrelationA& corrA,
                                const CgpCorrelationB& corrB);

// ----------------------------------------------------------------------
// N-party cascade (wide-row variant).

struct CascadeStateCgp {
    RowVec spShare;       // SP's share (n rows × W blocks)
    RowVec peerShare;     // active sender's share
};

enum class MaliciousMode : uint8_t {
    SemiHonest = 0,
    Malicious  = 1   // each party additionally commits to its messages
};

bool cgpCascadeRound(const CascadeStateCgp& incoming,
                     const CgpCorrelationA& corrA,
                     const CgpCorrelationB& corrB,
                     MaliciousMode mode,
                     CascadeStateCgp& out);

// Final reveal: combine SP's accumulated share with the last sender's
// share row-wise.
RowVec cgpFinalReveal(const CascadeStateCgp& state);

} // namespace mpstar
} // namespace volePSI
