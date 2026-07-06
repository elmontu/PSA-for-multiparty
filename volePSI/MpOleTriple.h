#pragma once

// R34k: OLE-based Beaver triple bit generator. Replaces the trusted-
// dealer `generateBeaverTripleBit` (MpBeaverTriple.h) with a real 2-
// party protocol backed by libOTe's SilentOtTriple. Neither party
// learns the other's share of the generated triples — the trusted-
// dealer gap in R34 is closed for the 2-party case.
//
// SilentOtTriple uses a silent OT extension (Boyle-Couteau-Gilboa) to
// produce many bit triples in sublinear communication after a one-shot
// base-OT setup. The semantics it gives us per call to expand(A, B, C):
//   each party gets (A_i, B_i, C_i) such that:
//     (A_0 ⊕ A_1) AND (B_0 ⊕ B_1) == (C_0 ⊕ C_1)
//   where each of A, B, C is a span<block>, and each block holds 128
//   independent triples bit-by-bit.
//
// This module packages that into BeaverTripleBit batches (one per bit
// position) matching the existing R34 MPC primitives.

#include "MpSecretShare.h"
#include "MpBeaverTriple.h"

#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/task.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// 2-party party index: 0 or 1.
//
// Each call to oleGenerateTriples runs the full silent-OT-triple
// protocol over `sock`. The two parties must call it in cooperating
// coroutines (or threads) with matching `partyIdx` values 0 and 1 and
// the same `count`. Returns a batch of `count` BeaverTripleBit, each
// with N=2 (matching the 2-party setting).
//
// THIS IS THE R34k DELIVERABLE: closes the trusted-dealer gap for
// the 2-party MPC case. The trusted dealer in R34b/c becomes a 2-party
// protocol with neither party learning the other's share. Both bit
// triples are still uniformly random; the protocol's correctness +
// privacy properties are inherited from libOTe's SilentOtTriple
// (Boyle-Couteau-Gilboa Silent OT under LPN hardness).
//
// Limitations:
//   - 2-party only. For N>2, generalizing requires multi-party OT
//     extension (e.g., extending the libOTe primitive or chaining
//     pairwise generations); see docs/MPC_WIRE_DESIGN.md.
//   - Semi-honest only. SilentOtTriple supports a malicious variant
//     (SilentSecType::Malicious) at higher cost; documented but not
//     yet wired through this API.
macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriples(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock);

// R37: Malicious-secure variant. Selects SilentSecType::Malicious in the
// underlying libOTe triple protocol. Cost is ~2-3× higher than the
// semi-honest variant; catches an active adversary corrupting one party.
macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriplesMalicious(
    uint64_t partyIdx,
    size_t count,
    oc::PRNG& prng,
    coproto::Socket& sock);

// R37: N-party generalization via pairwise + folding. Generates
// N-party BeaverTripleBits by running (N-1) pairwise 2-party OLE
// protocols (party 0 pairs with 1, 2, ..., N-1) and folding the
// per-pair triples into an N-party additive share structure.
//
// This is 2-party-secure but N-party-usable: any single corruption is
// caught by the underlying 2-party OLE's security; joint corruption
// of party 0 (the hub) with any other party is NOT covered — that
// requires a native N-party OT-extension protocol, documented in
// docs/MPC_WIRE_DESIGN.md as a follow-up.
//
// partyIdx: my party index in [0, N)
// N: number of parties
// count: number of triple bits to generate
// sockets: sockets[i] is my connection to party i (empty at own index).
//          Total N sockets; sockets[myIdx] is unused.
// Returns a vector of BeaverTripleBits with N shares each.
macoro::task<std::vector<BeaverTripleBit>> oleGenerateTriplesNParty(
    uint64_t partyIdx,
    uint32_t N,
    size_t count,
    oc::PRNG& prng,
    std::vector<coproto::Socket>& sockets);

// Verify a batch of triples satisfies the invariant
//   for each i:  triples[i].u.reconstruct()
//              & triples[i].v.reconstruct()
//             == triples[i].w.reconstruct()
// Used by tests to confirm OLE-generated triples are correct.
bool verifyBeaverTripleBatch(const std::vector<BeaverTripleBit>& triples);

} // namespace mpstar
} // namespace volePSI
