#pragma once

#include "cryptoTools/Common/CLP.h"

namespace volePSI {

// In-process CLI wrapper around the SP-blind MPC private join driver
// (R34g-j). Single-process mode: all N parties + SP run in the same
// process, sharing memory. Each party's data is still secret-shared and
// the join logic still goes through MPC primitives (sort, expand,
// filter), so the OUTPUT is correct and all code paths are exercised.
//
// This is NOT a deployable wire protocol — that's R34k (deferred,
// requires OLE-based Beaver triple generation via libOTe and multi-
// round network coordination). What this mode IS useful for:
//   - validating end-to-end MPC join behavior against plaintext oracle
//   - benchmarking the MPC compute cost on real CSV inputs
//   - demonstrating the SP-blind join to stakeholders
//
// CLI:
//   frontend -mpsa-join-mpc -N <N> -M <M> -in0 <csv0> -in1 <csv1> ...
//                          -pw <W> -out <csv>
// Where -inK gives party K's input CSV (multi-row-per-id), -pw is
// payload width in 16-byte blocks (rowDataBits = pw * 128), -M is the
// per-(party, id) row cap, -out is the joined output CSV.
void doFileMpsaJoinMpc(osuCrypto::CLP& cmd);

} // namespace volePSI
