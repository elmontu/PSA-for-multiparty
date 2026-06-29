#pragma once

#include "cryptoTools/Common/CLP.h"

namespace volePSI {

// Entry point for the N-party table-valued private join wire protocol
// (R33). See docs/PRIVATE_JOIN_DESIGN.md.
//
// Privacy model: trusted-SP semantics. After AEAD decryption SP sees
// plaintext sender inputs. This is a deliberate weaker privacy model
// than the cascade MPSA (which keeps payload secret from SP via masking
// + shuffle reveal). Appropriate when SP is the data controller
// (regulator, broker) and entitled to the join output anyway. The
// full-MPC variant (SP-blind sort+filter) needs OLE/Beaver-triple
// infrastructure — tracked as R34.
//
// CLI args:
//   -mpsa-join             mode flag (checked by caller in main.cpp)
//   -N <senderCount>       number of senders (default 3)
//   -r <role>              0 = SP, 1 = sender (default 0)
//   -i <senderIdx>         required when -r 1; in [0, N)
//   -in <path>             input CSV when -r 1
//                            CSV format: col0=id, cols1..W=payload blocks.
//                            Multiple rows with same id allowed and expected
//                            (table-valued payload).
//   -out <path>            output CSV when -r 0
//   -port <basePort>       SP listens on basePort+i for sender i (default 17500)
//   -host <spHost>         sender's SP hostname (default localhost)
//   -pw <W>                payload width in blocks per row (default 1)
//   -M <M>                 max rows per id per party (default 4)
//   -v                     verbose debug logs to stderr
void doFileMpsaJoin(osuCrypto::CLP& cmd);

} // namespace volePSI
