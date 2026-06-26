#pragma once

#include "cryptoTools/Common/CLP.h"

namespace volePSI {

// Entry point for the N-party MPSA pipeline. Dispatched from frontend/main.cpp
// when the CLI sees `-mpsa`. Reads role / N / sender index / port from cmd
// and runs either the Service Provider role or one of the N sender roles.
//
// CLI args:
//   -mpsa                  mode flag (checked by caller before invoking)
//   -N <senderCount>       (default: 3)
//   -r <role>              0 = SP, 1 = sender (default: 0)
//   -i <senderIdx>         required when -r 1
//   -in <path>             input CSV when -r 1
//   -out <path>            output CSV when -r 0
//   -port <basePort>       SP listens on basePort+i for sender i (default: 17500)
//   -host <spHost>         hostname senders dial SP at (default: localhost)
void doFileMpsa(osuCrypto::CLP& cmd);

} // namespace volePSI
