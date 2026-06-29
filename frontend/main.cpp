#include "volePSI/fileBased.h"
#include "volePSI/MpsaDriver.h"
#include "volePSI/MpsaJoinDriverWire.h"
#include "volePSI/MpsaJoinMpcDriver.h"

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    // R34: SP-blind MPC private join (single-process simulation).
    // Dispatched first since flag is most specific.
    if (cmd.isSet("mpsa-join-mpc")) {
        volePSI::doFileMpsaJoinMpc(cmd);
        return 0;
    }

    // R33: table-valued private join (trusted-SP wire protocol).
    if (cmd.isSet("mpsa-join")) {
        volePSI::doFileMpsaJoin(cmd);
        return 0;
    }

    if (cmd.isSet("mpsa")) {
        volePSI::doFileMpsa(cmd);
        return 0;
    }

    volePSI::doFileSpHshPSIwithOSN(cmd);
    return 0;
}
