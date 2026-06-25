#include "volePSI/fileBased.h"
#include "volePSI/MpsaDriver.h"

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    if (cmd.isSet("mpsa")) {
        volePSI::doFileMpsa(cmd);
        return 0;
    }

    volePSI::doFileSpHshPSIwithOSN(cmd);
    return 0;
}
