#include "MpKem.h"

#include <cstring>
#include <stdexcept>
#include <iostream>

namespace volePSI {
namespace mpstar {

namespace {
bool gStubWarned = false;
void warnStub() {
    if (!gStubWarned) {
        std::cerr << "[MpKem] WARNING: StubKem is in use. NOT secure. "
                     "Integrate a real KEM (ML-KEM-768) before deployment.\n";
        gStubWarned = true;
    }
}
} // namespace

void StubKem::keypair(std::vector<uint8_t>& pk,
                      std::vector<uint8_t>& sk) const
{
    warnStub();
    pk.assign(kPkBytes, 0);
    sk.assign(kSkBytes, 0);
}

void StubKem::encap(const std::vector<uint8_t>& peer_pk,
                    std::vector<uint8_t>& ct,
                    std::vector<uint8_t>& ss) const
{
    warnStub();
    if (peer_pk.size() != kPkBytes)
        throw std::runtime_error("StubKem::encap: bad peer pk size");
    ct.assign(kCtBytes, 0);
    ss.assign(kSsBytes, 0);
}

void StubKem::decap(const std::vector<uint8_t>& ct,
                    const std::vector<uint8_t>& sk,
                    std::vector<uint8_t>& ss) const
{
    warnStub();
    if (ct.size() != kCtBytes)
        throw std::runtime_error("StubKem::decap: bad ciphertext size");
    if (sk.size() != kSkBytes)
        throw std::runtime_error("StubKem::decap: bad sk size");
    ss.assign(kSsBytes, 0);
}

} // namespace mpstar
} // namespace volePSI
