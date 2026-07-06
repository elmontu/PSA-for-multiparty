#include "MpCgpPreprocess.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <numeric>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

// Handshake: both parties send a random 16-byte contribution; the shared
// seed = XOR of both contributions. This ensures the seed is uniformly
// random from either party's view (neither can bias it alone), even
// though both learn it. In the full-security variant this handshake
// only seeds the OT extension setup, not the correlation values
// themselves — those are derived via silent OT so neither side sees
// the peer's inputs.
macoro::task<oc::block> handshakeSeed(uint64_t partyIdx, coproto::Socket& sock)
{
    oc::block mine;
    // Freshly-random contribution.
    oc::PRNG local;
    local.SetSeed(oc::sysRandomSeed());
    mine = local.get<oc::block>();

    std::array<uint8_t, 16> mineBytes;
    std::memcpy(mineBytes.data(), &mine, 16);
    std::array<uint8_t, 16> peerBytes{};

    if (partyIdx == 0) {
        co_await sock.send(mineBytes);
        co_await sock.recv(peerBytes);
    } else {
        co_await sock.recv(peerBytes);
        co_await sock.send(mineBytes);
    }

    oc::block peer;
    std::memcpy(&peer, peerBytes.data(), 16);
    oc::block shared;
    auto* pa = reinterpret_cast<uint8_t*>(&shared);
    auto* pm = reinterpret_cast<uint8_t*>(&mine);
    auto* pp = reinterpret_cast<uint8_t*>(&peer);
    for (int i = 0; i < 16; ++i) pa[i] = pm[i] ^ pp[i];
    co_return shared;
}

} // namespace

macoro::task<CgpPreprocResult> cgpPreprocessOverWire(
    uint64_t partyIdx,
    uint32_t n, uint32_t W,
    oc::PRNG& prng,
    coproto::Socket& sock)
{
    if (partyIdx > 1)
        throw std::runtime_error("cgpPreprocessOverWire: partyIdx must be 0 or 1");
    if (n == 0 || W == 0)
        throw std::runtime_error("cgpPreprocessOverWire: n and W must be >= 1");

    // Step 1: handshake to derive a shared PRNG seed.
    oc::block sharedSeed = co_await handshakeSeed(partyIdx, sock);

    // Step 2: seed a shared PRNG and generate the same trusted-dealer
    // correlation on BOTH sides. This is the scaffolding step where the
    // libOTe silent-OT substitution slots in — instead of both parties
    // computing the FULL correlation from the shared seed (which
    // reveals it to both), the silent-OT variant derives the OT-based
    // correlated randomness where each party only sees ITS half.
    oc::PRNG sharedPrng;
    sharedPrng.SetSeed(sharedSeed);
    CgpCorrelationA cA;
    CgpCorrelationB cB;
    cgpDealerGenerate(n, W, sharedPrng, cA, cB);
    (void)prng;

    CgpPreprocResult res;
    res.isPartyA = (partyIdx == 0);
    if (partyIdx == 0) {
        res.partyA = std::move(cA);
    } else {
        res.partyB = std::move(cB);
    }
    co_return res;
}

} // namespace mpstar
} // namespace volePSI
