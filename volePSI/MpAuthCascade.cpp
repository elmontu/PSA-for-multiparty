#include "MpAuthCascade.h"
#include "MpStarCrypto.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

oc::block deriveMacKey(const std::array<uint8_t, 32>& spKey,
                       const std::array<uint8_t, 32>& sessionId,
                       uint32_t roundIdx)
{
    std::string purpose = "mac_round_" + std::to_string(roundIdx);
    auto k = deriveSessionKey(spKey, sessionId, purpose);
    oc::block out;
    std::memcpy(&out, k.data(), sizeof(oc::block));
    return out;
}

std::vector<int> randomPermutation(uint32_t n, const oc::block& seed)
{
    // Fisher-Yates from a seeded PRNG. We use the cryptoTools PRNG with
    // the given block seed — identical interface to the one used by
    // OSNSender::init_wj_seeded so the simulation tracks the wire protocol.
    oc::PRNG prng;
    prng.SetSeed(seed);

    std::vector<int> dest(n);
    std::iota(dest.begin(), dest.end(), 0);
    for (uint32_t i = n - 1; i > 0; --i) {
        uint32_t j = prng.get<uint32_t>() % (i + 1);
        std::swap(dest[i], dest[j]);
    }
    return dest;
}

bool cascadeRound(const std::vector<CascadeColumn>& incoming,
                  const std::vector<int>& permutation,
                  const oc::block& alphaOld,
                  const oc::block& alphaNew,
                  oc::PRNG& sharingPrng,
                  CascadeRoundOutput& out)
{
    out.spState.clear();
    out.peerHandoff.clear();

    if (incoming.empty()) return true;
    const size_t C = permutation.size();

    out.spState.reserve(incoming.size());
    out.peerHandoff.reserve(incoming.size());

    for (const auto& col : incoming) {
        if (col.sp.size() != C || col.peer.size() != C) return false;

        // Step 1: verify incoming MAC under alphaOld.
        if (!verifyAuthShares(col.sp, col.peer, alphaOld)) return false;

        // Step 2: permute data + tag in lockstep on each side.
        AuthShare sp_permuted   = permuteAuth(col.sp,   permutation);
        AuthShare peer_permuted = permuteAuth(col.peer, permutation);

        // Step 3: re-MAC under alphaNew. Each party LOCALLY recomputes
        // its tag share as alphaNew · own_data_share. No comm needed.
        //   sp.tag_new  ⊕ peer.tag_new
        //     = alphaNew·sp.data ⊕ alphaNew·peer.data
        //     = alphaNew · (sp.data ⊕ peer.data) = alphaNew · plain ✓
        // Tag shares stay uniformly random because data shares are uniform
        // and gf128Mul by a fixed nonzero key is a bijection. Unused
        // `sharingPrng` is kept in the signature for future OLE-based
        // randomization (see docs/MALICIOUS_CASCADE_DESIGN.md).
        (void)sharingPrng;
        AuthShare sp_out, peer_out;
        sp_out.data   = std::move(sp_permuted.data);
        peer_out.data = std::move(peer_permuted.data);
        sp_out.tag.resize(C);
        peer_out.tag.resize(C);
        for (size_t i = 0; i < C; ++i) {
            sp_out.tag[i]   = alphaNew.gf128Mul(sp_out.data[i]);
            peer_out.tag[i] = alphaNew.gf128Mul(peer_out.data[i]);
        }

        out.spState.push_back(std::move(sp_out));
        out.peerHandoff.push_back(std::move(peer_out));
    }

    return true;
}

bool finalVerify(const std::vector<AuthShare>& spState,
                 const std::vector<AuthShare>& lastPeerState,
                 const oc::block& alphaFinal,
                 std::vector<std::vector<oc::block>>& outPlain)
{
    outPlain.clear();
    if (spState.size() != lastPeerState.size()) return false;
    outPlain.resize(spState.size());

    for (size_t c = 0; c < spState.size(); ++c) {
        if (!verifyAuthShares(spState[c], lastPeerState[c], alphaFinal)) {
            outPlain.clear();
            return false;
        }
        const size_t C = spState[c].size();
        outPlain[c].resize(C);
        for (size_t i = 0; i < C; ++i) {
            outPlain[c][i] = spState[c].data[i] ^ lastPeerState[c].data[i];
        }
    }
    return true;
}

} // namespace mpstar
} // namespace volePSI
