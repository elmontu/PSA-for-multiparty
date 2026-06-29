#include "MpOleAlpha.h"

#include <cstring>

namespace volePSI {
namespace mpstar {

namespace {

// Constant-time equality on oc::block (16 bytes). Returns 0 if equal,
// non-zero otherwise; XOR-accumulator avoids early termination.
uint8_t ctEqBlocks(const oc::block& a, const oc::block& b) {
    const auto* pa = reinterpret_cast<const uint8_t*>(&a);
    const auto* pb = reinterpret_cast<const uint8_t*>(&b);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= (pa[i] ^ pb[i]);
    return diff;
}

} // namespace

MyShareAlpha generateMyAlphaShare(oc::PRNG& prng) {
    return prng.get<oc::block>();
}

OleGf128Result dealerOleGf128(oc::block alphaA, oc::block xB, oc::PRNG& prng) {
    oc::block aA = prng.get<oc::block>();  // uniform mask for party A
    oc::block product = alphaA.gf128Mul(xB);
    oc::block cB;
    {
        const auto* p = reinterpret_cast<const uint8_t*>(&product);
        const auto* q = reinterpret_cast<const uint8_t*>(&aA);
        auto* r = reinterpret_cast<uint8_t*>(&cB);
        for (int i = 0; i < 16; ++i) r[i] = p[i] ^ q[i];
    }
    // Invariant check (paranoia; would be removed in production):
    {
        oc::block check_xor;
        const auto* p = reinterpret_cast<const uint8_t*>(&aA);
        const auto* q = reinterpret_cast<const uint8_t*>(&cB);
        auto* r = reinterpret_cast<uint8_t*>(&check_xor);
        for (int i = 0; i < 16; ++i) r[i] = p[i] ^ q[i];
        if (ctEqBlocks(check_xor, product) != 0) {
            throw std::runtime_error("dealerOleGf128: invariant failed (bug)");
        }
    }
    OleGf128Result res;
    res.forPartyA = {alphaA, aA};
    res.forPartyB = {xB, cB};
    return res;
}

AuthShareMine authShareInput(
    oc::block plain,
    bool iAmInputParty,
    MyShareAlpha myAlpha,
    const OleGf128Correlation& myOleAcross,
    uint64_t partyIdx)
{
    (void)partyIdx;  // not used in the algebra; kept for API symmetry
    AuthShareMine out;
    if (iAmInputParty) {
        // I hold plain. My data share = plain. My tag share =
        // (my α-share · plain) XOR (OLE output for cross term).
        //
        // The OLE was set up so that I am party B (input party with x =
        // plain) and the other party is party A (with α_other). So my
        // OLE-correlation gives me (myValue=plain, myMask=cB) with cB =
        // α_other · plain XOR aA. The other party holds (α_other, aA).
        //
        // Joint α·plain = (α_self XOR α_other)·plain
        //               = (α_self·plain) XOR (α_other·plain)
        //               = (α_self·plain) XOR (cB XOR aA)
        //
        // My contribution to tag: α_self·plain XOR cB (I know both).
        // Other contribution: aA (they know it from their OLE side).
        // XOR-sum: my_tag XOR their_tag = α_self·plain XOR cB XOR aA
        //                                = α·plain ✓
        out.data = plain;
        oc::block selfTerm = myAlpha.gf128Mul(plain);
        const auto* p = reinterpret_cast<const uint8_t*>(&selfTerm);
        const auto* q = reinterpret_cast<const uint8_t*>(&myOleAcross.myMask);
        auto* r = reinterpret_cast<uint8_t*>(&out.tag);
        for (int i = 0; i < 16; ++i) r[i] = p[i] ^ q[i];
    } else {
        // I don't know plain. My data share = 0. My tag share = the
        // OLE mask aA which is the cross term α_self · plain (jointly,
        // with the other party's cB providing the remainder).
        out.data = oc::block{};
        out.tag = myOleAcross.myMask;
    }
    return out;
}

bool verifyAuthBatchJoint(
    const std::vector<AuthShareMine>& sharesA,
    const std::vector<AuthShareMine>& sharesB,
    oc::block jointAlpha)
{
    if (sharesA.size() != sharesB.size()) return false;
    uint8_t failAcc = 0;  // accumulate failure bit constant-time
    for (size_t i = 0; i < sharesA.size(); ++i) {
        oc::block jointData, jointTag, expectedTag;
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&sharesA[i].data);
            const auto* b = reinterpret_cast<const uint8_t*>(&sharesB[i].data);
            auto* r = reinterpret_cast<uint8_t*>(&jointData);
            for (int j = 0; j < 16; ++j) r[j] = a[j] ^ b[j];
        }
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&sharesA[i].tag);
            const auto* b = reinterpret_cast<const uint8_t*>(&sharesB[i].tag);
            auto* r = reinterpret_cast<uint8_t*>(&jointTag);
            for (int j = 0; j < 16; ++j) r[j] = a[j] ^ b[j];
        }
        expectedTag = jointAlpha.gf128Mul(jointData);
        failAcc |= ctEqBlocks(jointTag, expectedTag);
    }
    return failAcc == 0;
}

bool macCheckBatched(
    const std::vector<AuthShareMine>& sharesA,
    const std::vector<AuthShareMine>& sharesB,
    oc::block jointAlpha,
    oc::PRNG& challengePrng)
{
    if (sharesA.size() != sharesB.size()) return false;
    // Random linear combination: pick random r_i, accumulate
    //   joint_data = Σ r_i · (data_A_i XOR data_B_i)
    //   joint_tag  = Σ r_i · (tag_A_i  XOR tag_B_i)
    // Check joint_tag == α · joint_data.
    oc::block accData{};
    oc::block accTag{};
    for (size_t i = 0; i < sharesA.size(); ++i) {
        oc::block r = challengePrng.get<oc::block>();
        oc::block jointData, jointTag;
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&sharesA[i].data);
            const auto* b = reinterpret_cast<const uint8_t*>(&sharesB[i].data);
            auto* z = reinterpret_cast<uint8_t*>(&jointData);
            for (int j = 0; j < 16; ++j) z[j] = a[j] ^ b[j];
        }
        {
            const auto* a = reinterpret_cast<const uint8_t*>(&sharesA[i].tag);
            const auto* b = reinterpret_cast<const uint8_t*>(&sharesB[i].tag);
            auto* z = reinterpret_cast<uint8_t*>(&jointTag);
            for (int j = 0; j < 16; ++j) z[j] = a[j] ^ b[j];
        }
        oc::block termData = r.gf128Mul(jointData);
        oc::block termTag  = r.gf128Mul(jointTag);
        const auto* pd = reinterpret_cast<const uint8_t*>(&termData);
        const auto* pt = reinterpret_cast<const uint8_t*>(&termTag);
        auto* ad = reinterpret_cast<uint8_t*>(&accData);
        auto* at = reinterpret_cast<uint8_t*>(&accTag);
        for (int j = 0; j < 16; ++j) {
            ad[j] ^= pd[j];
            at[j] ^= pt[j];
        }
    }
    oc::block expected = jointAlpha.gf128Mul(accData);
    return ctEqBlocks(accTag, expected) == 0;
}

} // namespace mpstar
} // namespace volePSI
