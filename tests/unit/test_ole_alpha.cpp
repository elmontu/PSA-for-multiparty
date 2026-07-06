// R28 tests: OLE-based α-sharing for the malicious cascade.

#include "volePSI/MpOleAlpha.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "macoro/task.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static oc::PRNG makePrng(uint8_t b) {
    oc::PRNG p;
    block s; std::memset(&s, b, 16);
    p.SetSeed(s);
    return p;
}

static block xorBlocks(block a, block b) {
    block out;
    const auto* pa = reinterpret_cast<const uint8_t*>(&a);
    const auto* pb = reinterpret_cast<const uint8_t*>(&b);
    auto* po = reinterpret_cast<uint8_t*>(&out);
    for (int i = 0; i < 16; ++i) po[i] = pa[i] ^ pb[i];
    return out;
}

// --------------------------------------------------------------

bool test_ole_correlation_invariant() {
    auto prng = makePrng(0x10);
    for (int iter = 0; iter < 20; ++iter) {
        block alphaA = prng.get<block>();
        block xB     = prng.get<block>();
        auto res = mp::dealerOleGf128(alphaA, xB, prng);
        // Verify invariant: αA · xB == aA XOR cB
        block lhs = alphaA.gf128Mul(xB);
        block rhs = xorBlocks(res.forPartyA.myMask, res.forPartyB.myMask);
        if (!(lhs == rhs)) return false;
        // Each party's myValue is what they put in.
        if (!(res.forPartyA.myValue == alphaA)) return false;
        if (!(res.forPartyB.myValue == xB)) return false;
    }
    return true;
}

bool test_auth_share_roundtrip() {
    // Two parties pick α-shares; party A is the input party with plain x.
    // After authShareInput, joint data = x and joint tag = α · x.
    auto prng = makePrng(0x11);
    for (int iter = 0; iter < 20; ++iter) {
        block alphaA = mp::generateMyAlphaShare(prng);
        block alphaB = mp::generateMyAlphaShare(prng);
        block jointAlpha = xorBlocks(alphaA, alphaB);

        block plain = prng.get<block>();
        // OLE setup: the cross term is α_B · plain (since A is input, B
        // contributes α_B).
        auto ole = mp::dealerOleGf128(alphaB, plain, prng);

        // Party A is input; receives ole.forPartyB correlation
        // (myValue=plain, myMask=cB).
        auto shareA = mp::authShareInput(plain, /*iAmInputParty=*/true,
                                         alphaA, ole.forPartyB, /*partyIdx=*/0);
        // Party B is non-input; receives ole.forPartyA correlation
        // (myValue=αB, myMask=aA).
        // Wait — myOleAcross for party B is the "other side" of the OLE.
        // In our setup, A inputs plain, B inputs αB. The OLE outputs
        // forPartyA = (αB_for_B-input, aA) ? Let me re-check.
        //
        // Actually the OLE name semantics in dealerOleGf128: alphaA is
        // the α arg (party A's α, treated as input for the OLE), xB is
        // the x arg (party B's input). forPartyA gets (αA, aA);
        // forPartyB gets (xB, cB). So OLE party A here is the α-holder.
        //
        // In our cascade: input party (data plaintext holder) is the
        // x-holder = OLE party B. Non-input party (α_other holder) is
        // the α-holder = OLE party A.
        //
        // Wait, that means in my test:
        // - Cascade party A is INPUT party — holds plain
        // - Cascade party A is OLE party B (x-holder)
        // - Cascade party B is non-input — holds αB
        // - Cascade party B is OLE party A (α-holder)
        //
        // So I called dealerOleGf128(alphaA=αB, xB=plain) — the first
        // arg is OLE-A's α-input, second is OLE-B's x-input. So:
        //   ole.forPartyA = (αB, aA)  → goes to cascade-party-B (the non-input party)
        //   ole.forPartyB = (plain, cB) → goes to cascade-party-A (the input party)
        // Good, my shareA above used ole.forPartyB which matches.

        auto shareB = mp::authShareInput(block{}, /*iAmInputParty=*/false,
                                         alphaB, ole.forPartyA, /*partyIdx=*/1);

        // Verify joint data = plain.
        if (!(xorBlocks(shareA.data, shareB.data) == plain)) return false;
        // Verify joint tag = α · plain.
        block jointTag = xorBlocks(shareA.tag, shareB.tag);
        block expected = jointAlpha.gf128Mul(plain);
        if (!(jointTag == expected)) return false;
    }
    return true;
}

bool test_verifyAuthBatchJoint_accepts_honest() {
    auto prng = makePrng(0x12);
    block alphaA = mp::generateMyAlphaShare(prng);
    block alphaB = mp::generateMyAlphaShare(prng);
    block jointAlpha = xorBlocks(alphaA, alphaB);

    std::vector<mp::AuthShareMine> sharesA, sharesB;
    for (int i = 0; i < 8; ++i) {
        block plain = prng.get<block>();
        auto ole = mp::dealerOleGf128(alphaB, plain, prng);
        sharesA.push_back(mp::authShareInput(plain, true,  alphaA, ole.forPartyB, 0));
        sharesB.push_back(mp::authShareInput(block{}, false, alphaB, ole.forPartyA, 1));
    }
    return mp::verifyAuthBatchJoint(sharesA, sharesB, jointAlpha);
}

bool test_verifyAuthBatchJoint_rejects_tampered() {
    auto prng = makePrng(0x13);
    block alphaA = mp::generateMyAlphaShare(prng);
    block alphaB = mp::generateMyAlphaShare(prng);
    block jointAlpha = xorBlocks(alphaA, alphaB);

    std::vector<mp::AuthShareMine> sharesA, sharesB;
    for (int i = 0; i < 4; ++i) {
        block plain = prng.get<block>();
        auto ole = mp::dealerOleGf128(alphaB, plain, prng);
        sharesA.push_back(mp::authShareInput(plain, true,  alphaA, ole.forPartyB, 0));
        sharesB.push_back(mp::authShareInput(block{}, false, alphaB, ole.forPartyA, 1));
    }
    // Tamper: flip one byte of one tag share without updating data.
    auto* p = reinterpret_cast<uint8_t*>(&sharesA[2].tag);
    p[5] ^= 0x40;
    return !mp::verifyAuthBatchJoint(sharesA, sharesB, jointAlpha);
}

bool test_mac_check_batched_accepts_honest() {
    auto prng = makePrng(0x14);
    block alphaA = mp::generateMyAlphaShare(prng);
    block alphaB = mp::generateMyAlphaShare(prng);
    block jointAlpha = xorBlocks(alphaA, alphaB);

    std::vector<mp::AuthShareMine> sharesA, sharesB;
    for (int i = 0; i < 16; ++i) {
        block plain = prng.get<block>();
        auto ole = mp::dealerOleGf128(alphaB, plain, prng);
        sharesA.push_back(mp::authShareInput(plain, true,  alphaA, ole.forPartyB, 0));
        sharesB.push_back(mp::authShareInput(block{}, false, alphaB, ole.forPartyA, 1));
    }
    auto challengePrng = makePrng(0xAB);
    return mp::macCheckBatched(sharesA, sharesB, jointAlpha, challengePrng);
}

bool test_mac_check_batched_rejects_tampered() {
    auto prng = makePrng(0x15);
    block alphaA = mp::generateMyAlphaShare(prng);
    block alphaB = mp::generateMyAlphaShare(prng);
    block jointAlpha = xorBlocks(alphaA, alphaB);

    std::vector<mp::AuthShareMine> sharesA, sharesB;
    for (int i = 0; i < 16; ++i) {
        block plain = prng.get<block>();
        auto ole = mp::dealerOleGf128(alphaB, plain, prng);
        sharesA.push_back(mp::authShareInput(plain, true,  alphaA, ole.forPartyB, 0));
        sharesB.push_back(mp::authShareInput(block{}, false, alphaB, ole.forPartyA, 1));
    }
    // Tamper data share without updating tag.
    auto* p = reinterpret_cast<uint8_t*>(&sharesA[7].data);
    p[3] ^= 0x10;
    auto challengePrng = makePrng(0xCD);
    return !mp::macCheckBatched(sharesA, sharesB, jointAlpha, challengePrng);
}

// --------------------------------------------------------------

// R37: wire-protocol OLE — verify the invariant alphaA · bB == a XOR c
// where a is party 0's output mask, c is party 1's output mask.
bool test_ole_gf128_over_wire_invariant() {
    auto prng = makePrng(0x50);
    block alphaA = prng.get<block>();
    block bB     = prng.get<block>();

    auto socks = coproto::LocalAsyncSocket::makePair();
    auto p0 = [&]() -> macoro::task<mp::OleGf128CorrelationOverWire> {
        oc::PRNG p; p.SetSeed(oc::sysRandomSeed());
        co_return co_await mp::oleGf128OverWire(0, alphaA, p, socks[0]);
    };
    auto p1 = [&]() -> macoro::task<mp::OleGf128CorrelationOverWire> {
        oc::PRNG p; p.SetSeed(oc::sysRandomSeed());
        co_return co_await mp::oleGf128OverWire(1, bB, p, socks[1]);
    };
    auto r = macoro::sync_wait(macoro::when_all_ready(p0(), p1()));
    auto p0r = std::move(std::get<0>(r)).result();
    auto p1r = std::move(std::get<1>(r)).result();

    block lhs = alphaA.gf128Mul(bB);
    block rhs = xorBlocks(p0r.myMask, p1r.myMask);
    if (!(p0r.myValue == alphaA) || !(p1r.myValue == bB)) return false;
    return lhs == rhs;
}

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"ole_correlation_invariant",            test_ole_correlation_invariant},
        {"auth_share_roundtrip",                 test_auth_share_roundtrip},
        {"verifyAuthBatchJoint_accepts_honest",  test_verifyAuthBatchJoint_accepts_honest},
        {"verifyAuthBatchJoint_rejects_tampered", test_verifyAuthBatchJoint_rejects_tampered},
        {"mac_check_batched_accepts_honest",     test_mac_check_batched_accepts_honest},
        {"mac_check_batched_rejects_tampered",   test_mac_check_batched_rejects_tampered},
        {"ole_gf128_over_wire_invariant",        test_ole_gf128_over_wire_invariant},
    };
    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try { std::cout << (fn() ? "PASS" : "FAIL") << "\n"; if (!fn()) ++failures; }
        catch (const std::exception& e) { std::cout << "FAIL (" << e.what() << ")\n"; ++failures; }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
