// R26b/step2: CGP OT-based preprocessing test.

#include "volePSI/MpCgpPreprocess.h"
#include "volePSI/MpCgpShuffle.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Crypto/PRNG.h"

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

// Run the 2-party wire preprocessing and return both parties' outputs.
static std::pair<mp::CgpPreprocResult, mp::CgpPreprocResult>
runPreprocess(uint32_t n, uint32_t W, uint8_t seed) {
    auto socks = coproto::LocalAsyncSocket::makePair();
    auto p0 = [&]() -> macoro::task<mp::CgpPreprocResult> {
        oc::PRNG prng = makePrng(seed + 0);
        co_return co_await mp::cgpPreprocessOverWire(0, n, W, prng, socks[0]);
    };
    auto p1 = [&]() -> macoro::task<mp::CgpPreprocResult> {
        oc::PRNG prng = makePrng(seed + 1);
        co_return co_await mp::cgpPreprocessOverWire(1, n, W, prng, socks[1]);
    };
    auto r = macoro::sync_wait(macoro::when_all_ready(p0(), p1()));
    return {std::move(std::get<0>(r)).result(), std::move(std::get<1>(r)).result()};
}

// --------------------------------------------------------------

bool test_preprocess_roles() {
    auto [r0, r1] = runPreprocess(8, 1, 0x10);
    return r0.isPartyA && !r1.isPartyA;
}

bool test_correlation_invariant() {
    // alpha[i] = a[pi[i]] XOR b[i] row-wise
    const uint32_t n = 16, W = 2;
    auto [r0, r1] = runPreprocess(n, W, 0x20);
    if (!r0.isPartyA || r1.isPartyA) return false;
    const auto& a = r0.partyA.a;
    const auto& alpha = r0.partyA.alpha;
    const auto& pi = r1.partyB.pi;
    const auto& b = r1.partyB.b;
    if (a.size() != n || alpha.size() != n || pi.size() != n || b.size() != n) return false;
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t w = 0; w < W; ++w) {
            block expected;
            const auto* pa = reinterpret_cast<const uint8_t*>(&a[pi[i]][w]);
            const auto* pb = reinterpret_cast<const uint8_t*>(&b[i][w]);
            auto* pe = reinterpret_cast<uint8_t*>(&expected);
            for (int j = 0; j < 16; ++j) pe[j] = pa[j] ^ pb[j];
            if (!(expected == alpha[i][w])) return false;
        }
    }
    return true;
}

bool test_preprocess_drives_cgp_shuffle() {
    // Feed the preprocessed correlation into cgpRunInMemory and verify
    // end-to-end shuffle correctness.
    const uint32_t n = 16, W = 1;
    auto [r0, r1] = runPreprocess(n, W, 0x30);
    auto prng = makePrng(0x40);
    mp::RowVec x_A(n), x_B(n);
    for (uint32_t i = 0; i < n; ++i) {
        x_A[i].resize(W); x_B[i].resize(W);
        for (uint32_t w = 0; w < W; ++w) {
            x_A[i][w] = prng.get<block>();
            x_B[i][w] = prng.get<block>();
        }
    }
    auto result = mp::cgpRunInMemory(x_A, x_B, r0.partyA, r1.partyB);
    // Joint reconstruction: y_A XOR y_B should equal pi(x_A XOR x_B).
    for (uint32_t i = 0; i < n; ++i) {
        int src = r1.partyB.pi[i];
        for (uint32_t w = 0; w < W; ++w) {
            block joint_in, joint_out;
            const auto* pa = reinterpret_cast<const uint8_t*>(&x_A[src][w]);
            const auto* pb = reinterpret_cast<const uint8_t*>(&x_B[src][w]);
            auto* pj = reinterpret_cast<uint8_t*>(&joint_in);
            for (int j = 0; j < 16; ++j) pj[j] = pa[j] ^ pb[j];
            const auto* pya = reinterpret_cast<const uint8_t*>(&result.y_A[i][w]);
            const auto* pyb = reinterpret_cast<const uint8_t*>(&result.y_B[i][w]);
            auto* pyj = reinterpret_cast<uint8_t*>(&joint_out);
            for (int j = 0; j < 16; ++j) pyj[j] = pya[j] ^ pyb[j];
            if (!(joint_in == joint_out)) return false;
        }
    }
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"preprocess_roles",              test_preprocess_roles},
        {"correlation_invariant",         test_correlation_invariant},
        {"preprocess_drives_cgp_shuffle", test_preprocess_drives_cgp_shuffle},
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
