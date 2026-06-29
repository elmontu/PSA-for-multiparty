// R34k unit test: real 2-party OLE-based Beaver triple generation via
// libOTe SilentOtTriple, closing the trusted-dealer gap for the 2-party
// MPC private join.
//
// Each test spawns two coroutines (one per party) communicating over an
// in-process LocalAsyncSocket pair. The shared invariant
// (u_0 ⊕ u_1) AND (v_0 ⊕ v_1) == (w_0 ⊕ w_1) is verified after both
// halves return their triple batches.
//
// The triples are then drop-in usable in secureAnd from MpBeaverTriple.h.

#include "volePSI/MpOleTriple.h"
#include "volePSI/MpBeaverTriple.h"
#include "volePSI/MpSecretShare.h"

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

static oc::PRNG makePrng(uint8_t seedByte) {
    oc::PRNG p;
    block s; std::memset(&s, seedByte, 16);
    p.SetSeed(s);
    return p;
}

// Run the 2-party OLE triple generation over an in-process socket pair.
// Returns (party0Triples, party1Triples). Caller can merge them to
// validate the invariant.
static std::pair<std::vector<mp::BeaverTripleBit>,
                 std::vector<mp::BeaverTripleBit>>
runOleTripleGen(size_t count, uint8_t seed)
{
    auto socks = coproto::LocalAsyncSocket::makePair();

    auto party0 = [&]() -> macoro::task<std::vector<mp::BeaverTripleBit>> {
        oc::PRNG p0 = makePrng(seed + 0);
        auto t = co_await mp::oleGenerateTriples(0, count, p0, socks[0]);
        co_await socks[0].flush();
        co_return t;
    };
    auto party1 = [&]() -> macoro::task<std::vector<mp::BeaverTripleBit>> {
        oc::PRNG p1 = makePrng(seed + 1);
        auto t = co_await mp::oleGenerateTriples(1, count, p1, socks[1]);
        co_await socks[1].flush();
        co_return t;
    };

    auto results = macoro::sync_wait(
        macoro::when_all_ready(party0(), party1()));
    auto t0 = std::move(std::get<0>(results)).result();
    auto t1 = std::move(std::get<1>(results)).result();
    return {std::move(t0), std::move(t1)};
}

// Merge per-party triple batches into a single batch with N=2 shares
// populated. This is the "view from outside" — in the real protocol no
// single party can perform this merge.
static std::vector<mp::BeaverTripleBit>
mergeBatches(const std::vector<mp::BeaverTripleBit>& a,
             const std::vector<mp::BeaverTripleBit>& b)
{
    if (a.size() != b.size())
        throw std::runtime_error("mergeBatches: size mismatch");
    std::vector<mp::BeaverTripleBit> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i].u = mp::SharedBit(2);
        out[i].v = mp::SharedBit(2);
        out[i].w = mp::SharedBit(2);
        out[i].u.shares[0] = a[i].u.shares[0];
        out[i].u.shares[1] = b[i].u.shares[1];
        out[i].v.shares[0] = a[i].v.shares[0];
        out[i].v.shares[1] = b[i].v.shares[1];
        out[i].w.shares[0] = a[i].w.shares[0];
        out[i].w.shares[1] = b[i].w.shares[1];
    }
    return out;
}

// --------------------------------------------------------------

bool test_ole_triple_basic_invariant() {
    const size_t count = 128;  // exactly one block worth
    auto [t0, t1] = runOleTripleGen(count, 0x01);
    if (t0.size() != count || t1.size() != count) return false;
    auto merged = mergeBatches(t0, t1);
    return mp::verifyBeaverTripleBatch(merged);
}

bool test_ole_triple_uneven_count() {
    // Non-block-aligned count.
    const size_t count = 70;
    auto [t0, t1] = runOleTripleGen(count, 0x02);
    if (t0.size() != count || t1.size() != count) return false;
    auto merged = mergeBatches(t0, t1);
    return mp::verifyBeaverTripleBatch(merged);
}

bool test_ole_triple_larger_batch() {
    // 4 blocks worth = 512 triples.
    const size_t count = 512;
    auto [t0, t1] = runOleTripleGen(count, 0x03);
    if (t0.size() != count || t1.size() != count) return false;
    auto merged = mergeBatches(t0, t1);
    return mp::verifyBeaverTripleBatch(merged);
}

bool test_ole_triple_shares_random() {
    // Each party's share alone should NOT trivially equal the underlying
    // u, v, or w. Sample many triples and check that party 0's u shares
    // are not all 0 (or all 1).
    const size_t count = 256;
    auto [t0, t1] = runOleTripleGen(count, 0x04);
    int u0_ones = 0, v0_ones = 0, w0_ones = 0;
    for (size_t i = 0; i < count; ++i) {
        if (t0[i].u.shares[0]) ++u0_ones;
        if (t0[i].v.shares[0]) ++v0_ones;
        if (t0[i].w.shares[0]) ++w0_ones;
    }
    // For uniform random bits we expect ~128. Allow 50-200 range for
    // statistical safety.
    auto inRange = [](int x) { return x > 50 && x < 200; };
    return inRange(u0_ones) && inRange(v0_ones) && inRange(w0_ones);
}

bool test_ole_triple_drives_secureAnd() {
    // Verify the OLE-generated triples are drop-in usable for the
    // existing secureAnd from MpBeaverTriple.h. We construct shared
    // bits x and y, secureAnd them using OLE-generated triples, and
    // check the result.
    const size_t count = 16;
    auto [t0, t1] = runOleTripleGen(count, 0x05);
    auto merged = mergeBatches(t0, t1);

    auto prng = makePrng(0x55);
    int correct = 0;
    int total = 0;
    for (uint8_t xv : {uint8_t{0}, uint8_t{1}}) {
        for (uint8_t yv : {uint8_t{0}, uint8_t{1}}) {
            // Use 4 triples per (x, y) pair to keep test runtime low.
            for (int tIdx = 0; tIdx < 4; ++tIdx) {
                if (total >= static_cast<int>(merged.size())) break;
                auto xs = mp::shareBit(2, xv, prng);
                auto ys = mp::shareBit(2, yv, prng);
                auto zs = mp::secureAnd(xs, ys, merged[total]);
                if (zs.reconstruct() == (xv & yv)) ++correct;
                ++total;
            }
        }
    }
    return correct == total && total > 0;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"ole_triple_basic_invariant",   test_ole_triple_basic_invariant},
        {"ole_triple_uneven_count",      test_ole_triple_uneven_count},
        {"ole_triple_larger_batch",      test_ole_triple_larger_batch},
        {"ole_triple_shares_random",     test_ole_triple_shares_random},
        {"ole_triple_drives_secureAnd",  test_ole_triple_drives_secureAnd},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try {
            if (fn()) std::cout << "PASS\n";
            else { std::cout << "FAIL\n"; ++failures; }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")\n";
            ++failures;
        } catch (...) {
            std::cout << "FAIL (unknown exception)\n";
            ++failures;
        }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
