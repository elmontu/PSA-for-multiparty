// MPSVS Phase 17.2 — OLE-based Beaver triple generation for malicious-secure
// MPSVS pipeline.
//
// Replaces the trusted-dealer `generateBeaverTripleBits` with real OLE-based
// generation via libOTe's SilentOtTriple (Boyle-Couteau-Gilboa Silent OT
// under LPN hardness). Two async parties exchange messages over a coproto
// LocalAsyncSocket pair; neither party learns the other's shares.
//
// Two variants tested:
//   - semi-honest: oleGenerateTriples (fast)
//   - malicious:  oleGenerateTriplesMalicious (2-3× slower; catches active
//                 corruption in the OLE protocol itself)
//
// After generation, the resulting triples are drop-in usable in the MPSVS
// wire path (Phase 5 inclusion, Phase 6 bucket, etc.). This test:
//   1. Runs the OLE protocol between two async parties.
//   2. Merges the resulting per-party triples into an in-memory batch
//      (simulator-only view; real deployment keeps parties separated).
//   3. Verifies the invariant u·v = w for each triple.
//   4. Uses the batch in a real MPSVS operation (Phase 5 inclusion).
//   5. Verifies the output matches the trusted-dealer baseline.

#include "volePSI/MpBeaverTriple.h"
#include "volePSI/MpOleTriple.h"
#include "volePSI/MpSecretShare.h"
#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsInclusionWire.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "macoro/task.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// PRNG builder from a seed byte.
static oc::PRNG makePrng(uint8_t seedByte) {
    oc::PRNG p;
    oc::block s;
    std::memset(&s, seedByte, 16);
    p.SetSeed(s);
    return p;
}

// Run OLE triple generation between two async parties on a socket pair.
// Returns (party0's triples, party1's triples).
static std::pair<std::vector<BeaverTripleBit>, std::vector<BeaverTripleBit>>
runOleGen(size_t count, uint8_t seed, bool malicious) {
    auto socks = coproto::LocalAsyncSocket::makePair();
    auto party0 = [&]() -> macoro::task<std::vector<BeaverTripleBit>> {
        oc::PRNG p0 = makePrng(seed + 0);
        auto t = malicious
                    ? co_await oleGenerateTriplesMalicious(0, count, p0, socks[0])
                    : co_await oleGenerateTriples(0, count, p0, socks[0]);
        co_await socks[0].flush();
        co_return t;
    };
    auto party1 = [&]() -> macoro::task<std::vector<BeaverTripleBit>> {
        oc::PRNG p1 = makePrng(seed + 1);
        auto t = malicious
                    ? co_await oleGenerateTriplesMalicious(1, count, p1, socks[1])
                    : co_await oleGenerateTriples(1, count, p1, socks[1]);
        co_await socks[1].flush();
        co_return t;
    };
    auto results = macoro::sync_wait(
        macoro::when_all_ready(party0(), party1()));
    auto t0 = std::move(std::get<0>(results)).result();
    auto t1 = std::move(std::get<1>(results)).result();
    return {std::move(t0), std::move(t1)};
}

// Merge per-party batches into N=2 form (simulator view).
static std::vector<BeaverTripleBit>
mergeBatches(const std::vector<BeaverTripleBit>& a,
             const std::vector<BeaverTripleBit>& b) {
    std::vector<BeaverTripleBit> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i].u = SharedBit(2);
        out[i].v = SharedBit(2);
        out[i].w = SharedBit(2);
        out[i].u.shares[0] = a[i].u.shares[0];
        out[i].u.shares[1] = b[i].u.shares[1];
        out[i].v.shares[0] = a[i].v.shares[0];
        out[i].v.shares[1] = b[i].v.shares[1];
        out[i].w.shares[0] = a[i].w.shares[0];
        out[i].w.shares[1] = b[i].w.shares[1];
    }
    return out;
}

// ==========================================================================

static void test_ole_triples_correctness_semi_honest() {
    std::printf("--- C1: OLE (semi-honest) triples pass verifyBeaverTripleBatch ---\n");
    auto [t0, t1] = runOleGen(/*count=*/256, /*seed=*/0x11, /*malicious=*/false);
    CHECK(t0.size() == 256, "C1: party 0 got 256 triples");
    CHECK(t1.size() == 256, "C1: party 1 got 256 triples");
    auto merged = mergeBatches(t0, t1);
    bool valid = verifyBeaverTripleBatch(merged);
    CHECK(valid, "C1: all 256 OLE triples satisfy u·v=w invariant");
}

static void test_ole_triples_correctness_malicious() {
    std::printf("--- C2: OLE (malicious variant) triples pass verifyBeaverTripleBatch ---\n");
    auto [t0, t1] = runOleGen(/*count=*/256, /*seed=*/0x22, /*malicious=*/true);
    CHECK(t0.size() == 256, "C2: party 0 got 256 triples");
    CHECK(t1.size() == 256, "C2: party 1 got 256 triples");
    auto merged = mergeBatches(t0, t1);
    bool valid = verifyBeaverTripleBatch(merged);
    CHECK(valid, "C2: OLE-malicious triples satisfy u·v=w");
}

static void test_ole_triples_wired_into_phase5() {
    std::printf("--- C3: OLE triples drop-in for MPSVS Phase 5 inclusion ---\n");
    // Generate a large batch of OLE triples.
    size_t budget_per_row = inclusionTripleBudgetPerRow();
    size_t rows_to_test = 2;
    size_t total_triples = budget_per_row * rows_to_test + 100;

    auto t_start = std::chrono::steady_clock::now();
    auto [t0, t1] = runOleGen(total_triples, /*seed=*/0x33, /*malicious=*/false);
    auto t_end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
    std::printf("  Generated %zu OLE triples in %ld ms (%.0f triples/sec)\n",
                 total_triples, ms, 1000.0 * total_triples / std::max(1L, ms));

    auto ole_triples = mergeBatches(t0, t1);

    // Build a small shared union row (2 rows).
    oc::PRNG prng(oc::block(0xa, 0xb));
    std::vector<UnionRow> plain;
    for (int i = 0; i < 2; ++i) {
        UnionRow r{};
        r.bin = 0; r.period = 202601; r.sector = 1;
        r.live = 1; r.b_MAS = 1; r.b_DOS = 1; r.b_MOM = 1;
        r.p_MAS.v[fields::MAS_debt]   = 30000 + i * 20000;
        r.p_MAS.valid[fields::MAS_debt] = 1;
        r.p_MAS.v[fields::MAS_dserv]  = 2500 + i * 1500;
        r.p_MAS.valid[fields::MAS_dserv]= 1;
        r.p_MAS.v[fields::MAS_delq]   = 600 + i * 400;
        r.p_MAS.valid[fields::MAS_delq] = 1;
        r.p_MAS.v[fields::MAS_npl]    = 300 + i * 200;
        r.p_MAS.valid[fields::MAS_npl]  = 1;
        r.p_MAS.v[fields::MAS_unsec]  = 10000 + i * 5000;
        r.p_MAS.valid[fields::MAS_unsec]= 1;
        r.p_MAS.v[fields::MAS_stdebt] = 7500 + i * 3000;
        r.p_MAS.valid[fields::MAS_stdebt]= 1;
        r.p_MAS.g = 5000; r.p_MAS.v_g = 1;
        r.p_DOS.v[fields::DOS_income] = 60000 + i * 20000;
        r.p_DOS.valid[fields::DOS_income] = 1;
        r.p_DOS.g = 3000; r.p_DOS.v_g = 1;
        r.p_MOM.v[fields::MOM_emp] = 5 + i;
        r.p_MOM.valid[fields::MOM_emp] = 1;
        plain.push_back(r);
    }
    std::vector<SharedUnionRow> shared_in;
    for (const auto& u : plain) shared_in.push_back(shareUnionRow(2, u, prng));

    RangeConfig rc;
    rc.income = {1, 10000000ULL};
    rc.debt   = {1, 100000000ULL};
    rc.emp    = {1, 100000};

    // Run Phase 5 inclusion using the OLE-generated triples.
    auto shared_entities = computeEntityMetricsWireBatch(
        shared_in, rc, CoveragePolicy::STRICT_GATING, ole_triples);
    CHECK(shared_entities.size() == 2, "C3: 2 entity rows produced with OLE triples");

    // Reconstruct and verify against plaintext oracle.
    auto oracle = computeEntityMetrics(plain, rc, CoveragePolicy::STRICT_GATING);
    for (size_t i = 0; i < shared_entities.size(); ++i) {
        EntityMetricRow rec = reconstructEntityMetricRow(shared_entities[i]);
        for (size_t m = 0; m < kMetricCount; ++m) {
            if (rec.metrics[m].incl != oracle[i].metrics[m].incl) {
                CHECK(false, "C3: reconstructed inclusion matches oracle");
                return;
            }
        }
    }
    CHECK(true, "C3: all 9 metric inclusion bits match oracle (OLE triples work)");
}

int main() {
    std::printf("=== MPSVS Phase 17.2: OLE Beaver Triples over Sockets ===\n\n");
    std::printf("Replaces trusted-dealer with real OLE via libOTe SilentOtTriple.\n");
    std::printf("Two async parties exchange messages over coproto LocalAsyncSocket.\n\n");
    test_ole_triples_correctness_semi_honest();
    test_ole_triples_correctness_malicious();
    test_ole_triples_wired_into_phase5();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — OLE triples are drop-in for MPSVS pipeline.\n");
        std::printf("Trusted-dealer assumption REMOVED from Phase 17 stack.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
