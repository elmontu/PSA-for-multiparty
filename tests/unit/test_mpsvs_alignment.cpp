// Phase 4 acceptance-criteria tests: F_PSA binned alignment.
// Per docs/DEPLOYMENT_FULL_MPC.md Phase 4 + Protocol §5.

#include "volePSI/MpsvsAlignment.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <sodium.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace volePSI::mpsvs;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// Small BinParams for test speed: β=4 (16 bins), cap_P=8 (few slots).
static BinParams smallParams() {
    BinParams p;
    p.beta = 4;
    p.tau_bits = 20;
    p.cap_P = 8;
    return p;
}

// Helper: build a real row for a given (source, bin, key, period).
static Row makeRow(uint32_t source, uint64_t bin, uint64_t key,
                   uint64_t period, uint64_t sector,
                   const std::array<uint64_t, kPayloadNumFields>& vals = {}) {
    Row r{};
    r.bin = bin;
    r.source = source;
    r.key = key;
    r.memb = 1;
    r.period = period;
    r.sector = sector;
    r.payload.v = vals;
    for (auto& v : r.payload.valid) v = 1;
    return r;
}

// ---------------------------------------------------------------------------
// C1: F_PSA output shape — exactly N̂ rows regardless of input size.
// ---------------------------------------------------------------------------

static void test_output_shape() {
    oc::PRNG prng(oc::block(0, 1));
    BinParams p = smallParams();

    // 3 clients, 3 K-way common entities (bin 5, 3 unique keys).
    std::vector<Row> mas{makeRow(0, 5, 100, 20263, 42),
                          makeRow(0, 5, 200, 20263, 42),
                          makeRow(0, 5, 300, 20263, 42)};
    std::vector<Row> dos{makeRow(1, 5, 100, 20263, 42),
                          makeRow(1, 5, 200, 20263, 42),
                          makeRow(1, 5, 300, 20263, 42)};
    std::vector<Row> mom{makeRow(2, 5, 100, 20263, 42),
                          makeRow(2, 5, 200, 20263, 42),
                          makeRow(2, 5, 300, 20263, 42)};

    auto r = runFPsa(mas, dos, mom, p, prng);
    size_t expected = (1ULL << p.beta) * 3 * p.cap_P;
    CHECK(r.table.size() == expected,
          "C1: output has exactly 2^β · 3 · cap_P rows");

    auto a = auditAlignment(r);
    CHECK(a.total_rows == expected, "C1: audit confirms total row count");
    CHECK(a.live_rows == 3, "C1: exactly 3 live rows (three K-way entities)");
    CHECK(a.all_shapes_public, "C1: all row shapes are public (fixed struct)");
}

// ---------------------------------------------------------------------------
// C2: R16 defect-A closure — dummies NEVER become live.
// ---------------------------------------------------------------------------

static void test_r16_dummies_dead() {
    oc::PRNG prng(oc::block(0, 2));
    BinParams p = smallParams();

    // Pathological case: one real MAS row + all-dummy DOS/MOM (empty inputs).
    std::vector<Row> mas{makeRow(0, 3, 42, 20263, 5)};
    std::vector<Row> dos, mom;
    auto r = runFPsa(mas, dos, mom, p, prng);

    // Live rows = number of canonical rows with at least one presence bit.
    // Only ONE row (the MAS real) should be live.
    auto a = auditAlignment(r);
    CHECK(a.live_rows == 1,
          "C2 (R16): exactly one live row — the MAS real; dummies stay dead");

    // Verify that the one live row has b_MAS=1, others=0.
    UnionRow live_row{};
    bool found = false;
    for (const auto& u : r.table) if (u.live) { live_row = u; found = true; break; }
    CHECK(found && live_row.b_MAS == 1 && live_row.b_DOS == 0 && live_row.b_MOM == 0,
          "C2 (R16): live row has b_MAS=1, b_DOS=0, b_MOM=0");
}

// ---------------------------------------------------------------------------
// C3: K-way intersection — all three membership bits set on the union row.
// ---------------------------------------------------------------------------

static void test_k_way_intersection() {
    oc::PRNG prng(oc::block(0, 3));
    BinParams p = smallParams();

    // One entity: bin=2, key=99, present in all three sources.
    std::vector<Row> mas{makeRow(0, 2, 99, 20263, 10, {{100,0,0,0,0,0}})};
    std::vector<Row> dos{makeRow(1, 2, 99, 20263, 10, {{200,0,0,0,0,0}})};
    std::vector<Row> mom{makeRow(2, 2, 99, 20263, 10, {{300,0,0,0,0,0}})};

    auto r = runFPsa(mas, dos, mom, p, prng);

    // Find the one live row
    UnionRow live_row{};
    int live_cnt = 0;
    for (const auto& u : r.table) {
        if (u.live) { live_row = u; ++live_cnt; }
    }
    CHECK(live_cnt == 1, "C3: exactly one live row for K-way intersection entity");
    CHECK(live_row.b_MAS == 1 && live_row.b_DOS == 1 && live_row.b_MOM == 1,
          "C3: all three membership bits set on K-way union row");
    CHECK(live_row.p_MAS.v[0] == 100 && live_row.p_DOS.v[0] == 200 &&
          live_row.p_MOM.v[0] == 300,
          "C3: each source's payload correctly carried into the union");
    CHECK(live_row.sector == 10 && live_row.period == 20263,
          "C3: sector and period preserved");
}

// ---------------------------------------------------------------------------
// C4: Determinism — same input + same seed → equivalent output (up to shuffle).
// ---------------------------------------------------------------------------

static void test_determinism_up_to_shuffle() {
    BinParams p = smallParams();
    std::vector<Row> mas{makeRow(0, 5, 100, 20263, 42),
                          makeRow(0, 7, 200, 20263, 42)};
    std::vector<Row> dos{makeRow(1, 5, 100, 20263, 42)};
    std::vector<Row> mom{makeRow(2, 7, 200, 20263, 42)};

    oc::PRNG prngA(oc::block(0, 4));
    oc::PRNG prngB(oc::block(0, 4));   // same seed
    auto rA = runFPsa(mas, dos, mom, p, prngA);
    auto rB = runFPsa(mas, dos, mom, p, prngB);

    // Same seed → identical output
    CHECK(rA.table.size() == rB.table.size(),
          "C4: same seed → identical output size");
    bool identical = true;
    for (size_t i = 0; i < rA.table.size(); ++i) {
        if (rA.table[i].live != rB.table[i].live) { identical = false; break; }
        if (rA.table[i].b_MAS != rB.table[i].b_MAS) { identical = false; break; }
    }
    CHECK(identical, "C4: same seed → identical output");

    // Different seed → different order but same set of live rows
    oc::PRNG prngC(oc::block(0, 999));
    auto rC = runFPsa(mas, dos, mom, p, prngC);
    // Multiset of (memb bits, key, period) live rows same
    int live_A = 0, live_C = 0;
    for (const auto& u : rA.table) if (u.live) ++live_A;
    for (const auto& u : rC.table) if (u.live) ++live_C;
    CHECK(live_A == live_C && live_A == 2,
          "C4: same live-row count across shuffles (2 distinct entities)");
}

// ---------------------------------------------------------------------------
// C5: Duplicate detection at (canonical_id, period) → generic abort.
// ---------------------------------------------------------------------------

static void test_duplicate_detection() {
    BinParams p = smallParams();
    // MAS submits the same (key, period) twice — should abort.
    std::vector<Row> mas{
        makeRow(0, 3, 55, 20263, 1),
        makeRow(0, 3, 55, 20263, 1),   // duplicate
    };
    std::vector<Row> dos, mom;
    oc::PRNG prng(oc::block(0, 5));

    bool threw = false;
    try {
        runFPsa(mas, dos, mom, p, prng);
    } catch (const DuplicateEntityPeriod& e) {
        threw = true;
        // Message must not reveal which entity or which source
        std::string msg = e.what();
        // The exception message should NOT contain the key value nor sector
        CHECK(msg.find("55") == std::string::npos,
              "C5: duplicate abort message does not leak key value");
        CHECK(msg.find("20263") == std::string::npos,
              "C5: duplicate abort message does not leak period value");
    }
    CHECK(threw, "C5: duplicate (canonical_id, period) triggers abort");
}

// ---------------------------------------------------------------------------
// C6: Sector reconciliation — MAS-priority default; shared conflict flag,
//     never leaked per-entity.
// ---------------------------------------------------------------------------

static void test_sector_reconciliation() {
    BinParams p = smallParams();
    // Entity present in MAS (sector=10) and DOS (sector=99 — conflict).
    std::vector<Row> mas{makeRow(0, 4, 77, 20263, 10)};
    std::vector<Row> dos{makeRow(1, 4, 77, 20263, 99)};
    std::vector<Row> mom;
    oc::PRNG prng(oc::block(0, 6));

    auto r = runFPsa(mas, dos, mom, p, prng);
    UnionRow row{};
    for (const auto& u : r.table) if (u.live) { row = u; break; }

    CHECK(row.sector == 10,
          "C6: MAS-priority sector reconciliation (MAS=10, DOS=99 → 10 wins)");
    CHECK(row.sector_conflict == 1,
          "C6: sector_conflict flag set (shared, not per-entity revealed)");
}

// ---------------------------------------------------------------------------
// C7: SP (S1/S2) message shape is public (fixed struct).
// ---------------------------------------------------------------------------

static void test_public_shape() {
    oc::PRNG prng(oc::block(0, 7));
    BinParams p = smallParams();
    std::vector<Row> mas, dos, mom;
    // Empty inputs — everything is dummies.
    auto r = runFPsa(mas, dos, mom, p, prng);

    // Output size independent of input content
    size_t expected = (1ULL << p.beta) * 3 * p.cap_P;
    CHECK(r.table.size() == expected,
          "C7: output size = 2^β · 3 · cap_P regardless of input (empty case)");

    auto a = auditAlignment(r);
    CHECK(a.live_rows == 0, "C7: empty input → zero live rows");
    CHECK(a.canonical_rows > 0, "C7: canonical flags still populated on dummies");
    CHECK(a.all_shapes_public, "C7: fixed struct shape");
}

// ---------------------------------------------------------------------------
// C8: Bin overflow triggers RestartSession.
// ---------------------------------------------------------------------------

static void test_bin_overflow_restart() {
    BinParams p = smallParams();
    p.cap_P = 2;  // very small
    // Put 3 real rows in bin 0 for MAS — overflow (cap_P=2).
    std::vector<Row> mas{
        makeRow(0, 0, 1, 20263, 1),
        makeRow(0, 0, 2, 20263, 1),
        makeRow(0, 0, 3, 20263, 1),
    };
    std::vector<Row> dos, mom;
    oc::PRNG prng(oc::block(0, 8));

    bool threw = false;
    try {
        runFPsa(mas, dos, mom, p, prng);
    } catch (const RestartSession&) {
        threw = true;
    }
    CHECK(threw, "C8: bin overflow triggers RestartSession");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) {
        std::printf("FATAL: libsodium init failed\n");
        return 2;
    }
    std::puts("=== MpsvsAlignment — Phase 4 acceptance-criteria tests ===\n");

    test_output_shape();               std::puts("");
    test_r16_dummies_dead();           std::puts("");
    test_k_way_intersection();         std::puts("");
    test_determinism_up_to_shuffle();  std::puts("");
    test_duplicate_detection();        std::puts("");
    test_sector_reconciliation();      std::puts("");
    test_public_shape();               std::puts("");
    test_bin_overflow_restart();

    std::puts("");
    if (failures) { std::printf("== %d FAILURES ==\n", failures); return 1; }
    std::puts("ALL PASSED — Phase 4 acceptance criteria met");
    return 0;
}
