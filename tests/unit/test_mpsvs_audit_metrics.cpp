// MPSVS Audit Persistence + Prometheus Metrics tests.

#include "volePSI/MpsvsAuditPersist.h"
#include "volePSI/MpsvsMetrics.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static std::string tmpPath(const std::string& base) {
    return "/tmp/mpsvs_test_" + base + "_" + std::to_string(getpid()) + ".log";
}

// ==========================================================================
// Audit persistence tests
// ==========================================================================

static void test_persist_append_and_reload() {
    std::printf("--- C1: append + reopen restores chain ---\n");
    auto path = tmpPath("c1");
    std::remove(path.c_str());
    // Session 1: write 3 entries.
    {
        PersistentAuditLog log(path);
        CHECK(log.entryCount() == 0, "C1: empty on first open");
        for (int i = 0; i < 3; ++i) {
            AbortContext ctx{"agg", static_cast<uint32_t>(i), "cell_" + std::to_string(i), ""};
            log.append(AbortReason::MAC_FAIL, ctx);
        }
        CHECK(log.entryCount() == 3, "C1: 3 entries appended");
    }
    // Session 2: reopen, verify same content.
    {
        PersistentAuditLog log(path);
        CHECK(log.entryCount() == 3, "C1: 3 entries preserved across restart");
        auto chain = log.readAll();
        CHECK(chain[0].ctx.cell_key == "cell_0", "C1: entry 0 content preserved");
        CHECK(chain[2].ctx.party_id == 2, "C1: entry 2 metadata preserved");
        CHECK(log.verifyChain(), "C1: chain verifies after reload");
    }
    std::remove(path.c_str());
}

static void test_persist_detects_tampering() {
    std::printf("--- C2: on-disk tampering detected on reload ---\n");
    auto path = tmpPath("c2");
    std::remove(path.c_str());
    // Session 1: write 5 entries.
    {
        PersistentAuditLog log(path);
        for (int i = 0; i < 5; ++i) {
            AbortContext ctx{"phase", 0, "cell_" + std::to_string(i), ""};
            log.append(AbortReason::DLEQ_FAIL, ctx);
        }
    }
    // Tamper: read file, flip a bit somewhere in the middle, write back.
    std::vector<uint8_t> raw;
    {
        std::ifstream f(path, std::ios::binary);
        raw.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
    CHECK(raw.size() > 50, "C2: file has entries");
    raw[raw.size() / 2] ^= 0x01;   // flip low bit
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(raw.data()), raw.size());
    }
    // Reopen — should throw due to chain mismatch OR verifyChain fails.
    bool caught = false;
    try {
        PersistentAuditLog log2(path);
        caught = !log2.verifyChain();
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught, "C2: post-hoc file tampering detected");
    std::remove(path.c_str());
}

static void test_persist_standalone_verify() {
    std::printf("--- C3: standalone verifyPersistedAudit works ---\n");
    auto path = tmpPath("c3");
    std::remove(path.c_str());
    {
        PersistentAuditLog log(path);
        for (int i = 0; i < 4; ++i) {
            AbortContext ctx{"agg", 0, "cell", ""};
            log.append(AbortReason::MAC_FAIL, ctx);
        }
    }
    bool ok = verifyPersistedAudit(path);
    CHECK(ok, "C3: standalone verifier accepts honest file");
    std::remove(path.c_str());
}

// ==========================================================================
// Metrics tests
// ==========================================================================

static void test_metrics_counter_gauge() {
    std::printf("--- C4: counter + gauge basic API ---\n");
    auto& m = MetricsRegistry::instance();
    m.clear();
    m.incCounter("test_counter", 1);
    m.incCounter("test_counter", 3);
    CHECK(m.getCounter("test_counter") == 4.0, "C4: counter accumulates");
    m.setGauge("test_gauge", 42.5);
    CHECK(m.getGauge("test_gauge") == 42.5, "C4: gauge set/get");
    m.setGauge("test_gauge", 10.0);
    CHECK(m.getGauge("test_gauge") == 10.0, "C4: gauge overwrites");
}

static void test_metrics_histogram() {
    std::printf("--- C5: histogram observations ---\n");
    auto& m = MetricsRegistry::instance();
    m.clear();
    for (double v : {0.005, 0.05, 0.5, 5.0, 50.0, 500.0}) {
        m.observe("test_hist", v);
    }
    // Rendered format includes bucket labels + count + sum.
    std::string out = m.render();
    CHECK(out.find("test_hist_count 6") != std::string::npos,
           "C5: histogram tracks total count");
    CHECK(out.find("test_hist_sum") != std::string::npos,
           "C5: histogram tracks sum");
    CHECK(out.find("le=\"0.001\"") != std::string::npos,
           "C5: bucket labels present");
}

static void test_metrics_prometheus_render() {
    std::printf("--- C6: Prometheus text format is well-formed ---\n");
    auto& m = MetricsRegistry::instance();
    m.clear();
    m.incCounter(metrics::kMacCheckTotal, 100);
    m.incCounter(metrics::kMacFailureTotal, 3);
    m.setGauge(metrics::kRhoSpent, 0.234);
    m.observe(metrics::kPhaseDurationSeconds, 0.15);
    std::string out = m.render();
    std::printf("%s\n", out.c_str());
    CHECK(out.find("# TYPE mpsvs_mac_check_total counter") != std::string::npos,
           "C6: counter TYPE line present");
    CHECK(out.find("mpsvs_mac_check_total 100") != std::string::npos,
           "C6: counter value line present");
    CHECK(out.find("# TYPE mpsvs_rho_spent gauge") != std::string::npos,
           "C6: gauge TYPE line present");
    CHECK(out.find("mpsvs_rho_spent 0.234") != std::string::npos,
           "C6: gauge value line present");
    CHECK(out.find("# TYPE mpsvs_phase_duration_seconds histogram") != std::string::npos,
           "C6: histogram TYPE line present");
}

int main() {
    std::printf("=== MPSVS Audit Persistence + Metrics ===\n\n");
    test_persist_append_and_reload();
    test_persist_detects_tampering();
    test_persist_standalone_verify();
    test_metrics_counter_gauge();
    test_metrics_histogram();
    test_metrics_prometheus_render();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — audit persistence + Prometheus metrics operational.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
