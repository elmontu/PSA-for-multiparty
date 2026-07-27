#pragma once

// MPSVS Metrics — Prometheus-compatible counters/gauges/histograms.
//
// Exportable in the standard Prometheus text exposition format for scraping
// by prometheus-server or similar. Purely local (no HTTP server included);
// caller writes render() to their metrics endpoint.
//
// Metric taxonomy for MPSVS deployment:
//   - Counter: mpsvs_mac_check_total, mpsvs_dp_release_total, mpsvs_abort_total
//   - Gauge: mpsvs_rho_spent, mpsvs_cover_k_expected, mpsvs_active_session_count
//   - Histogram: mpsvs_phase_duration_seconds (per phase)

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace volePSI {
namespace mpsvs {

class MetricsRegistry {
public:
    static MetricsRegistry& instance();

    // Counter — monotonically increasing (per Prometheus convention).
    void incCounter(const std::string& name, double v = 1.0);
    double getCounter(const std::string& name) const;

    // Gauge — arbitrary value, may go up or down.
    void setGauge(const std::string& name, double v);
    double getGauge(const std::string& name) const;

    // Histogram — records observations into buckets.
    void observe(const std::string& name, double v);

    // Render in Prometheus text format:
    //   # TYPE name counter
    //   name value
    //   # TYPE name gauge
    //   name value
    //   # TYPE name histogram
    //   name_bucket{le="..."} count
    //   name_count total
    //   name_sum sum_of_values
    std::string render() const;

    // Reset all metrics (test-only).
    void clear();

private:
    MetricsRegistry() = default;

    struct HistogramData {
        std::vector<double> buckets = {0.001, 0.01, 0.1, 1.0, 10.0, 100.0};
        std::vector<uint64_t> counts;  // count per bucket + +inf
        uint64_t total_count = 0;
        double sum = 0.0;
        HistogramData() : counts(buckets.size() + 1, 0) {}
    };

    mutable std::mutex mu_;
    std::unordered_map<std::string, double> counters_;
    std::unordered_map<std::string, double> gauges_;
    std::unordered_map<std::string, HistogramData> histograms_;
};

// Standard MPSVS metric names (use these constants for consistency).
namespace metrics {
    constexpr const char* kMacCheckTotal        = "mpsvs_mac_check_total";
    constexpr const char* kMacFailureTotal      = "mpsvs_mac_failure_total";
    constexpr const char* kDpReleaseTotal       = "mpsvs_dp_release_total";
    constexpr const char* kAbortTotal           = "mpsvs_abort_total";
    constexpr const char* kSacrificeVerifyTotal = "mpsvs_sacrifice_verify_total";
    constexpr const char* kBitProofVerifyTotal  = "mpsvs_bit_proof_verify_total";
    constexpr const char* kShuffleNizkVerifyTotal = "mpsvs_shuffle_nizk_verify_total";
    constexpr const char* kRhoSpent             = "mpsvs_rho_spent";
    constexpr const char* kActiveSessions       = "mpsvs_active_sessions";
    constexpr const char* kCoverKExpected       = "mpsvs_cover_k_expected";
    constexpr const char* kPhaseDurationSeconds = "mpsvs_phase_duration_seconds";
    constexpr const char* kEntitiesProcessed    = "mpsvs_entities_processed_total";
}

} // namespace mpsvs
} // namespace volePSI
