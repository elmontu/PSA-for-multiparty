#include "MpsvsMetrics.h"

#include <algorithm>
#include <sstream>

namespace volePSI {
namespace mpsvs {

MetricsRegistry& MetricsRegistry::instance() {
    static MetricsRegistry g;
    return g;
}

void MetricsRegistry::incCounter(const std::string& name, double v) {
    std::lock_guard<std::mutex> lg(mu_);
    counters_[name] += v;
}

double MetricsRegistry::getCounter(const std::string& name) const {
    std::lock_guard<std::mutex> lg(mu_);
    auto it = counters_.find(name);
    return it == counters_.end() ? 0.0 : it->second;
}

void MetricsRegistry::setGauge(const std::string& name, double v) {
    std::lock_guard<std::mutex> lg(mu_);
    gauges_[name] = v;
}

double MetricsRegistry::getGauge(const std::string& name) const {
    std::lock_guard<std::mutex> lg(mu_);
    auto it = gauges_.find(name);
    return it == gauges_.end() ? 0.0 : it->second;
}

void MetricsRegistry::observe(const std::string& name, double v) {
    std::lock_guard<std::mutex> lg(mu_);
    auto& h = histograms_[name];
    h.total_count++;
    h.sum += v;
    // Find first bucket ≥ v.
    bool placed = false;
    for (size_t i = 0; i < h.buckets.size(); ++i) {
        if (v <= h.buckets[i]) {
            h.counts[i]++;
            placed = true;
            break;
        }
    }
    if (!placed) h.counts.back()++;   // +inf bucket
}

std::string MetricsRegistry::render() const {
    std::lock_guard<std::mutex> lg(mu_);
    std::ostringstream out;
    // Sort names for deterministic output.
    std::vector<std::string> keys_c, keys_g, keys_h;
    for (const auto& kv : counters_) keys_c.push_back(kv.first);
    for (const auto& kv : gauges_)   keys_g.push_back(kv.first);
    for (const auto& kv : histograms_) keys_h.push_back(kv.first);
    std::sort(keys_c.begin(), keys_c.end());
    std::sort(keys_g.begin(), keys_g.end());
    std::sort(keys_h.begin(), keys_h.end());
    for (const auto& n : keys_c) {
        out << "# TYPE " << n << " counter\n";
        out << n << " " << counters_.at(n) << "\n";
    }
    for (const auto& n : keys_g) {
        out << "# TYPE " << n << " gauge\n";
        out << n << " " << gauges_.at(n) << "\n";
    }
    for (const auto& n : keys_h) {
        const auto& h = histograms_.at(n);
        out << "# TYPE " << n << " histogram\n";
        uint64_t cumulative = 0;
        for (size_t i = 0; i < h.buckets.size(); ++i) {
            cumulative += h.counts[i];
            out << n << "_bucket{le=\"" << h.buckets[i] << "\"} " << cumulative << "\n";
        }
        cumulative += h.counts.back();
        out << n << "_bucket{le=\"+Inf\"} " << cumulative << "\n";
        out << n << "_count " << h.total_count << "\n";
        out << n << "_sum " << h.sum << "\n";
    }
    return out.str();
}

void MetricsRegistry::clear() {
    std::lock_guard<std::mutex> lg(mu_);
    counters_.clear();
    gauges_.clear();
    histograms_.clear();
}

} // namespace mpsvs
} // namespace volePSI
