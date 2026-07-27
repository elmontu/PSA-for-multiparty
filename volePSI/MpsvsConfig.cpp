#include "MpsvsConfig.h"

#include <sodium.h>

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Canonical text
// ---------------------------------------------------------------------------

std::string MpsvsConfig::toCanonicalText() const {
    // Fixed key ordering + fixed formatting → deterministic hash.
    std::ostringstream o;
    o.setf(std::ios::fixed);
    o.precision(9);
    o << "audit_log_path=" << audit_log_path << "\n"
      << "bin_beta=" << bin_beta << "\n"
      << "bin_cap_per_party=" << bin_cap_per_party << "\n"
      << "bin_tau_bits=" << bin_tau_bits << "\n"
      << "bucket_count=" << bucket_count << "\n"
      << "cover_k_max=" << cover_k_max << "\n"
      << "cover_k_min=" << cover_k_min << "\n"
      << "dp_contribution_clip=" << dp_contribution_clip << "\n"
      << "dp_delta=" << dp_delta << "\n"
      << "dp_rho_budget=" << dp_rho_budget << "\n"
      << "dp_rho_per_query=" << dp_rho_per_query << "\n"
      << "fp_fractional_bits=" << fp_fractional_bits << "\n"
      << "fp_guard_bits=" << fp_guard_bits << "\n"
      << "k_anon_threshold=" << k_anon_threshold << "\n"
      << "max_concurrent_sessions=" << max_concurrent_sessions << "\n"
      << "metrics_bind=" << metrics_bind << "\n";
    return o.str();
}

std::array<uint8_t, 32> MpsvsConfig::configHash() const {
    ensureSodiumInit();
    std::string text = toCanonicalText();
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(),
                        reinterpret_cast<const uint8_t*>(text.data()),
                        text.size());
    return h;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

std::string validateConfig(const MpsvsConfig& c) {
    if (!(c.dp_rho_per_query > 0.0 && c.dp_rho_per_query <= 1.0))
        return "dp_rho_per_query must be in (0, 1]";
    if (!(c.dp_rho_budget > 0.0 && c.dp_rho_budget <= 10.0))
        return "dp_rho_budget must be in (0, 10]";
    if (c.dp_rho_per_query > c.dp_rho_budget)
        return "dp_rho_per_query exceeds dp_rho_budget";
    if (!(c.dp_delta > 0.0 && c.dp_delta < 1.0))
        return "dp_delta must be in (0, 1)";
    if (!(c.dp_contribution_clip > 0.0))
        return "dp_contribution_clip must be > 0";
    if (c.k_anon_threshold == 0)
        return "k_anon_threshold must be > 0";
    if (c.cover_k_min > c.cover_k_max)
        return "cover_k_min > cover_k_max";
    if (c.cover_k_max > 10000)
        return "cover_k_max > 10000 (unreasonable)";
    if (!(c.bin_beta >= 1 && c.bin_beta <= 24))
        return "bin_beta must be in [1, 24]";
    if (!(c.bin_tau_bits >= 8 && c.bin_tau_bits <= 128))
        return "bin_tau_bits must be in [8, 128]";
    if (c.bin_cap_per_party == 0 || c.bin_cap_per_party > 65536)
        return "bin_cap_per_party must be in (0, 65536]";
    if (!(c.fp_fractional_bits >= 8 && c.fp_fractional_bits <= 96))
        return "fp_fractional_bits must be in [8, 96]";
    if (c.fp_guard_bits == 0 || c.fp_guard_bits > 32)
        return "fp_guard_bits must be in (0, 32]";
    if (c.bucket_count == 0 || c.bucket_count > 4096)
        return "bucket_count must be in (0, 4096]";
    if ((c.bucket_count & (c.bucket_count - 1)) != 0)
        return "bucket_count must be a power of 2";
    if (c.max_concurrent_sessions == 0 || c.max_concurrent_sessions > 64)
        return "max_concurrent_sessions must be in (0, 64]";
    return {};
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    return s.substr(a, b - a);
}

MpsvsConfig parseConfigText(const std::string& text,
                              const MpsvsConfig& defaults) {
    MpsvsConfig c = defaults;
    std::istringstream ss(text);
    std::string line;
    int lineno = 0;
    while (std::getline(ss, line)) {
        ++lineno;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) {
            throw std::runtime_error("MpsvsConfig line " + std::to_string(lineno) +
                                        ": missing '='");
        }
        std::string key = trim(t.substr(0, eq));
        std::string val = trim(t.substr(eq + 1));
        // Dispatch by key. Unknown keys silently ignored for forward-compat.
        try {
            if      (key == "dp_rho_per_query")   c.dp_rho_per_query   = std::stod(val);
            else if (key == "dp_rho_budget")      c.dp_rho_budget      = std::stod(val);
            else if (key == "dp_delta")           c.dp_delta           = std::stod(val);
            else if (key == "dp_contribution_clip") c.dp_contribution_clip = std::stod(val);
            else if (key == "k_anon_threshold")   c.k_anon_threshold   = static_cast<uint32_t>(std::stoul(val));
            else if (key == "cover_k_min")        c.cover_k_min        = static_cast<uint32_t>(std::stoul(val));
            else if (key == "cover_k_max")        c.cover_k_max        = static_cast<uint32_t>(std::stoul(val));
            else if (key == "bin_beta")           c.bin_beta           = static_cast<uint32_t>(std::stoul(val));
            else if (key == "bin_tau_bits")       c.bin_tau_bits       = static_cast<uint32_t>(std::stoul(val));
            else if (key == "bin_cap_per_party")  c.bin_cap_per_party  = static_cast<uint32_t>(std::stoul(val));
            else if (key == "fp_fractional_bits") c.fp_fractional_bits = static_cast<uint32_t>(std::stoul(val));
            else if (key == "fp_guard_bits")      c.fp_guard_bits      = static_cast<uint32_t>(std::stoul(val));
            else if (key == "bucket_count")       c.bucket_count       = static_cast<uint32_t>(std::stoul(val));
            else if (key == "audit_log_path")     c.audit_log_path     = val;
            else if (key == "metrics_bind")       c.metrics_bind       = val;
            else if (key == "max_concurrent_sessions")
                c.max_concurrent_sessions = static_cast<uint32_t>(std::stoul(val));
            // Unknown key: ignore silently.
        } catch (const std::exception& e) {
            throw std::runtime_error("MpsvsConfig line " + std::to_string(lineno) +
                                        " key=" + key + ": parse error: " + e.what());
        }
    }
    return c;
}

MpsvsConfig loadConfigFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("MpsvsConfig: cannot open " + path);
    std::ostringstream buf;
    buf << f.rdbuf();
    MpsvsConfig c = parseConfigText(buf.str());
    std::string err = validateConfig(c);
    if (!err.empty())
        throw std::runtime_error("MpsvsConfig: " + path + ": " + err);
    return c;
}

std::string emitConfigText(const MpsvsConfig& c) {
    // Same as canonical text but with descriptive comments.
    std::ostringstream o;
    o.setf(std::ios::fixed);
    o.precision(9);
    o << "# MPSVS Configuration — regulator sign-off required for changes\n"
      << "# Any change to this file changes configHash and appears in the\n"
      << "# audit chain via a CONFIG_LOAD entry.\n\n";
    o << "# ─── Differential privacy (Phase 12) ───\n"
      << "dp_rho_per_query = " << c.dp_rho_per_query << "\n"
      << "dp_rho_budget = " << c.dp_rho_budget << "\n"
      << "dp_delta = " << c.dp_delta << "\n"
      << "dp_contribution_clip = " << c.dp_contribution_clip << "\n\n";
    o << "# ─── k-anonymity gate (Phase 17) ───\n"
      << "k_anon_threshold = " << c.k_anon_threshold << "\n\n";
    o << "# ─── Cover firms (Phase 12+) ───\n"
      << "cover_k_min = " << c.cover_k_min << "\n"
      << "cover_k_max = " << c.cover_k_max << "\n\n";
    o << "# ─── F_PSA alignment (Phase 4) ───\n"
      << "bin_beta = " << c.bin_beta << "\n"
      << "bin_tau_bits = " << c.bin_tau_bits << "\n"
      << "bin_cap_per_party = " << c.bin_cap_per_party << "\n\n";
    o << "# ─── Fixed-point (Rev 7 §9) ───\n"
      << "fp_fractional_bits = " << c.fp_fractional_bits << "\n"
      << "fp_guard_bits = " << c.fp_guard_bits << "\n\n";
    o << "# ─── Bucketing (Phase 6 + §8) ───\n"
      << "bucket_count = " << c.bucket_count << "\n\n";
    o << "# ─── Operational ───\n"
      << "audit_log_path = " << c.audit_log_path << "\n"
      << "metrics_bind = " << c.metrics_bind << "\n"
      << "max_concurrent_sessions = " << c.max_concurrent_sessions << "\n";
    return o.str();
}

} // namespace mpsvs
} // namespace volePSI
