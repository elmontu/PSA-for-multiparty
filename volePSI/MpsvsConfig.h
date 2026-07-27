#pragma once

// MPSVS Configuration — runtime-loadable parameters with validation.
//
// Purpose: eliminates hardcoded protocol parameters scattered across the
// codebase. Regulator-controlled operational parameters (ρ budget, k-anon
// threshold, cover range, contribution clip, ...) load from a config file
// at protocol start; validation ensures they fall in safe bounds; change
// control writes a hash of the loaded config to the audit chain for
// tamper-evident record of "which config produced which release."
//
// Format: simple key=value, one per line. Comments start with '#'.
// Deliberately avoids yaml-cpp / json dependency for zero-dep parsing.
// Example:
//     # DP budget per query (zCDP ρ). Must be > 0 and <= 1.
//     dp_rho_per_query = 0.1
//     # k-anonymity gate threshold (Rev 7 §12).
//     k_anon_threshold = 5
//     # Cover-firm range (must satisfy 0 <= K_min <= K_max <= 10000).
//     cover_k_min = 3
//     cover_k_max = 15
//     ...
//
// All fields are optional in the file; missing fields use defaults.

#include "MpsvsProdHygiene.h"

#include <array>
#include <cstdint>
#include <string>

namespace volePSI {
namespace mpsvs {

struct MpsvsConfig {
    // -----------------------------------------------------------------------
    // Differential privacy (Phase 12)
    // -----------------------------------------------------------------------
    double   dp_rho_per_query   = 0.1;   // zCDP ρ per release; in (0, 1]
    double   dp_rho_budget      = 3.0;   // total ρ over full lifetime
    double   dp_delta           = 1e-6;  // δ for (ε, δ)-DP conversion
    double   dp_contribution_clip = 1.0e6;  // C_max for sum queries

    // -----------------------------------------------------------------------
    // k-anonymity gate (Phase 17)
    // -----------------------------------------------------------------------
    uint32_t k_anon_threshold   = 5;     // suppress cells with n_valid < k

    // -----------------------------------------------------------------------
    // Cover firms (Phase 12+)
    // -----------------------------------------------------------------------
    uint32_t cover_k_min        = 3;
    uint32_t cover_k_max        = 15;

    // -----------------------------------------------------------------------
    // F_PSA alignment (Phase 4)
    // -----------------------------------------------------------------------
    uint32_t bin_beta           = 13;    // 2^β bins
    uint32_t bin_tau_bits       = 71;    // key width
    uint32_t bin_cap_per_party  = 256;   // cap_P per bin

    // -----------------------------------------------------------------------
    // Fixed-point convention (Rev 7 §9)
    // -----------------------------------------------------------------------
    uint32_t fp_fractional_bits = 40;    // f in x·2^f encoding
    uint32_t fp_guard_bits      = 8;

    // -----------------------------------------------------------------------
    // Bucketing (Phase 6 + §8)
    // -----------------------------------------------------------------------
    uint32_t bucket_count       = 128;   // B; Rev 7 R27 break-even threshold

    // -----------------------------------------------------------------------
    // Operational
    // -----------------------------------------------------------------------
    std::string audit_log_path  = "/var/log/mpsvs_audit.log";
    std::string metrics_bind    = "0.0.0.0:9090";
    uint32_t    max_concurrent_sessions = 4;

    // Compute a deterministic hash of the config (for change-control log).
    // SHA-256 over the canonical key=value serialisation.
    std::array<uint8_t, 32> configHash() const;

    // Render config as canonical key=value text (for logging + hashing).
    std::string toCanonicalText() const;
};

// Validate config bounds. Returns error message on first violation; empty
// string on success.
std::string validateConfig(const MpsvsConfig& cfg);

// Parse a config from key=value text. Missing keys use defaults from the
// input `defaults`. Unknown keys are ignored with no error (forward-compat).
// Throws std::runtime_error on malformed line (e.g., "key without =").
MpsvsConfig parseConfigText(const std::string& text,
                              const MpsvsConfig& defaults = MpsvsConfig{});

// Load a config from a file. Returns MpsvsConfig on success; throws on any
// read error or validation failure.
MpsvsConfig loadConfigFile(const std::string& path);

// Emit a canonical config text (all fields, sorted). Useful for generating
// sample config files or dumping current config for audit.
std::string emitConfigText(const MpsvsConfig& cfg);

} // namespace mpsvs
} // namespace volePSI
