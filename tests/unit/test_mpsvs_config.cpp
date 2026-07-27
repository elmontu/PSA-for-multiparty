// MPSVS Config tests: parse, validate, canonical text, hash stability.

#include "volePSI/MpsvsConfig.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ==========================================================================
// Defaults + validation
// ==========================================================================

static void test_defaults_validate() {
    std::printf("--- C1: default config passes validation ---\n");
    MpsvsConfig c;
    std::string err = validateConfig(c);
    CHECK(err.empty(), "C1: defaults pass validation");
    if (!err.empty()) std::printf("     err: %s\n", err.c_str());
}

static void test_invalid_rho() {
    std::printf("--- C2: invalid dp_rho_per_query rejected ---\n");
    MpsvsConfig c;
    c.dp_rho_per_query = 0.0;
    CHECK(!validateConfig(c).empty(), "C2a: rho=0 rejected");
    c.dp_rho_per_query = 2.0;
    CHECK(!validateConfig(c).empty(), "C2b: rho=2 rejected (> 1)");
    c.dp_rho_per_query = -0.1;
    CHECK(!validateConfig(c).empty(), "C2c: rho=-0.1 rejected");
}

static void test_rho_exceeds_budget() {
    std::printf("--- C3: dp_rho_per_query > dp_rho_budget rejected ---\n");
    MpsvsConfig c;
    c.dp_rho_budget = 0.5;
    c.dp_rho_per_query = 0.9;
    CHECK(!validateConfig(c).empty(), "C3: per-query > budget rejected");
}

static void test_cover_range() {
    std::printf("--- C4: cover_k_min > cover_k_max rejected ---\n");
    MpsvsConfig c;
    c.cover_k_min = 20;
    c.cover_k_max = 5;
    CHECK(!validateConfig(c).empty(), "C4: inverted cover range rejected");
}

static void test_bucket_power_of_two() {
    std::printf("--- C5: bucket_count must be power of 2 ---\n");
    MpsvsConfig c;
    c.bucket_count = 100;   // not a power of 2
    CHECK(!validateConfig(c).empty(), "C5a: bucket_count=100 rejected");
    c.bucket_count = 128;
    CHECK(validateConfig(c).empty(), "C5b: bucket_count=128 accepted");
    c.bucket_count = 256;
    CHECK(validateConfig(c).empty(), "C5c: bucket_count=256 accepted");
}

static void test_bin_beta_range() {
    std::printf("--- C6: bin_beta bounds enforced ---\n");
    MpsvsConfig c;
    c.bin_beta = 0;
    CHECK(!validateConfig(c).empty(), "C6a: beta=0 rejected");
    c.bin_beta = 100;
    CHECK(!validateConfig(c).empty(), "C6b: beta=100 rejected");
    c.bin_beta = 13;
    CHECK(validateConfig(c).empty(), "C6c: beta=13 (default) accepted");
}

static void test_kanon_zero_rejected() {
    std::printf("--- C7: k_anon_threshold=0 rejected ---\n");
    MpsvsConfig c;
    c.k_anon_threshold = 0;
    CHECK(!validateConfig(c).empty(), "C7: k=0 rejected");
}

// ==========================================================================
// Parser tests
// ==========================================================================

static void test_parse_empty_uses_defaults() {
    std::printf("--- C8: empty text yields defaults ---\n");
    auto c = parseConfigText("");
    MpsvsConfig def;
    CHECK(c.dp_rho_per_query == def.dp_rho_per_query, "C8a: rho default");
    CHECK(c.k_anon_threshold == def.k_anon_threshold,   "C8b: k default");
}

static void test_parse_comments_and_blank_lines() {
    std::printf("--- C9: comments and blank lines ignored ---\n");
    std::string text =
        "# this is a comment\n"
        "\n"
        "   # indented comment\n"
        "dp_rho_per_query = 0.05\n"
        "\n";
    auto c = parseConfigText(text);
    CHECK(c.dp_rho_per_query == 0.05, "C9: rho parsed to 0.05");
}

static void test_parse_whitespace_tolerant() {
    std::printf("--- C10: whitespace around key/value ---\n");
    auto c = parseConfigText("   k_anon_threshold   =    10   \n");
    CHECK(c.k_anon_threshold == 10u, "C10: k parsed to 10 with surrounding whitespace");
}

static void test_parse_missing_equals_rejected() {
    std::printf("--- C11: line without '=' throws ---\n");
    bool threw = false;
    try {
        (void)parseConfigText("dp_rho_per_query 0.1\n");
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C11: malformed line throws");
}

static void test_parse_unknown_key_ignored() {
    std::printf("--- C12: unknown keys silently ignored (forward-compat) ---\n");
    bool threw = false;
    try {
        auto c = parseConfigText("future_new_field = 42\ndp_rho_per_query = 0.2\n");
        CHECK(c.dp_rho_per_query == 0.2, "C12: known field parsed while unknown ignored");
    } catch (const std::exception&) { threw = true; }
    CHECK(!threw, "C12: unknown key does not throw");
}

static void test_parse_full_config() {
    std::printf("--- C13: full multi-field config parses correctly ---\n");
    std::string text =
        "dp_rho_per_query = 0.25\n"
        "dp_rho_budget = 2.5\n"
        "dp_contribution_clip = 500000\n"
        "k_anon_threshold = 7\n"
        "cover_k_min = 4\n"
        "cover_k_max = 20\n"
        "bin_beta = 15\n"
        "bin_cap_per_party = 512\n"
        "bucket_count = 256\n"
        "fp_fractional_bits = 48\n"
        "audit_log_path = /tmp/test.log\n"
        "max_concurrent_sessions = 8\n";
    auto c = parseConfigText(text);
    CHECK(c.dp_rho_per_query      == 0.25,        "C13a: rho");
    CHECK(c.dp_rho_budget         == 2.5,         "C13b: budget");
    CHECK(c.dp_contribution_clip  == 500000.0,    "C13c: clip");
    CHECK(c.k_anon_threshold      == 7u,          "C13d: k_anon");
    CHECK(c.cover_k_min           == 4u,          "C13e: cover_min");
    CHECK(c.cover_k_max           == 20u,         "C13f: cover_max");
    CHECK(c.bin_beta              == 15u,         "C13g: beta");
    CHECK(c.bin_cap_per_party     == 512u,        "C13h: cap_P");
    CHECK(c.bucket_count          == 256u,        "C13i: bucket");
    CHECK(c.fp_fractional_bits    == 48u,         "C13j: fp");
    CHECK(c.audit_log_path        == "/tmp/test.log", "C13k: log path");
    CHECK(c.max_concurrent_sessions == 8u,        "C13l: sessions");
}

// ==========================================================================
// Canonical text + hash
// ==========================================================================

static void test_canonical_text_deterministic() {
    std::printf("--- C14: canonical text is deterministic ---\n");
    MpsvsConfig a, b;
    CHECK(a.toCanonicalText() == b.toCanonicalText(),
          "C14: two default configs produce identical canonical text");
}

static void test_hash_matches_for_equal_configs() {
    std::printf("--- C15: configHash matches for equal configs ---\n");
    MpsvsConfig a, b;
    b.k_anon_threshold = a.k_anon_threshold;
    auto ha = a.configHash();
    auto hb = b.configHash();
    CHECK(std::memcmp(ha.data(), hb.data(), 32) == 0,
          "C15: identical configs have identical SHA-256");
}

static void test_hash_differs_after_change() {
    std::printf("--- C16: configHash changes when any field changes ---\n");
    MpsvsConfig a;
    auto h_before = a.configHash();
    a.k_anon_threshold = a.k_anon_threshold + 1;
    auto h_after = a.configHash();
    CHECK(std::memcmp(h_before.data(), h_after.data(), 32) != 0,
          "C16: hash flips after changing k_anon_threshold");

    MpsvsConfig b;
    auto h_b_before = b.configHash();
    b.dp_rho_per_query = b.dp_rho_per_query + 0.01;
    auto h_b_after = b.configHash();
    CHECK(std::memcmp(h_b_before.data(), h_b_after.data(), 32) != 0,
          "C16b: hash flips after changing dp_rho_per_query");
}

static void test_round_trip_parse_emit() {
    std::printf("--- C17: emit → parse round-trip preserves hash ---\n");
    MpsvsConfig a;
    a.k_anon_threshold = 12;
    a.dp_rho_per_query = 0.15;
    a.bucket_count = 512;
    a.audit_log_path = "/tmp/roundtrip.log";
    std::string text = emitConfigText(a);
    MpsvsConfig b = parseConfigText(text);
    auto ha = a.configHash();
    auto hb = b.configHash();
    CHECK(std::memcmp(ha.data(), hb.data(), 32) == 0,
          "C17: parsed config has same hash as original");
    CHECK(b.k_anon_threshold == 12u,       "C17a: k_anon survives");
    CHECK(b.dp_rho_per_query == 0.15,       "C17b: rho survives");
    CHECK(b.bucket_count     == 512u,       "C17c: bucket survives");
    CHECK(b.audit_log_path   == "/tmp/roundtrip.log", "C17d: log path survives");
}

// ==========================================================================
// File loading
// ==========================================================================

static void test_load_missing_file_throws() {
    std::printf("--- C18: loading nonexistent file throws ---\n");
    bool threw = false;
    try {
        (void)loadConfigFile("/nonexistent/path/to/config.txt");
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C18: missing file throws");
}

static void test_load_invalid_file_throws() {
    std::printf("--- C19: file with invalid config values throws ---\n");
    const char* path = "/tmp/mpsvs_config_invalid_test.txt";
    FILE* f = std::fopen(path, "w");
    std::fprintf(f, "dp_rho_per_query = 5.0\n");   // out of range
    std::fclose(f);
    bool threw = false;
    try {
        (void)loadConfigFile(path);
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C19: out-of-range values cause validation failure");
    std::remove(path);
}

static void test_load_valid_file() {
    std::printf("--- C20: valid file loads correctly ---\n");
    const char* path = "/tmp/mpsvs_config_valid_test.txt";
    FILE* f = std::fopen(path, "w");
    std::fprintf(f, "# test config\n");
    std::fprintf(f, "dp_rho_per_query = 0.2\n");
    std::fprintf(f, "k_anon_threshold = 10\n");
    std::fprintf(f, "cover_k_min = 5\n");
    std::fprintf(f, "cover_k_max = 25\n");
    std::fclose(f);
    MpsvsConfig c = loadConfigFile(path);
    CHECK(c.dp_rho_per_query == 0.2,  "C20a: rho loaded");
    CHECK(c.k_anon_threshold == 10u,   "C20b: k loaded");
    CHECK(c.cover_k_min == 5u,         "C20c: cover_min loaded");
    CHECK(c.cover_k_max == 25u,        "C20d: cover_max loaded");
    std::remove(path);
}

int main() {
    std::printf("=== MPSVS Config tests ===\n\n");
    test_defaults_validate();
    test_invalid_rho();
    test_rho_exceeds_budget();
    test_cover_range();
    test_bucket_power_of_two();
    test_bin_beta_range();
    test_kanon_zero_rejected();
    test_parse_empty_uses_defaults();
    test_parse_comments_and_blank_lines();
    test_parse_whitespace_tolerant();
    test_parse_missing_equals_rejected();
    test_parse_unknown_key_ignored();
    test_parse_full_config();
    test_canonical_text_deterministic();
    test_hash_matches_for_equal_configs();
    test_hash_differs_after_change();
    test_round_trip_parse_emit();
    test_load_missing_file_throws();
    test_load_invalid_file_throws();
    test_load_valid_file();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — config parses, validates, hashes deterministically.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
