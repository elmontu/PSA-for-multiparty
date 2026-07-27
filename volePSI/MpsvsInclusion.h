#pragma once

// MPSVS Phase 5 — Validity, missingness, and inclusion bits.
//
// Per docs/PROTOCOL.md Phase 5 (spec §12) + Protocol §7.
//
// Takes the F_PSA union output (Phase 4 UnionRow) and produces per-ratio
// inclusion bits + entity-level (num, den) pairs for downstream ranking
// (Phase 8) and aggregation (Phase 11).
//
// Inclusion masks (Protocol §7):
//   incl_DTI  = alignment · b_MAS · b_DOS · v_debt · v_income · [[income∈rng]]
//   incl_DSI  = alignment · b_MAS · b_DOS · v_dserv · v_income · [[income∈rng]]
//   incl_DEmp = alignment · b_MAS · b_MOM · v_debt · v_emp · [[emp∈rng]]
//   incl_IPW  = alignment · b_DOS · b_MOM · v_income · v_emp · [[emp∈rng]]
//   incl_Delq = alignment · b_MAS · v_delq · v_debt · [[debt∈rng]]
//   incl_NPL  = alignment · b_MAS · v_npl · v_debt · [[debt∈rng]]
//   incl_gap  = alignment · b_MAS · b_DOS · v_gdebt · v_gincome
//   ... (unsecured, short-term shares analogous) ...
//   incl_vuln = live AND CoveragePredicate_Φ({avail_c})    (Rev 7 R25)
//
// Rev 7 R25 coverage policy for vuln score:
//   STRICT_GATING    : all components must be available
//   RENORMALISED     : any component available; weights redistributed
//
// Invariants (Phase 5 acceptance criteria):
//   * Every ratio has a per-entity inclusion bit produced (never revealed).
//   * Missing / range-invalid values → incl=0; NEVER zero substitution of
//     the underlying (num, den) that gates on the bit.
//   * Downstream aggregate is `Σ incl · num` and `Σ incl · den` — never
//     an unmasked sum over the whole table.

#include "MpsvsAlignment.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Ratio metric registry
// ---------------------------------------------------------------------------

enum class Metric : uint8_t {
    DTI,           // debt / income
    DSI,           // debt_service / income
    DEmp,          // debt / employment
    IPW,           // income / employment (per worker; inverse: high=less vuln)
    Delq,          // delinquent / debt
    NPL,           // nonperforming / debt
    UnsecShare,    // unsecured / debt
    StDebtShare,   // short-term debt / debt
    Gap,           // g_debt − g_income (from Rev 7 §4.1 local growth)
    _COUNT
};

constexpr size_t kMetricCount = static_cast<size_t>(Metric::_COUNT);

const char* metricName(Metric m);

// Payload field indices (matches MpsvsAlignment PayloadPerSource.v layout).
// Rev 7 §5.2 payload schemas:
//   MAS: [debt, dserv, delq, npl, unsec, stdebt]  (indices 0..5)
//   DOS: [income, revenue, surplus, _, _, _]       (indices 0..2)
//   MOM: [emp, lab, wap, unemp, retr, vac]          (indices 0..5)
namespace fields {
    // MAS
    constexpr size_t MAS_debt   = 0;
    constexpr size_t MAS_dserv  = 1;
    constexpr size_t MAS_delq   = 2;
    constexpr size_t MAS_npl    = 3;
    constexpr size_t MAS_unsec  = 4;
    constexpr size_t MAS_stdebt = 5;
    // DOS
    constexpr size_t DOS_income = 0;
    constexpr size_t DOS_rev    = 1;
    constexpr size_t DOS_surp   = 2;
    // MOM
    constexpr size_t MOM_emp    = 0;
    constexpr size_t MOM_lab    = 1;
    constexpr size_t MOM_wap    = 2;
    constexpr size_t MOM_unemp  = 3;
    constexpr size_t MOM_retr   = 4;
    constexpr size_t MOM_vac    = 5;
}

// ---------------------------------------------------------------------------
// Range configuration (per attribute; Rev 7 §12 range-check gate)
// ---------------------------------------------------------------------------

struct AttrRange {
    uint64_t min_incl = 1;                     // exclusive of zero + negatives
    uint64_t max_incl = 100'000'000'000'000ULL; // SGD 1T cents typical cap
};

struct RangeConfig {
    // Denominator range checks (needed for ratio inclusion).
    AttrRange income{1, 100'000'000'000'000ULL};
    AttrRange emp{1, 10'000'000ULL};
    AttrRange debt{1, 100'000'000'000'000ULL};
    // For growth we already clamped ±G at Phase 1 §4.1; no in-Phase-5 gate needed.
};

// ---------------------------------------------------------------------------
// Coverage policy for vuln inclusion (Rev 7 R25 / §8.3)
// ---------------------------------------------------------------------------

enum class CoveragePolicy : uint8_t {
    STRICT_GATING,        // all core components must be available
    RENORMALISED_WEIGHTS, // any component available; weights redistributed
};

// Which metrics constitute the "core" set for vuln coverage decisions.
// Provisional: DTI + DSI + Delq + NPL as required core.
constexpr std::array<Metric, 4> kVulnCoreMetrics = {
    Metric::DTI, Metric::DSI, Metric::Delq, Metric::NPL
};

// ---------------------------------------------------------------------------
// EntityMetricRow — Phase 5 output
// ---------------------------------------------------------------------------

// Per-row, per-metric num/den pair + inclusion bit. Downstream Phase 8 sorts
// by (popkey, invalid, ratio_key) using these; Phase 10-11 aggregate as
// Σ incl·num and Σ incl·den.
struct MetricPair {
    uint64_t num = 0;
    uint64_t den = 0;
    uint8_t  incl = 0;   // secret bit; 1 iff the ratio is included for this entity
};

struct EntityMetricRow {
    // Carry-through public bookkeeping.
    uint64_t bin = 0;

    // Carry-through from UnionRow.
    uint64_t period = 0;
    uint64_t sector = 0;
    uint8_t  sector_conflict = 0;
    uint8_t  live = 0;
    uint8_t  b_MAS = 0;
    uint8_t  b_DOS = 0;
    uint8_t  b_MOM = 0;

    // Per-metric (num, den, incl). Fixed-size array indexed by Metric enum.
    std::array<MetricPair, kMetricCount> metrics{};

    // Vuln coverage (Rev 7 §8.3):
    //   avail_core = number of core metrics with incl=1 (from kVulnCoreMetrics).
    //   incl_vuln  = 1 iff the coverage policy admits this row.
    uint8_t  avail_core_count = 0;
    uint8_t  incl_vuln = 0;
};

// ---------------------------------------------------------------------------
// Phase 5 pipeline
// ---------------------------------------------------------------------------

// Compute EntityMetricRow for every UnionRow. `alignment_bit` is derived
// per Rev 7 Phase 4 output: rows with live=1 are the aligned-and-real ones.
std::vector<EntityMetricRow>
computeEntityMetrics(const std::vector<UnionRow>& union_rows,
                     const RangeConfig& rc,
                     CoveragePolicy vuln_policy);

// Aggregate helper: sum incl·num and incl·den per metric across the whole
// input (no per-sector grouping — that's Phase 10). Useful for Phase 5 tests
// and for smoke-level validation.
struct MetricAggregate {
    uint64_t sum_num = 0;
    uint64_t sum_den = 0;
    uint64_t n_valid = 0;   // count of incl=1 rows
};

std::array<MetricAggregate, kMetricCount>
aggregateOverAll(const std::vector<EntityMetricRow>& rows);

// ---------------------------------------------------------------------------
// Audit — Phase 5 acceptance criteria
// ---------------------------------------------------------------------------

struct InclusionAudit {
    // For every metric: count of rows where inclusion=1.
    std::array<size_t, kMetricCount> incl_count_by_metric{};
    // For every metric: rows where memb OK but validity/range failed
    // (verifies non-zero-substitution invariant).
    std::array<size_t, kMetricCount> memb_ok_but_incl_zero{};
    // Vuln coverage summary.
    size_t vuln_incl_count = 0;
    size_t vuln_live_but_incl_zero = 0;
};

InclusionAudit auditInclusion(const std::vector<EntityMetricRow>& rows);

} // namespace mpsvs
} // namespace volePSI
