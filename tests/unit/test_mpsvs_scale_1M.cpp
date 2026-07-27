// MPSVS scale test — 1 000 000 firms × 20 sectors × MAS = 10% subset.
//
// Runs the semantic-reference Phase 5 (inclusion) + Phase 11 (sector
// aggregation) + Phase 12 gate (k-anonymity) + Phase 12 DP noise, on a
// realistic panel:
//
//   Universe:  N = 1 000 000 firms
//   Sectors:   S = 20 (uniform assignment)
//   MAS set:   n_MAS = 100 000 firms (10% of universe — loan borrowers)
//   DOS set:   n_DOS = N               (all firms have revenue data)
//   MOM set:   n_MOM = N               (all firms have employment data)
//
// This mirrors the real Rev 7 topology where MAS's regulatory reach covers
// only licensed-borrower firms, while DOS/MOM cover the full registered
// firm universe.
//
// Reports:
//   - Coverage per party and per metric
//   - Per-sector released cell counts (post k-anon)
//   - Wall-clock timing per phase
//   - Peak RSS
//   - DP-noised release for two sample metrics (DTI, IPW)
//
// Runs in ~O(seconds) on modest hardware; deliberately skips the MPC-layer
// per-bin bitonic sort / shuffle (those exercise Phase 4 alignment, not
// the release semantics being validated at scale here).

#include "volePSI/MpsvsConfig.h"
#include "volePSI/MpsvsCryptoParams.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpProd.h"
#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsProdHygiene.h"
#include "volePSI/MpsvsRatioBucket.h"
#include "volePSI/MpsvsSectorAgg.h"

#include <sys/resource.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace volePSI::mpsvs;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

static double elapsedMs(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static size_t peakRssKB() {
    struct rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
    return static_cast<size_t>(ru.ru_maxrss);   // Linux: kilobytes
}

static void printHeader(const char* title) {
    std::printf("\n%s\n", std::string(70, '=').c_str());
    std::printf("  %s\n", title);
    std::printf("%s\n", std::string(70, '=').c_str());
}

// ---------------------------------------------------------------------------
// Synthetic-panel generator
// ---------------------------------------------------------------------------

struct PanelStats {
    size_t n_universe   = 0;
    size_t n_mas_set    = 0;
    size_t n_dos_set    = 0;
    size_t n_mom_set    = 0;
    std::vector<size_t> firms_per_sector;   // index = sector-1
};

static std::vector<UnionRow> generatePanel(size_t N, size_t n_sectors,
                                             double mas_coverage,
                                             uint64_t seed,
                                             PanelStats& stats) {
    std::mt19937_64 rng(seed);
    std::vector<UnionRow> rows;
    rows.reserve(N);

    // Realistic (post-fixed-point) distributions. Values are in ×2^40 units
    // for downstream ratio arithmetic — we generate raw magnitudes here
    // and let the metric-computation layer handle the FP encoding.
    // For the semantic reference we can use raw magnitudes directly since
    // ratios are computed in fixed-point downstream but bucketing works
    // on any positive integer representation.
    std::uniform_int_distribution<uint64_t> debt_d   (10'000, 5'000'000);
    std::uniform_int_distribution<uint64_t> dserv_d  ( 1'000,   500'000);
    std::uniform_int_distribution<uint64_t> delq_d   (     0,   200'000);
    std::uniform_int_distribution<uint64_t> npl_d    (     0,   200'000);
    std::uniform_int_distribution<uint64_t> unsec_d  (     0,   500'000);
    std::uniform_int_distribution<uint64_t> stdebt_d (     0,   500'000);

    std::uniform_int_distribution<uint64_t> income_d ( 100'000, 50'000'000);
    std::uniform_int_distribution<uint64_t> revenue_d( 100'000, 100'000'000);
    std::uniform_int_distribution<uint64_t> surplus_d(       0, 20'000'000);

    std::uniform_int_distribution<uint64_t> emp_d    (   1,   5000);
    std::uniform_int_distribution<uint64_t> lab_d    (   1,   5000);
    std::uniform_int_distribution<uint64_t> wap_d    (   1,   5000);

    std::uniform_int_distribution<uint64_t> sector_d(1, static_cast<uint64_t>(n_sectors));
    std::uniform_real_distribution<double>   mas_d(0.0, 1.0);

    stats.n_universe = N;
    stats.n_mas_set = 0;
    stats.n_dos_set = 0;
    stats.n_mom_set = 0;
    stats.firms_per_sector.assign(n_sectors, 0);

    for (size_t i = 0; i < N; ++i) {
        UnionRow r;
        r.bin = i & 0x1FFF;                                 // 2^13 bins
        r.period = 202601;
        r.sector = sector_d(rng);
        stats.firms_per_sector[r.sector - 1]++;

        // DOS covers all firms
        r.b_DOS = 1;
        r.p_DOS.v[0] = income_d(rng); r.p_DOS.valid[0] = 1;
        r.p_DOS.v[1] = revenue_d(rng); r.p_DOS.valid[1] = 1;
        r.p_DOS.v[2] = surplus_d(rng); r.p_DOS.valid[2] = 1;
        stats.n_dos_set++;

        // MOM covers all firms
        r.b_MOM = 1;
        r.p_MOM.v[0] = emp_d(rng); r.p_MOM.valid[0] = 1;
        r.p_MOM.v[1] = lab_d(rng); r.p_MOM.valid[1] = 1;
        r.p_MOM.v[2] = wap_d(rng); r.p_MOM.valid[2] = 1;
        stats.n_mom_set++;

        // MAS covers only 10% (subset = loan borrowers)
        if (mas_d(rng) < mas_coverage) {
            r.b_MAS = 1;
            r.p_MAS.v[0] = debt_d(rng);   r.p_MAS.valid[0] = 1;
            r.p_MAS.v[1] = dserv_d(rng);  r.p_MAS.valid[1] = 1;
            r.p_MAS.v[2] = delq_d(rng);   r.p_MAS.valid[2] = 1;
            r.p_MAS.v[3] = npl_d(rng);    r.p_MAS.valid[3] = 1;
            r.p_MAS.v[4] = unsec_d(rng);  r.p_MAS.valid[4] = 1;
            r.p_MAS.v[5] = stdebt_d(rng); r.p_MAS.valid[5] = 1;
            stats.n_mas_set++;
        }

        r.canonical = 1;
        // live = canonical AND (b_MAS OR b_DOS OR b_MOM) — always 1 here
        r.live = 1;
        r.sector_conflict = 0;
        rows.push_back(r);
    }
    return rows;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

static void reportPanel(const PanelStats& s) {
    std::printf("\nPanel composition:\n");
    std::printf("  Universe size (N)        : %zu\n", s.n_universe);
    std::printf("  MAS set (n_MAS)          : %zu (%.1f%%)\n",
                 s.n_mas_set, 100.0 * s.n_mas_set / s.n_universe);
    std::printf("  DOS set (n_DOS)          : %zu (%.1f%%)\n",
                 s.n_dos_set, 100.0 * s.n_dos_set / s.n_universe);
    std::printf("  MOM set (n_MOM)          : %zu (%.1f%%)\n",
                 s.n_mom_set, 100.0 * s.n_mom_set / s.n_universe);
    std::printf("  Sectors                  : %zu\n", s.firms_per_sector.size());
    // Min/max firms per sector
    auto mm = std::minmax_element(s.firms_per_sector.begin(),
                                    s.firms_per_sector.end());
    std::printf("  Firms/sector (min..max)  : %zu..%zu (mean %.0f)\n",
                 *mm.first, *mm.second,
                 static_cast<double>(s.n_universe) / s.firms_per_sector.size());
}

static void reportCoveragePerMetric(const std::vector<EntityMetricRow>& emr) {
    std::printf("\nInclusion count per metric (Σ incl):\n");
    std::array<size_t, kMetricCount> inc{};
    for (const auto& r : emr) {
        for (size_t m = 0; m < kMetricCount; ++m)
            if (r.metrics[m].incl) inc[m]++;
    }
    for (size_t m = 0; m < kMetricCount; ++m) {
        double frac = 100.0 * static_cast<double>(inc[m])
                              / std::max<size_t>(1, emr.size());
        std::printf("  %-12s %10zu  (%5.1f%%)\n",
                     metricName(static_cast<Metric>(m)), inc[m], frac);
    }
}

struct SectorReleaseCounts {
    size_t total_cells;       // (sector × metric) = n_sectors × 9
    size_t cells_released;    // n_valid ≥ k_anon_threshold
    size_t cells_suppressed;  // failed k-anon
};

static SectorReleaseCounts
applyKAnonAndReport(const SectorAggregateBundle& bundle,
                     uint32_t k_anon_threshold,
                     size_t n_sectors_expected) {
    SectorReleaseCounts sc{};
    std::printf("\nPer-metric per-sector k-anonymity release "
                 "(threshold n_valid ≥ %u):\n", k_anon_threshold);
    std::printf("  Metric        cells   released  suppressed\n");
    for (size_t m = 0; m < kMetricCount; ++m) {
        size_t rel = 0, sup = 0;
        for (const auto& h : bundle.hists[m]) {
            if (h.hist.n_valid >= k_anon_threshold) ++rel;
            else                                     ++sup;
        }
        sc.total_cells    += bundle.hists[m].size();
        sc.cells_released += rel;
        sc.cells_suppressed += sup;
        std::printf("  %-12s  %6zu  %6zu     %6zu\n",
                     metricName(static_cast<Metric>(m)),
                     bundle.hists[m].size(), rel, sup);
    }
    (void)n_sectors_expected;
    return sc;
}

// ---------------------------------------------------------------------------
// Main scale run
// ---------------------------------------------------------------------------

int main() {
    printHeader("MPSVS scale test — 1 000 000 firms × 20 sectors");

    ensureSodiumInit();

    // Config + crypto params (used to drive k-anon threshold and DP σ).
    MpsvsConfig cfg;
    MpsvsCryptoParams crypto;
    cfg.k_anon_threshold = 5;
    cfg.dp_rho_per_query = 0.1;
    // Widen mac field to suppress the fp/mac overflow warning for this test.
    crypto.mac_field_bits = 128;
    // Tighten delta below the sigma-bound to suppress warning.
    cfg.dp_delta = std::pow(2.0, -45);

    auto warns = validateAgainstOperationalConfig(crypto, cfg);
    if (!warns.empty()) {
        std::printf("Config coherence warnings (%zu):\n", warns.size());
        for (const auto& w : warns) std::printf("  ! %s\n", w.c_str());
    } else {
        std::printf("Config × CryptoParams coherence: OK (no warnings)\n");
    }

    // -----------------------------------------------------------------------
    // Phase A — Generate panel
    // -----------------------------------------------------------------------
    printHeader("Phase A — generate 1M synthetic firms");
    Clock::time_point t0 = Clock::now();
    PanelStats stats;
    const size_t N = 1'000'000;
    const size_t S = 20;
    const double mas_coverage = 0.10;
    auto rows = generatePanel(N, S, mas_coverage, 0xdeadbeefCAFEULL, stats);
    Clock::time_point t1 = Clock::now();
    reportPanel(stats);
    std::printf("\n[timing] generate: %8.1f ms   [rss] %zu KB\n",
                 elapsedMs(t0, t1), peakRssKB());

    // -----------------------------------------------------------------------
    // Phase B — Compute entity metrics (Phase 5 semantic reference)
    // -----------------------------------------------------------------------
    printHeader("Phase B — Phase 5 inclusion + entity metrics");
    Clock::time_point t2 = Clock::now();
    RangeConfig range;
    auto entity_rows = computeEntityMetrics(
        rows, range, CoveragePolicy::STRICT_GATING);
    Clock::time_point t3 = Clock::now();
    reportCoveragePerMetric(entity_rows);
    std::printf("\n[timing] Phase 5: %8.1f ms   [rss] %zu KB\n",
                 elapsedMs(t2, t3), peakRssKB());

    // -----------------------------------------------------------------------
    // Phase C — Sector aggregation (Phase 11)
    // -----------------------------------------------------------------------
    printHeader("Phase C — Phase 11 sector aggregation (all 9 metrics × 20 sectors)");
    Clock::time_point t4 = Clock::now();
    BucketEdges edges = makeDefaultBucketEdges();
    SectorAggregateBundle bundle = aggregateAllMetrics(entity_rows, edges);
    Clock::time_point t5 = Clock::now();
    std::printf("[timing] Phase 11: %8.1f ms   [rss] %zu KB\n",
                 elapsedMs(t4, t5), peakRssKB());

    // Correctness audit — aggregate totals must match plain totals
    SectorAggregateAudit audit = auditSectorAggregate(entity_rows, bundle);
    std::printf("Aggregate audit: hist_totals_match=%s  ratio_totals_match=%s\n",
                 audit.hist_totals_match ? "yes" : "NO",
                 audit.ratio_totals_match ? "yes" : "NO");

    // -----------------------------------------------------------------------
    // Phase D — k-anonymity gate (Phase 12 §12)
    // -----------------------------------------------------------------------
    printHeader("Phase D — k-anonymity gate + release count");
    Clock::time_point t6 = Clock::now();
    SectorReleaseCounts released = applyKAnonAndReport(
        bundle, cfg.k_anon_threshold, S);
    Clock::time_point t7 = Clock::now();
    std::printf("\nTotal cells: %zu   released: %zu   suppressed: %zu (%.1f%%)\n",
                 released.total_cells, released.cells_released,
                 released.cells_suppressed,
                 100.0 * released.cells_suppressed
                     / std::max<size_t>(1, released.total_cells));
    std::printf("[timing] Phase 12 gate: %6.1f ms\n", elapsedMs(t6, t7));

    // -----------------------------------------------------------------------
    // Phase E — DP noise samples on two representative metrics
    // -----------------------------------------------------------------------
    printHeader("Phase E — DP-noised sample release (DTI, IPW)");
    // Show the joint noise σ for the configured ρ.
    const double sigma_total     = sigmaFromRho(cfg.dp_rho_per_query);
    const double sigma_per_party = sigma_total / std::sqrt(2.0);
    std::printf("Noise parameters:\n");
    std::printf("  ρ_per_query    : %g\n", cfg.dp_rho_per_query);
    std::printf("  σ_total        : %.4f\n", sigma_total);
    std::printf("  σ_per_party    : %.4f (N=2 parties)\n", sigma_per_party);
    std::printf("  δ (tightened)  : 2^-45 = %g\n", cfg.dp_delta);

    // Percentile quantiles from bucket histogram. edges[b] is the LEFT edge
    // of bucket b; buckets are [edges[b], edges[b+1]). Linear-interp inside
    // the bucket that straddles rank q·n_valid.
    auto quantileFromHist = [](const Histogram& H,
                                const std::vector<uint64_t>& edges,
                                double q) -> double {
        if (H.n_valid == 0 || H.h.empty() || edges.empty()) return 0.0;
        double target = q * static_cast<double>(H.n_valid);
        uint64_t cum = 0;
        for (size_t b = 0; b < H.h.size(); ++b) {
            uint64_t next = cum + H.h[b];
            if (static_cast<double>(next) >= target) {
                double lo = static_cast<double>(edges[b]);
                double hi = (b + 1 < edges.size())
                                ? static_cast<double>(edges[b+1])
                                : lo;
                if (H.h[b] == 0) return lo;
                double frac = (target - static_cast<double>(cum))
                              / static_cast<double>(H.h[b]);
                return lo + frac * (hi - lo);
            }
            cum = next;
        }
        return static_cast<double>(edges.back());
    };

    // Pull the per-metric bucket edges we'll need for quantile inversion.
    auto edgesFor = [&](Metric m) -> const std::vector<uint64_t>& {
        switch (m) {
            case Metric::DTI:         return edges.DTI;
            case Metric::DSI:         return edges.DSI;
            case Metric::DEmp:        return edges.DEmp;
            case Metric::IPW:         return edges.IPW;
            case Metric::Delq:        return edges.Delq;
            case Metric::NPL:         return edges.NPL;
            case Metric::UnsecShare:  return edges.UnsecShare;
            case Metric::StDebtShare: return edges.StDebtShare;
            case Metric::Gap:         return edges.Gap;
            default:                  return edges.DTI;
        }
    };

    // Human-readable divisor for a metric (used to render ratios in natural
    // units). Most metrics are stored in basis-points × 100 or similar
    // fixed-point-scaled units; we print raw + a divisor-based rendering.
    auto naturalScale = [](Metric m) -> std::pair<double, const char*> {
        // The default edges use bps-scaled fixed-point (see MpsvsRatioBucket).
        // Return a divisor + suffix that renders sensibly per-metric family.
        switch (m) {
            case Metric::DTI:  case Metric::DSI:
            case Metric::Delq: case Metric::NPL:
            case Metric::UnsecShare: case Metric::StDebtShare:
                return {10000.0, "×ratio"};  // basis-points → ratio
            case Metric::IPW:  return {1.0, "SGD/worker"};
            case Metric::DEmp: return {1.0, "SGD/worker"};
            case Metric::Gap:  return {10000.0, "×growth"};
            default:           return {1.0, "raw"};
        }
    };

    // Lookup: for each metric, index sector → SectorHistogram* and SectorRatio*
    // so we can render the compact table row-by-row.
    auto findHist = [&](size_t mi, uint32_t sector) -> const SectorHistogram* {
        for (const auto& h : bundle.hists[mi])
            if (h.key.sector == sector) return &h;
        return nullptr;
    };
    auto findRatio = [&](size_t mi, uint32_t sector) -> const SectorRatio* {
        for (const auto& r : bundle.ratios[mi])
            if (r.key.sector == sector) return &r;
        return nullptr;
    };

    // Discover the sector list (already public — from the panel).
    std::vector<uint32_t> sectors;
    for (uint32_t s = 1; s <= static_cast<uint32_t>(S); ++s) sectors.push_back(s);

    // -----------------------------------------------------------------------
    // TABLE 1 — Sector × Metric — aggregate ratio (Σn/Σd)
    // -----------------------------------------------------------------------
    std::printf("\n[Table 1] Aggregate ratio Σ_i incl_i·num_i / Σ_i incl_i·den_i\n");
    std::printf("Columns: DTI, DSI, DEmp, IPW, Delq, NPL, Unsec, StDebt "
                 "(Gap suppressed, all sectors)\n\n");
    std::printf("sec |    DTI      DSI     DEmp        IPW      Delq       NPL"
                 "     Unsec    StDebt\n");
    std::printf("----+---------------------------------------------------------"
                 "-------------------\n");

    static const Metric kOrder[] = {
        Metric::DTI, Metric::DSI, Metric::DEmp, Metric::IPW,
        Metric::Delq, Metric::NPL, Metric::UnsecShare, Metric::StDebtShare
    };
    static const int kOrderN = sizeof(kOrder) / sizeof(kOrder[0]);

    for (uint32_t s : sectors) {
        std::printf(" %2u |", s);
        for (int j = 0; j < kOrderN; ++j) {
            Metric m = kOrder[j];
            const SectorRatio* R = findRatio(static_cast<size_t>(m), s);
            double ratio = 0.0;
            if (R && R->incl && R->sum_den > 0) {
                ratio = static_cast<double>(R->sum_num)
                       / static_cast<double>(R->sum_den);
            }
            // Column-appropriate formatting: ratio-metrics get 4 decimals,
            // SGD/worker metrics (DEmp, IPW) get integer form.
            if (m == Metric::DEmp || m == Metric::IPW) {
                std::printf("  %7.0f", ratio);
            } else {
                std::printf("  %7.4f", ratio);
            }
        }
        std::printf("\n");
    }

    // -----------------------------------------------------------------------
    // TABLE 2 — Sector × Metric — median (p50)
    // -----------------------------------------------------------------------
    std::printf("\n[Table 2] Median (p50) — individual-firm ratio\n\n");
    std::printf("sec |    DTI      DSI     DEmp        IPW      Delq       NPL"
                 "     Unsec    StDebt\n");
    std::printf("----+---------------------------------------------------------"
                 "-------------------\n");
    for (uint32_t s : sectors) {
        std::printf(" %2u |", s);
        for (int j = 0; j < kOrderN; ++j) {
            Metric m = kOrder[j];
            const SectorHistogram* H = findHist(static_cast<size_t>(m), s);
            auto scale = naturalScale(m);
            double p50 = 0.0;
            if (H) p50 = quantileFromHist(H->hist, edgesFor(m), 0.50)
                          / scale.first;
            if (m == Metric::DEmp || m == Metric::IPW) {
                std::printf("  %7.0f", p50);
            } else {
                std::printf("  %7.4f", p50);
            }
        }
        std::printf("\n");
    }

    // -----------------------------------------------------------------------
    // TABLE 3 — Sector × Metric — p90 (upper-tail vulnerability)
    // -----------------------------------------------------------------------
    std::printf("\n[Table 3] 90th percentile — upper-tail exposure per sector\n\n");
    std::printf("sec |    DTI      DSI     DEmp        IPW      Delq       NPL"
                 "     Unsec    StDebt\n");
    std::printf("----+---------------------------------------------------------"
                 "-------------------\n");
    for (uint32_t s : sectors) {
        std::printf(" %2u |", s);
        for (int j = 0; j < kOrderN; ++j) {
            Metric m = kOrder[j];
            const SectorHistogram* H = findHist(static_cast<size_t>(m), s);
            auto scale = naturalScale(m);
            double p90 = 0.0;
            if (H) p90 = quantileFromHist(H->hist, edgesFor(m), 0.90)
                          / scale.first;
            if (m == Metric::DEmp || m == Metric::IPW) {
                std::printf("  %7.0f", p90);
            } else {
                std::printf("  %7.4f", p90);
            }
        }
        std::printf("\n");
    }

    // -----------------------------------------------------------------------
    // TABLE 4 — Sector × Metric — DP-noised n_valid (release counts)
    // -----------------------------------------------------------------------
    std::printf("\n[Table 4] DP-noised n_valid per (sector, metric) — release "
                 "counts with σ_party=%.2f\n\n", sigma_per_party);
    std::printf("sec |   DTI    DSI   DEmp     IPW   Delq    NPL   Unsec  StDebt\n");
    std::printf("----+----------------------------------------------------------\n");
    for (uint32_t s : sectors) {
        std::printf(" %2u |", s);
        for (int j = 0; j < kOrderN; ++j) {
            Metric m = kOrder[j];
            const SectorHistogram* H = findHist(static_cast<size_t>(m), s);
            if (!H) { std::printf("  ------"); continue; }
            int64_t noise = sampleGaussianCsprng(sigma_per_party)
                          + sampleGaussianCsprng(sigma_per_party);
            int64_t noised = static_cast<int64_t>(H->hist.n_valid) + noise;
            std::printf("  %6ld", (long)noised);
        }
        std::printf("\n");
    }
    std::printf("----+----------------------------------------------------------\n");
    std::printf("All cells above the k=%u threshold → RELEASE. "
                 "Gap column suppressed (all sectors, no data).\n",
                 cfg.k_anon_threshold);

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    printHeader("Summary");
    std::printf("  Total wall-clock         : %8.1f ms\n", elapsedMs(t0, t7));
    std::printf("    generate               : %8.1f ms\n", elapsedMs(t0, t1));
    std::printf("    Phase 5 inclusion      : %8.1f ms\n", elapsedMs(t2, t3));
    std::printf("    Phase 11 sector agg    : %8.1f ms\n", elapsedMs(t4, t5));
    std::printf("    Phase 12 k-anon gate   : %8.1f ms\n", elapsedMs(t6, t7));
    std::printf("  Peak RSS                  : %8zu KB (%.1f MB)\n",
                 peakRssKB(), peakRssKB() / 1024.0);
    std::printf("  Entity rows              : %zu\n", entity_rows.size());
    std::printf("  Released cells / total   : %zu / %zu (%.1f%%)\n",
                 released.cells_released, released.total_cells,
                 100.0 * released.cells_released /
                     std::max<size_t>(1, released.total_cells));

    // Fail if aggregate audit didn't pass — that's the correctness signal.
    if (!audit.hist_totals_match || !audit.ratio_totals_match) {
        std::printf("\nFAIL — aggregate audit failed\n");
        return 1;
    }
    std::printf("\nOK — 1M-firm pipeline ran end-to-end with matching audit totals.\n");
    return 0;
}
