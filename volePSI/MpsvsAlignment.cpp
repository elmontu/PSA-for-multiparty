#include "MpsvsAlignment.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <numeric>
#include <random>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Duplicate detection
// ---------------------------------------------------------------------------

void assertNoDuplicateEntityPeriod(const std::vector<Row>& rows) {
    // Detect (key, period) duplicates within this party's real rows.
    // Uses a temporary map — in real MPC this is an oblivious adjacency check
    // after sort, but the SEMANTIC result is the same.
    std::map<std::pair<uint64_t, uint64_t>, size_t> seen;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (!rows[i].isReal()) continue;
        auto k = std::make_pair(rows[i].key, rows[i].period);
        if (seen.count(k)) {
            // Generic abort message — no per-entity leakage in the message
            // (only "duplicate detected", not which id or which source).
            throw DuplicateEntityPeriod(
                "assertNoDuplicateEntityPeriod: duplicate (key, period) at source");
        }
        seen[k] = i;
    }
}

// ---------------------------------------------------------------------------
// Bin packing
// ---------------------------------------------------------------------------

BinnedTable packBins(uint32_t source,
                     const std::vector<Row>& real_rows,
                     const BinParams& params,
                     oc::PRNG& prng) {
    BinnedTable t;
    t.beta = params.beta;
    t.cap_P = params.cap_P;
    const uint64_t num_bins = 1ULL << params.beta;
    t.rows.assign(num_bins, {});

    // Validate real rows first
    assertNoDuplicateEntityPeriod(real_rows);

    // Place each real row into its bin. Bin is set by upstream (Phase 2 §3).
    for (const Row& r : real_rows) {
        if (r.bin >= num_bins)
            throw std::runtime_error("packBins: bin id out of range");
        if (r.source != source)
            throw std::runtime_error("packBins: row source mismatch");
        t.rows[r.bin].push_back(r);
        if (r.memb != 1)
            throw std::runtime_error("packBins: real row must have memb=1");
    }

    // Check per-bin overflow before padding
    for (const auto& bin : t.rows) {
        if (bin.size() > params.cap_P) {
            throw RestartSession(
                "packBins: bin overflow — restart session with fresh ctx");
        }
    }

    // Pad each bin with dummies to exactly cap_P.
    for (uint64_t b = 0; b < num_bins; ++b) {
        while (t.rows[b].size() < params.cap_P) {
            Row d{};
            d.bin = b;
            d.source = source;
            // Random key within τ bits.
            uint64_t k = prng.get<uint64_t>();
            if (params.tau_bits < 64) k &= (1ULL << params.tau_bits) - 1;
            d.key = k;
            d.memb = 0;
            d.period = 0;   // ⊥
            d.sector = 0;   // ⊥
            t.rows[b].push_back(d);
        }
    }
    return t;
}

// ---------------------------------------------------------------------------
// Within-bin sort — oblivious bitonic
// ---------------------------------------------------------------------------

// Sort a single bin's rows by (key, source). Uses std::stable_sort here as
// the SEMANTIC reference; the MPC upgrade replaces this with an oblivious
// bitonic network of fixed shape.
//
// Rev 7 §5.3 pads to next power of two with public dead rows for bitonic.
// Since public dead rows are structurally trivial to strip (they carry a
// PUBLIC "dead" flag), we pad→sort→strip within this function so the
// bin's semantic length stays at 3·cap_P per the F_PSA output spec.
void withinBinSort(std::vector<Row>& bin) {
    size_t n_real = bin.size();
    size_t p = 1;
    while (p < n_real) p *= 2;
    // Pad with dead rows (sort last)
    while (bin.size() < p) {
        Row d{};
        d.bin = bin.empty() ? 0 : bin.front().bin;
        d.source = 4;   // "public dead" source label > all real sources
        d.key = std::numeric_limits<uint64_t>::max();
        d.memb = 0;
        bin.push_back(d);
    }

    std::stable_sort(bin.begin(), bin.end(),
        [](const Row& a, const Row& b) {
            if (a.key != b.key) return a.key < b.key;
            return a.source < b.source;
        });

    // Strip trailing public dead rows (source == 4). Because they sort last,
    // they occupy exactly the last (p - n_real) positions after sort.
    bin.resize(n_real);
}

// ---------------------------------------------------------------------------
// WindowedMerge (R16 membership-gated)
// ---------------------------------------------------------------------------

std::vector<UnionRow> windowedMerge(const std::vector<Row>& sorted_bin) {
    // Produce one output row per position; canonical iff first in run.
    // Merge window is ±2 (Rev 7 §5.4 note: run length ≤ 3 by dedup invariant).
    std::vector<UnionRow> out(sorted_bin.size());

    auto keyEq = [](const Row& a, const Row& b) {
        return a.key == b.key && a.memb == 1 && b.memb == 1;
        // R16: two dummies with the same random key never "match" as same
        // entity because both have memb=0. Two reals with same key are a
        // legitimate collision (impossible up to §9 collision budget).
    };

    // For robust dummy handling, treat "same key" for merge purposes ONLY
    // when both rows are real. This is the R16 gating pattern.

    for (size_t i = 0; i < sorted_bin.size(); ++i) {
        const Row& r = sorted_bin[i];
        UnionRow& u = out[i];
        u.bin = r.bin;

        // "first" = i is the start of a same-key run. i is first iff either
        // i == 0 or key(i) != key(i-1) OR the previous row was a dummy.
        bool first = (i == 0) || (sorted_bin[i-1].key != r.key)
                             || (sorted_bin[i-1].memb == 0)
                             || (r.memb == 0);
        u.canonical = first ? 1 : 0;

        if (r.memb == 0) {
            // Dummy row → nothing to merge; presence bits stay 0.
            u.live = 0;
            continue;
        }

        // For real rows: scan the window [i, i+2] for same-key rows and pick
        // per-source presence + payload.
        auto pickSource = [&](uint32_t src, uint8_t& b_out,
                              PayloadPerSource& p_out) -> bool {
            for (size_t j = i; j < std::min(sorted_bin.size(), i + 3); ++j) {
                const Row& cand = sorted_bin[j];
                if (cand.source == src && cand.memb == 1 && keyEq(cand, r)) {
                    b_out = 1;
                    p_out = cand.payload;
                    return true;
                }
            }
            return false;
        };
        // R16 gating: only set b_src iff we found a REAL row from that source
        // with matching key.
        (void)pickSource(0 /*MAS*/, u.b_MAS, u.p_MAS);
        (void)pickSource(1 /*DOS*/, u.b_DOS, u.p_DOS);
        (void)pickSource(2 /*MOM*/, u.b_MOM, u.p_MOM);

        // Sector reconciliation: authoritative source rule = MAS > DOS > MOM.
        // If multiple sources present with different sectors, set the
        // sector_conflict shared flag but never leak per-entity.
        uint64_t chosen_sector = 0;
        bool have_any = false;
        uint64_t saw_sectors[3] = {0, 0, 0};
        int saw_count = 0;
        for (uint32_t src = 0; src <= 2; ++src) {
            for (size_t j = i; j < std::min(sorted_bin.size(), i + 3); ++j) {
                const Row& cand = sorted_bin[j];
                if (cand.source == src && cand.memb == 1 && keyEq(cand, r)) {
                    saw_sectors[saw_count++] = cand.sector;
                    if (!have_any) { chosen_sector = cand.sector; have_any = true; }
                }
            }
        }
        u.sector = chosen_sector;
        for (int a = 1; a < saw_count; ++a) {
            if (saw_sectors[a] != saw_sectors[0]) { u.sector_conflict = 1; break; }
        }

        // Period: same across sources by Phase 2 canonicalisation.
        u.period = r.period;
    }
    return out;
}

// ---------------------------------------------------------------------------
// LiveMark
// ---------------------------------------------------------------------------

void markLive(std::vector<UnionRow>& rows) {
    for (auto& u : rows) {
        uint8_t anyMem = u.b_MAS | u.b_DOS | u.b_MOM;
        u.live = u.canonical & anyMem;
    }
}

// ---------------------------------------------------------------------------
// ComposedShuffle
// ---------------------------------------------------------------------------

void composedShuffle(std::vector<UnionRow>& rows, oc::PRNG& prng) {
    // Rev 7 §5.6: S1 permutes with π1 (fresh); S2 permutes with π2 (fresh).
    // Semantic reference: apply π = π2 ∘ π1 as a single pass with a fresh
    // uniform permutation via Fisher-Yates. The MPC upgrade splits this
    // into two rounds with CGP-preprocessed correlations so neither server
    // learns the full composed permutation.
    const size_t n = rows.size();
    std::vector<size_t> perm(n);
    std::iota(perm.begin(), perm.end(), 0);
    for (size_t i = n - 1; i > 0; --i) {
        size_t j = prng.get<uint64_t>() % (i + 1);
        std::swap(perm[i], perm[j]);
    }
    std::vector<UnionRow> out(n);
    for (size_t i = 0; i < n; ++i) out[i] = rows[perm[i]];
    rows = std::move(out);
}

// ---------------------------------------------------------------------------
// F_PSA runner
// ---------------------------------------------------------------------------

AlignmentResult runFPsa(const std::vector<Row>& mas_rows,
                        const std::vector<Row>& dos_rows,
                        const std::vector<Row>& mom_rows,
                        const BinParams& params,
                        oc::PRNG& prng) {
    AlignmentResult result;
    result.params = params;

    // Per-party bin packing (source enum: 0=MAS, 1=DOS, 2=MOM)
    BinnedTable tMAS, tDOS, tMOM;
    try {
        tMAS = packBins(0, mas_rows, params, prng);
        tDOS = packBins(1, dos_rows, params, prng);
        tMOM = packBins(2, mom_rows, params, prng);
    } catch (const RestartSession& r) {
        result.restarted = true;
        throw;
    }

    // Concatenate per-bin: for each bin b, [MAS.rows[b], DOS.rows[b], MOM.rows[b]]
    const uint64_t num_bins = 1ULL << params.beta;
    std::vector<UnionRow> union_out;
    union_out.reserve(3ULL * params.cap_P * num_bins);
    for (uint64_t b = 0; b < num_bins; ++b) {
        std::vector<Row> bin_all;
        bin_all.reserve(3 * params.cap_P);
        bin_all.insert(bin_all.end(), tMAS.rows[b].begin(), tMAS.rows[b].end());
        bin_all.insert(bin_all.end(), tDOS.rows[b].begin(), tDOS.rows[b].end());
        bin_all.insert(bin_all.end(), tMOM.rows[b].begin(), tMOM.rows[b].end());
        // Sort obliviously by (key, source), padding to power of two.
        withinBinSort(bin_all);
        // Merge with R16 membership gating.
        auto merged = windowedMerge(bin_all);
        for (auto& u : merged) union_out.push_back(std::move(u));
    }

    // Mark live and shuffle
    markLive(union_out);
    composedShuffle(union_out, prng);
    result.table = std::move(union_out);
    return result;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

FPsaAudit auditAlignment(const AlignmentResult& r) {
    FPsaAudit a{};
    a.total_rows = r.table.size();
    for (const auto& u : r.table) {
        if (u.live) ++a.live_rows;
        if (u.canonical) ++a.canonical_rows;
        if (u.sector_conflict) ++a.sector_conflicts;
    }
    // Public shape: all rows are UnionRow (fixed struct); no data-dependent
    // sizes. Structurally true by the type.
    a.all_shapes_public = true;
    return a;
}

} // namespace mpsvs
} // namespace volePSI
