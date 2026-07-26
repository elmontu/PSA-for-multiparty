#include "MpsvsCompositeWire.h"

#include <algorithm>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::secureAnd;
using mpstar::shareBit;

// ---------------------------------------------------------------------------
// Public-constant 128-bit multiply. Public shifts; only Adds cost triples.
// ---------------------------------------------------------------------------

SharedU128Bin mulPublicConst128(const SharedU128Bin& x, __int128 c,
                                  const std::vector<BeaverTripleBit>& triples,
                                  size_t& idx) {
    const uint32_t N = x.bits[0].N();
    SharedU128Bin acc(N);
    for (int bit = 0; bit < 128; ++bit) {
        if (!((c >> bit) & 1)) continue;
        // shifted = x << bit (relabel — free; bits >= 128 dropped)
        SharedU128Bin shifted(N);
        for (int i = 0; i < 128 - bit; ++i) shifted.bits[i + bit] = x.bits[i];
        acc = bitAdd128(acc, shifted, triples, idx);
    }
    return acc;
}

// ---------------------------------------------------------------------------
// Precompute per-cell reciprocals.
// ---------------------------------------------------------------------------

// Subtract 1 from a SharedU64Bin (n_valid - 1).
static SharedU64Bin bitSubOneU64(const SharedU64Bin& x,
                                   const std::vector<BeaverTripleBit>& triples,
                                   size_t& idx) {
    // Two's complement: -1 = 0xFFFFFF...F (all bits 1).
    // Then x + (-1) mod 2^64 = x - 1.
    // We just need the "add all-1s then propagate carry" — equivalent to
    // a ripple-carry with a public constant.
    const uint32_t N = x.N();
    SharedU64Bin out;
    SharedBit carry(N);
    // Initial carry from adding -1: we're computing x + 0xFF..F.
    // Equivalent: NOT x + 0, then NOT again — but two's complement of -1
    // just means: for each bit i, out[i] = x[i] XOR 1 XOR carry, then
    // carry = old_carry OR (bit==0 case).
    // Simplest: use bitAdd of x with a public share of -1.
    SharedU64Bin minus_one;
    for (int i = 0; i < 64; ++i) {
        SharedBit sb(N);
        sb.shares[0] = 1;   // party 0 holds 1 in each bit → reconstructs to 1
        minus_one.bits[i] = sb;
    }
    // Do ripple-carry add.
    SharedBit c(N);
    for (int i = 0; i < 64; ++i) {
        SharedBit ab = mpstar::xorShared(x.bits[i], minus_one.bits[i]);
        SharedBit sum = mpstar::xorShared(ab, c);
        SharedBit and_ab = secureAnd(x.bits[i], minus_one.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(c, ab, triples[idx++]);
        SharedBit or_a = mpstar::xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        c = mpstar::xorShared(or_a, or_b);
        out.bits[i] = sum;
    }
    return out;
}

std::vector<SharedCellReciprocal>
precomputeCellReciprocals(
    const std::map<std::pair<uint32_t, Metric>, SharedU64Bin>& n_valid_by_cell,
    uint64_t N_max,
    const std::vector<BeaverTripleBit>& triples,
    size_t& idx) {
    std::vector<SharedCellReciprocal> out;
    out.reserve(n_valid_by_cell.size());
    for (const auto& kv : n_valid_by_cell) {
        SharedCellReciprocal sc;
        sc.popkey = kv.first.first;
        sc.metric = kv.first.second;
        SharedU64Bin denom = bitSubOneU64(kv.second, triples, idx);
        sc.recip_fp = goldschmidtRecipWire(denom, N_max, /*iters=*/6,
                                             triples, idx);
        out.push_back(std::move(sc));
    }
    return out;
}

// ---------------------------------------------------------------------------
// SharedU64Bin (u64 shared) → SharedU128Bin fp (multiply by 2^f).
// Just re-labels bits: input bit i → output bit i+f.
// ---------------------------------------------------------------------------

static SharedU128Bin u64binToFp(const SharedU64Bin& x, oc::PRNG& prng) {
    (void)prng;
    const uint32_t N = x.N();
    SharedU128Bin out(N);
    for (int i = 0; i < 64; ++i) {
        int j = i + kFpFractionalBits;
        if (j < 128) out.bits[j] = x.bits[i];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Small helpers for renormalised path.
// ---------------------------------------------------------------------------

// Gate a shared 128-bit fp value by a shared bit: (bit ? value : 0).
// Per-bit: out_i = secureAnd(bit, value_i) → 128 secureAnd calls.
static SharedU128Bin
gateFpByBit(const SharedBit& bit, const SharedU128Bin& value,
              const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    const uint32_t N = value.bits[0].N();
    SharedU128Bin out(N);
    for (int i = 0; i < 128; ++i) {
        if (idx >= triples.size())
            throw std::runtime_error("triple bag exhausted (gateFpByBit)");
        out.bits[i] = secureAnd(bit, value.bits[i], triples[idx++]);
    }
    return out;
}

// OR of two shared bits: a XOR b XOR (a AND b). One secureAnd.
static SharedBit
orShared(const SharedBit& a, const SharedBit& b,
          const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    SharedBit ab = secureAnd(a, b, triples[idx++]);
    return mpstar::xorShared(mpstar::xorShared(a, b), ab);
}

// Sum 4 shared bits into a shared 3-bit u64 (bit-shared count 0..4).
// Cost: 5 secureAnd (two half-adds + one 2-bit add). Result revealed by caller.
static SharedU64Bin
sumFourBits(const SharedBit& b0, const SharedBit& b1,
              const SharedBit& b2, const SharedBit& b3,
              const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    const uint32_t N = b0.N();
    // Half-add pairs (b0, b1) and (b2, b3): sum_lo + carry.
    SharedBit s01 = mpstar::xorShared(b0, b1);
    SharedBit c01 = secureAnd(b0, b1, triples[idx++]);
    SharedBit s23 = mpstar::xorShared(b2, b3);
    SharedBit c23 = secureAnd(b2, b3, triples[idx++]);
    // Add (s01, c01) + (s23, c23) as 2-bit values:
    //   bit_0 = s01 XOR s23
    //   carry_0 = s01 AND s23
    //   bit_1 = c01 XOR c23 XOR carry_0
    //   bit_2 = (c01 AND c23) OR (bit_1_a AND carry_0), where bit_1_a = c01 XOR c23
    SharedBit bit0 = mpstar::xorShared(s01, s23);
    SharedBit carry0 = secureAnd(s01, s23, triples[idx++]);
    SharedBit bit1_a = mpstar::xorShared(c01, c23);
    SharedBit bit1 = mpstar::xorShared(bit1_a, carry0);
    SharedBit and_cc = secureAnd(c01, c23, triples[idx++]);
    SharedBit and_ac = secureAnd(bit1_a, carry0, triples[idx++]);
    // OR(and_cc, and_ac) — one more secureAnd for the AND-part of OR.
    SharedBit or_a = mpstar::xorShared(and_cc, and_ac);
    SharedBit or_b = secureAnd(and_cc, and_ac, triples[idx++]);
    SharedBit bit2 = mpstar::xorShared(or_a, or_b);

    SharedU64Bin out;
    for (int i = 0; i < 64; ++i) out.bits[i] = SharedBit(N);
    out.bits[0] = bit0;
    out.bits[1] = bit1;
    out.bits[2] = bit2;
    return out;
}

// ---------------------------------------------------------------------------
// computeCompositeTwoScoreWire — strict AND renormalised
// ---------------------------------------------------------------------------

std::vector<SharedCompositeRow>
computeCompositeTwoScoreWire(
    const std::array<std::vector<SharedRankedRow>, kMetricCount>& metric_ranks,
    const std::vector<SharedCellReciprocal>& reciprocals,
    const CompositeWeightsWire& weights,
    const std::vector<BeaverTripleBit>& triples,
    size_t& idx,
    oc::PRNG& prng) {

    // Index rows by entity_idx per metric.
    std::vector<uint32_t> all_entities;
    std::map<uint32_t, uint32_t> entity_popkey;
    std::array<std::map<uint32_t, const SharedRankedRow*>, kMetricCount> lookup;
    for (size_t m = 0; m < kMetricCount; ++m) {
        for (const auto& r : metric_ranks[m]) {
            lookup[m][r.entity_idx] = &r;
            entity_popkey[r.entity_idx] = r.popkey;
        }
    }
    for (const auto& kv : entity_popkey) all_entities.push_back(kv.first);
    std::sort(all_entities.begin(), all_entities.end());

    std::map<std::pair<uint32_t, Metric>, const SharedCellReciprocal*> rlookup;
    for (const auto& r : reciprocals) rlookup[{r.popkey, r.metric}] = &r;

    std::vector<SharedCompositeRow> out;
    out.reserve(all_entities.size());

    for (uint32_t eid : all_entities) {
        SharedCompositeRow c;
        c.entity_idx = eid;
        c.popkey = entity_popkey[eid];
        c.vuln_strict_fp = SharedU128Bin(2);
        c.vuln_renorm_fp = SharedU128Bin(2);

        SharedBit and_chain;         // AND of core incls (strict)
        SharedBit or_chain;          // OR of core incls (renorm)
        bool first_chain = true;

        // Collect per-metric incl bits + weighted scores for post-loop batching.
        std::vector<SharedBit> core_incls;
        std::vector<SharedU128Bin> gated_scores;   // incl · w · score (all 128-bit fp)

        for (Metric mc : kVulnCoreMetrics) {
            size_t m = static_cast<size_t>(mc);
            auto it = lookup[m].find(eid);
            if (it == lookup[m].end()) {
                // Metric missing entirely — treat as incl=0 with zero score.
                core_incls.push_back(SharedBit(2));
                gated_scores.push_back(SharedU128Bin(2));
                continue;
            }
            const SharedRankedRow* row = it->second;

            // Chain: AND for strict, OR for renorm.
            if (first_chain) {
                and_chain = row->incl;
                or_chain  = row->incl;
                first_chain = false;
            } else {
                if (idx + 2 > triples.size())
                    throw std::runtime_error("triple bag exhausted (incl chain)");
                and_chain = secureAnd(and_chain, row->incl, triples[idx++]);
                or_chain  = orShared(or_chain, row->incl, triples, idx);
            }
            core_incls.push_back(row->incl);

            // Reciprocal 1/(n_valid-1).
            auto rit = rlookup.find({c.popkey, mc});
            if (rit == rlookup.end())
                throw std::runtime_error("no reciprocal for (popkey, metric)");
            const SharedU128Bin& recip_fp = rit->second->recip_fp;

            // score_fp = rank_fp · recip_fp
            SharedU128Bin rank_fp = u64binToFp(row->rank, prng);
            SharedU128Bin score_fp = fpMulShared(rank_fp, recip_fp, triples, idx);

            // weighted_fp = w_m (public fp const) · score_fp, fp-normalised.
            SharedU128Bin weighted_raw = mulPublicConst128(score_fp,
                                                            weights.w_fp[m],
                                                            triples, idx);
            SharedU128Bin weighted(2);
            for (int i = 0; i < 128; ++i) {
                int j = i + kFpFractionalBits;
                if (j < 128) weighted.bits[i] = weighted_raw.bits[j];
            }

            // Strict sum: acc += weighted (gated by AND-chain at output).
            c.vuln_strict_fp = bitAdd128(c.vuln_strict_fp, weighted, triples, idx);

            // Renorm gated score: incl · weighted (per-metric gate).
            SharedU128Bin gated_w = gateFpByBit(row->incl, weighted, triples, idx);
            gated_scores.push_back(gated_w);
        }
        // Pad to 4 entries if fewer metrics had rows.
        while (core_incls.size() < 4) {
            core_incls.push_back(SharedBit(2));
            gated_scores.push_back(SharedU128Bin(2));
        }

        c.incl_strict = first_chain ? SharedBit(2) : and_chain;
        c.incl_renorm = first_chain ? SharedBit(2) : or_chain;

        // renorm_num_fp = Σ gated_scores (3 bitAdd128).
        SharedU128Bin renorm_num_fp = gated_scores[0];
        for (int i = 1; i < 4; ++i)
            renorm_num_fp = bitAdd128(renorm_num_fp, gated_scores[i], triples, idx);

        // avail_core shared = sum of 4 core incl bits (5 secureAnd).
        SharedU64Bin avail_shared = sumFourBits(core_incls[0], core_incls[1],
                                                  core_incls[2], core_incls[3],
                                                  triples, idx);
        // Reveal avail_core — documented per-entity leak (see header).
        uint64_t avail = avail_shared.reconstruct() & 0x7;
        c.avail_core = static_cast<uint8_t>(avail);

        // vuln_renorm = renorm_num_fp / avail_core (via PUBLIC constant fp mult).
        // vuln_renorm_actual = renorm_num_actual / (avail · w_actual_per_metric).
        // With equal weights w_actual, we have renorm_num_fp = Σ(incl·w·score)_fp
        // and want vuln_renorm_fp = renorm_num_fp / (avail · w).
        // Rearranging: since ALL weights are equal to w_public, sum-of-gated-w
        // = avail · w. So denom (fp) = avail · w_fp. As a public value, its
        // reciprocal fp is: 1/(avail · w) → in fp: fp(1/(avail·w)).
        if (avail == 0) {
            c.vuln_renorm_fp = SharedU128Bin(2);   // deterministic zero
        } else {
            // Compute public reciprocal fp(1/(avail · w_actual)).
            // w_actual = weights.w_fp[core[0]] / 2^f (assume uniform weights).
            __int128 w_fp = weights.w_fp[static_cast<size_t>(kVulnCoreMetrics[0])];
            // denom_fp_actual (real) = avail · w_actual
            //                        = avail · (w_fp / 2^f)
            // 1/denom_actual (real) = 2^f / (avail · w_fp)
            // fp(1/denom_actual) = 2^f · 2^f / (avail · w_fp) = 2^(2f) / (avail · w_fp)
            __int128 numerator_2f = (static_cast<__int128>(1) << kFpFractionalBits);
            numerator_2f <<= kFpFractionalBits;   // 2^(2f)
            __int128 recip_public_fp = numerator_2f /
                                        (static_cast<__int128>(avail) * w_fp);

            // vuln_renorm_fp = renorm_num_fp · recip_public_fp / 2^f.
            SharedU128Bin scaled = mulPublicConst128(renorm_num_fp,
                                                       recip_public_fp,
                                                       triples, idx);
            // Truncate: shift right by f.
            SharedU128Bin out_fp(2);
            for (int i = 0; i < 128; ++i) {
                int j = i + kFpFractionalBits;
                if (j < 128) out_fp.bits[i] = scaled.bits[j];
            }
            c.vuln_renorm_fp = out_fp;
        }

        out.push_back(c);
    }
    return out;
}

// Deprecated alias.
std::vector<SharedCompositeRow>
computeCompositeStrictWire(
    const std::array<std::vector<SharedRankedRow>, kMetricCount>& metric_ranks,
    const std::vector<SharedCellReciprocal>& reciprocals,
    const CompositeWeightsWire& weights,
    const std::vector<BeaverTripleBit>& triples,
    size_t& idx,
    oc::PRNG& prng) {
    return computeCompositeTwoScoreWire(metric_ranks, reciprocals, weights,
                                          triples, idx, prng);
}

std::vector<PlainCompositeRow>
reconstructComposites(const std::vector<SharedCompositeRow>& shared) {
    std::vector<PlainCompositeRow> out;
    out.reserve(shared.size());
    for (const auto& s : shared) {
        PlainCompositeRow p;
        p.entity_idx = s.entity_idx;
        p.popkey = s.popkey;
        p.incl_strict = s.incl_strict.reconstruct();
        p.vuln_strict = fpToDoubleShared(s.vuln_strict_fp);
        p.incl_renorm = s.incl_renorm.reconstruct();
        p.vuln_renorm = fpToDoubleShared(s.vuln_renorm_fp);
        p.avail_core = s.avail_core;
        out.push_back(p);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
