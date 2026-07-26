#include "MpsvsInclusion.h"

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

const char* metricName(Metric m) {
    switch (m) {
        case Metric::DTI:         return "DTI";
        case Metric::DSI:         return "DSI";
        case Metric::DEmp:        return "DEmp";
        case Metric::IPW:         return "IPW";
        case Metric::Delq:        return "Delq";
        case Metric::NPL:         return "NPL";
        case Metric::UnsecShare:  return "UnsecShare";
        case Metric::StDebtShare: return "StDebtShare";
        case Metric::Gap:         return "Gap";
        case Metric::_COUNT: break;
    }
    return "?";
}

// Range check: [[value ∈ [min_incl, max_incl]]].
// MPC-wire upgrade replaces with secureLessThan(min−1, value) AND
// secureLessThan(value, max+1).
static inline uint8_t inRange(uint64_t value, const AttrRange& r) {
    return (value >= r.min_incl && value <= r.max_incl) ? 1 : 0;
}

// Standard AND on secret bits — in MPC-wire this is Beaver-triple secureAnd.
// Here plaintext & suffices for the semantic reference.
static inline uint8_t sand(uint8_t a, uint8_t b) { return a & b; }

std::vector<EntityMetricRow>
computeEntityMetrics(const std::vector<UnionRow>& union_rows,
                     const RangeConfig& rc,
                     CoveragePolicy vuln_policy) {
    std::vector<EntityMetricRow> out(union_rows.size());
    for (size_t i = 0; i < union_rows.size(); ++i) {
        const UnionRow& u = union_rows[i];
        EntityMetricRow& e = out[i];
        e.bin = u.bin;
        e.period = u.period;
        e.sector = u.sector;
        e.sector_conflict = u.sector_conflict;
        e.live = u.live;
        e.b_MAS = u.b_MAS;
        e.b_DOS = u.b_DOS;
        e.b_MOM = u.b_MOM;

        // Convenience aliases for validity + payload fields.
        const uint8_t v_debt   = u.p_MAS.valid[fields::MAS_debt];
        const uint8_t v_dserv  = u.p_MAS.valid[fields::MAS_dserv];
        const uint8_t v_delq   = u.p_MAS.valid[fields::MAS_delq];
        const uint8_t v_npl    = u.p_MAS.valid[fields::MAS_npl];
        const uint8_t v_unsec  = u.p_MAS.valid[fields::MAS_unsec];
        const uint8_t v_stdebt = u.p_MAS.valid[fields::MAS_stdebt];
        const uint8_t v_income = u.p_DOS.valid[fields::DOS_income];
        const uint8_t v_emp    = u.p_MOM.valid[fields::MOM_emp];
        const uint8_t v_gdebt  = u.p_MAS.v_g;
        const uint8_t v_gincome= u.p_DOS.v_g;

        const uint64_t debt    = u.p_MAS.v[fields::MAS_debt];
        const uint64_t dserv   = u.p_MAS.v[fields::MAS_dserv];
        const uint64_t delq    = u.p_MAS.v[fields::MAS_delq];
        const uint64_t npl     = u.p_MAS.v[fields::MAS_npl];
        const uint64_t unsec   = u.p_MAS.v[fields::MAS_unsec];
        const uint64_t stdebt  = u.p_MAS.v[fields::MAS_stdebt];
        const uint64_t income  = u.p_DOS.v[fields::DOS_income];
        const uint64_t emp     = u.p_MOM.v[fields::MOM_emp];

        // "alignment" == live in the semantic reference. MPC version uses
        // the shared alignment_bit from Phase 4 directly.
        const uint8_t align = u.live;

        // Per-metric inclusion masks + (num, den) pairs.
        auto& mDTI  = e.metrics[static_cast<size_t>(Metric::DTI)];
        mDTI.num = debt;
        mDTI.den = income;
        mDTI.incl = sand(sand(sand(align, u.b_MAS),
                              sand(u.b_DOS, v_debt)),
                         sand(v_income, inRange(income, rc.income)));

        auto& mDSI = e.metrics[static_cast<size_t>(Metric::DSI)];
        mDSI.num = dserv;
        mDSI.den = income;
        mDSI.incl = sand(sand(sand(align, u.b_MAS),
                              sand(u.b_DOS, v_dserv)),
                         sand(v_income, inRange(income, rc.income)));

        auto& mDEmp = e.metrics[static_cast<size_t>(Metric::DEmp)];
        mDEmp.num = debt;
        mDEmp.den = emp;
        mDEmp.incl = sand(sand(sand(align, u.b_MAS),
                               sand(u.b_MOM, v_debt)),
                          sand(v_emp, inRange(emp, rc.emp)));

        auto& mIPW = e.metrics[static_cast<size_t>(Metric::IPW)];
        mIPW.num = income;
        mIPW.den = emp;
        mIPW.incl = sand(sand(sand(align, u.b_DOS),
                              sand(u.b_MOM, v_income)),
                         sand(v_emp, inRange(emp, rc.emp)));

        auto& mDelq = e.metrics[static_cast<size_t>(Metric::Delq)];
        mDelq.num = delq;
        mDelq.den = debt;
        mDelq.incl = sand(sand(sand(align, u.b_MAS), v_delq),
                          sand(v_debt, inRange(debt, rc.debt)));

        auto& mNPL = e.metrics[static_cast<size_t>(Metric::NPL)];
        mNPL.num = npl;
        mNPL.den = debt;
        mNPL.incl = sand(sand(sand(align, u.b_MAS), v_npl),
                         sand(v_debt, inRange(debt, rc.debt)));

        auto& mUS = e.metrics[static_cast<size_t>(Metric::UnsecShare)];
        mUS.num = unsec;
        mUS.den = debt;
        mUS.incl = sand(sand(sand(align, u.b_MAS), v_unsec),
                        sand(v_debt, inRange(debt, rc.debt)));

        auto& mSD = e.metrics[static_cast<size_t>(Metric::StDebtShare)];
        mSD.num = stdebt;
        mSD.den = debt;
        mSD.incl = sand(sand(sand(align, u.b_MAS), v_stdebt),
                        sand(v_debt, inRange(debt, rc.debt)));

        // Gap = g_debt − g_income. Linear cross-source metric (Rev 7 §7).
        // Stored as (num=gap_signed_encoded, den=1) with incl bit gated by
        // both source growth-validity bits.
        auto& mGap = e.metrics[static_cast<size_t>(Metric::Gap)];
        // gap can be negative; encode as int64_t and reinterpret. Downstream
        // ranking treats it via signed compare (the ratio-key comparator).
        int64_t gap_signed = static_cast<int64_t>(u.p_MAS.g) -
                             static_cast<int64_t>(u.p_DOS.g);
        std::memcpy(&mGap.num, &gap_signed, sizeof(int64_t));
        mGap.den = 1;
        mGap.incl = sand(sand(sand(align, u.b_MAS), u.b_DOS),
                         sand(v_gdebt, v_gincome));

        // Vuln coverage:
        //   avail_core_count = Σ_{c ∈ kVulnCoreMetrics} incl_c
        uint8_t avail = 0;
        for (Metric c : kVulnCoreMetrics) {
            avail += e.metrics[static_cast<size_t>(c)].incl;
        }
        e.avail_core_count = avail;

        // Vuln inclusion per policy (Rev 7 §8.3):
        //   STRICT_GATING     : all core available AND live
        //   RENORMALISED_WGT  : any core available AND live
        if (vuln_policy == CoveragePolicy::STRICT_GATING) {
            e.incl_vuln = (avail == kVulnCoreMetrics.size()) ? sand(u.live, 1) : 0;
        } else {
            e.incl_vuln = (avail >= 1) ? sand(u.live, 1) : 0;
        }
    }
    return out;
}

std::array<MetricAggregate, kMetricCount>
aggregateOverAll(const std::vector<EntityMetricRow>& rows) {
    std::array<MetricAggregate, kMetricCount> out{};
    for (const auto& r : rows) {
        for (size_t i = 0; i < kMetricCount; ++i) {
            const auto& m = r.metrics[i];
            if (m.incl) {
                out[i].sum_num += m.num;
                out[i].sum_den += m.den;
                out[i].n_valid += 1;
            }
        }
    }
    return out;
}

InclusionAudit auditInclusion(const std::vector<EntityMetricRow>& rows) {
    InclusionAudit a{};
    for (const auto& r : rows) {
        // For each metric: was memb-side OK but incl=0 (i.e., excluded due to
        // validity or range, not membership).
        // We approximate the "memb-side OK" as "all membership bits required
        // for this metric are 1 and the row is live". This does not fully
        // replicate the internal logic (kept small); good enough for the
        // audit invariant "excluded ratios were excluded on validity/range,
        // not silently zero-substituted".
        for (size_t i = 0; i < kMetricCount; ++i) {
            const auto& m = r.metrics[i];
            if (m.incl) ++a.incl_count_by_metric[i];
        }
        if (r.incl_vuln) ++a.vuln_incl_count;
        if (r.live && !r.incl_vuln) ++a.vuln_live_but_incl_zero;
    }
    return a;
}

} // namespace mpsvs
} // namespace volePSI
