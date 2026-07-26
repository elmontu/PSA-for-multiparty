#include "MpsvsInclusionWire.h"

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::secureAnd;
using mpstar::secureLessThan;
using mpstar::secureLessThanTripleCost;
using mpstar::shareBit;
using mpstar::shareU64Bin;
using mpstar::xorConst;
using mpstar::xorShared;

size_t inclusionTripleBudgetPerRow() {
    // Range check = 2 secureLessThan + 1 secureAnd = 2·192 + 1 = 385
    // Three range checks: income, debt, emp → 1155
    // Per metric AND chain: <= 6 secureAnd = 6 triples × 9 metrics = 54
    // Vuln coverage: sum of 4 core bits (avail_core_count via bit add ≈ 4·2 = 8),
    //   plus 4 equality checks for strict/renorm gates ≈ 4·secureAnd ≈ 24
    // Total budget with generous slack: ~1300 per row.
    return 3 * (2 * secureLessThanTripleCost() + 1) + 9 * 6 + 100;
}

// Utility: convert a public uint64_t to a "shared u64bin" with only party-0
// carrying the value (others = 0). This is the "share a constant" operation
// used for the range endpoints (min-1, max+1) which are PUBLIC per the spec.
static SharedU64Bin shareConstU64Bin(uint32_t N, uint64_t value) {
    SharedU64Bin out;
    for (int b = 0; b < 64; ++b) {
        SharedBit sb(N);
        sb.shares[0] = static_cast<uint8_t>((value >> b) & 1);
        for (uint32_t p = 1; p < N; ++p) sb.shares[p] = 0;
        out.bits[b] = sb;
    }
    return out;
}

// Utility: XOR a shared bit with 1 (public constant flip). Free.
static SharedBit notShared(const SharedBit& x) {
    return xorConst(x, 1);
}

// Utility: secure AND with counter step.
static SharedBit sand(const SharedBit& a, const SharedBit& b,
                     const std::vector<BeaverTripleBit>& triples,
                     size_t& idx) {
    if (idx >= triples.size())
        throw std::runtime_error("triple bag exhausted");
    return secureAnd(a, b, triples[idx++]);
}

// Range check: [[min_incl ≤ value ≤ max_incl]] as a SharedBit.
// LT circuit is unsigned; use inclusive-form by adding ±1 to public endpoints:
//   in_range = (min - 1 < value) AND (value < max + 1)
// which is: NOT(value < min) AND NOT(max < value) — but LT is one-way, so we
// use the min-1 / max+1 trick (public constants).
static SharedBit rangeCheckShared(uint32_t N,
                                  const SharedU64Bin& value,
                                  const AttrRange& r,
                                  const std::vector<BeaverTripleBit>& triples,
                                  size_t& idx) {
    uint64_t lo_m1 = (r.min_incl == 0) ? 0 : (r.min_incl - 1);
    uint64_t hi_p1 = r.max_incl + 1;    // may overflow when max = UINT64_MAX
                                        // (Rev 7 range configs are far from that)
    SharedU64Bin lo_shared = shareConstU64Bin(N, lo_m1);
    SharedU64Bin hi_shared = shareConstU64Bin(N, hi_p1);
    // ge_min = (lo_m1 < value)
    SharedBit ge_min = secureLessThan(lo_shared, value, triples, idx);
    // le_max = (value < hi_p1)
    SharedBit le_max = secureLessThan(value, hi_shared, triples, idx);
    return sand(ge_min, le_max, triples, idx);
}

SharedEntityMetricRow
computeEntityMetricsWire(const SharedUnionRow& u,
                          const RangeConfig& rc,
                          CoveragePolicy vuln_policy,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& idx) {
    const uint32_t N = u.b_MAS.N();

    SharedEntityMetricRow e{};
    e.bin = u.bin;
    e.period = u.period;
    e.sector = u.sector;
    e.sector_conflict = u.sector_conflict;
    e.live = u.live;
    e.b_MAS = u.b_MAS;
    e.b_DOS = u.b_DOS;
    e.b_MOM = u.b_MOM;

    // Convenience refs.
    const SharedBit& v_debt   = u.p_MAS.valid[fields::MAS_debt];
    const SharedBit& v_dserv  = u.p_MAS.valid[fields::MAS_dserv];
    const SharedBit& v_delq   = u.p_MAS.valid[fields::MAS_delq];
    const SharedBit& v_npl    = u.p_MAS.valid[fields::MAS_npl];
    const SharedBit& v_unsec  = u.p_MAS.valid[fields::MAS_unsec];
    const SharedBit& v_stdebt = u.p_MAS.valid[fields::MAS_stdebt];
    const SharedBit& v_income = u.p_DOS.valid[fields::DOS_income];
    const SharedBit& v_emp    = u.p_MOM.valid[fields::MOM_emp];
    const SharedBit& v_gdebt  = u.p_MAS.v_g;
    const SharedBit& v_gincome= u.p_DOS.v_g;

    const SharedU64Bin& debt   = u.p_MAS.v[fields::MAS_debt];
    const SharedU64Bin& dserv  = u.p_MAS.v[fields::MAS_dserv];
    const SharedU64Bin& delq   = u.p_MAS.v[fields::MAS_delq];
    const SharedU64Bin& npl    = u.p_MAS.v[fields::MAS_npl];
    const SharedU64Bin& unsec  = u.p_MAS.v[fields::MAS_unsec];
    const SharedU64Bin& stdebt = u.p_MAS.v[fields::MAS_stdebt];
    const SharedU64Bin& income = u.p_DOS.v[fields::DOS_income];
    const SharedU64Bin& emp    = u.p_MOM.v[fields::MOM_emp];

    const SharedBit& align = u.live;

    // Range checks once (reused across metrics gated on same denominator).
    SharedBit inRange_income = rangeCheckShared(N, income, rc.income, triples, idx);
    SharedBit inRange_debt   = rangeCheckShared(N, debt,   rc.debt,   triples, idx);
    SharedBit inRange_emp    = rangeCheckShared(N, emp,    rc.emp,    triples, idx);

    // DTI: incl = align · b_MAS · b_DOS · v_debt · v_income · inRange_income
    auto makeIncl = [&](std::initializer_list<SharedBit> bits) {
        SharedBit acc = *bits.begin();
        auto it = bits.begin(); ++it;
        for (; it != bits.end(); ++it) acc = sand(acc, *it, triples, idx);
        return acc;
    };

    auto& mDTI = e.metrics[static_cast<size_t>(Metric::DTI)];
    mDTI.num = debt;
    mDTI.den = income;
    mDTI.incl = makeIncl({align, u.b_MAS, u.b_DOS, v_debt, v_income, inRange_income});

    auto& mDSI = e.metrics[static_cast<size_t>(Metric::DSI)];
    mDSI.num = dserv;
    mDSI.den = income;
    mDSI.incl = makeIncl({align, u.b_MAS, u.b_DOS, v_dserv, v_income, inRange_income});

    auto& mDEmp = e.metrics[static_cast<size_t>(Metric::DEmp)];
    mDEmp.num = debt;
    mDEmp.den = emp;
    mDEmp.incl = makeIncl({align, u.b_MAS, u.b_MOM, v_debt, v_emp, inRange_emp});

    auto& mIPW = e.metrics[static_cast<size_t>(Metric::IPW)];
    mIPW.num = income;
    mIPW.den = emp;
    mIPW.incl = makeIncl({align, u.b_DOS, u.b_MOM, v_income, v_emp, inRange_emp});

    auto& mDelq = e.metrics[static_cast<size_t>(Metric::Delq)];
    mDelq.num = delq;
    mDelq.den = debt;
    mDelq.incl = makeIncl({align, u.b_MAS, v_delq, v_debt, inRange_debt});

    auto& mNPL = e.metrics[static_cast<size_t>(Metric::NPL)];
    mNPL.num = npl;
    mNPL.den = debt;
    mNPL.incl = makeIncl({align, u.b_MAS, v_npl, v_debt, inRange_debt});

    auto& mUS = e.metrics[static_cast<size_t>(Metric::UnsecShare)];
    mUS.num = unsec;
    mUS.den = debt;
    mUS.incl = makeIncl({align, u.b_MAS, v_unsec, v_debt, inRange_debt});

    auto& mSD = e.metrics[static_cast<size_t>(Metric::StDebtShare)];
    mSD.num = stdebt;
    mSD.den = debt;
    mSD.incl = makeIncl({align, u.b_MAS, v_stdebt, v_debt, inRange_debt});

    // Gap: incl = align · b_MAS · b_DOS · v_gdebt · v_gincome.
    // Gap value is the signed difference; encoded by subtraction on shares
    // (subShared over the 64-bit u representation — see reconstruct helper).
    auto& mGap = e.metrics[static_cast<size_t>(Metric::Gap)];
    // Represent num as (g_MAS - g_DOS). Since SharedU64Bin XOR-shares each
    // bit, subtraction on the bit representation is not linear; the semantic
    // ref stored it via memcpy, but in the wire we keep num=debt-slot as a
    // placeholder and rely on downstream sector aggregation to handle gap
    // separately with an arithmetic-share subtractor. For now: num=g_MAS,
    // den=g_DOS; downstream will interpret (num, den) for Gap as signed diff.
    mGap.num = u.p_MAS.g;
    mGap.den = u.p_DOS.g;
    mGap.incl = makeIncl({align, u.b_MAS, u.b_DOS, v_gdebt, v_gincome});

    // Vuln coverage: avail_core_count = sum of 4 core incl bits (0..4).
    // We can compute it as a shared u64 by expressing each bit as u64 (only
    // low bit set) and summing arithmetic-shares. But we already have XOR-
    // shares; convert one bit to arithmetic-share via: bit_arith = XOR share
    // reconstructed → this leaks the plaintext, which we can't do here.
    //
    // Correct approach: represent avail_core_count as SharedU64Bin computed
    // via a bit-level adder tree (3 half-adders → 2-bit sum). For the size
    // 4 (values 0..4), the sum fits in 3 bits.
    //
    // For this first-pass wire we compute incl_vuln directly without
    // materializing the count:
    //   STRICT: incl_vuln = align · (incl_DTI · incl_DSI · incl_Delq · incl_NPL)
    //   RENORM: incl_vuln = align · (incl_DTI OR incl_DSI OR incl_Delq OR incl_NPL)
    // and set avail_core_count to a SharedU64Bin that's the arithmetic sum
    // computed via 3 half-adders on the four incl bits.

    if (vuln_policy == CoveragePolicy::STRICT_GATING) {
        SharedBit gate = makeIncl({align,
                                     mDTI.incl, mDSI.incl, mDelq.incl, mNPL.incl});
        e.incl_vuln = gate;
    } else {
        // OR of 4 bits: a OR b = a XOR b XOR (a AND b); build tree.
        auto sor = [&](const SharedBit& a, const SharedBit& b) {
            SharedBit ab = sand(a, b, triples, idx);
            SharedBit ax = xorShared(a, b);
            return xorShared(ax, ab);
        };
        SharedBit any = sor(mDTI.incl, mDSI.incl);
        any = sor(any, mDelq.incl);
        any = sor(any, mNPL.incl);
        e.incl_vuln = sand(align, any, triples, idx);
    }

    // Bit-level adder: sum of 4 bits into 3-bit result.
    // half_adder(a, b) → (sum = a XOR b, carry = a AND b).
    // full_adder(a, b, cin) → (sum = a XOR b XOR cin,
    //                          cout = (a AND b) OR (cin AND (a XOR b))).
    auto full_add = [&](const SharedBit& a, const SharedBit& b,
                         const SharedBit& cin,
                         SharedBit& sum, SharedBit& cout) {
        SharedBit ab = xorShared(a, b);
        sum = xorShared(ab, cin);
        SharedBit and_ab = sand(a, b, triples, idx);
        SharedBit and_cab = sand(cin, ab, triples, idx);
        // OR of and_ab and and_cab.
        SharedBit x = xorShared(and_ab, and_cab);
        SharedBit ac = sand(and_ab, and_cab, triples, idx);
        cout = xorShared(x, ac);
    };
    // Adding 4 bits: (b0 + b1) then + b2 then + b3.
    // Layer 1: half-adder of DTI + DSI.
    SharedBit s01 = xorShared(mDTI.incl, mDSI.incl);
    SharedBit c01 = sand(mDTI.incl, mDSI.incl, triples, idx);
    // Add Delq to (s01, c01) forming (s0, c0/1, c2).
    SharedBit s02, c02;
    SharedBit zero_bit(N);   // shared bit for constant 0 (already 0).
    full_add(s01, mDelq.incl, zero_bit, s02, c02);   // s02 low, c02 to carry into c1
    // Carry chain into bit 1: c01 XOR c02, and their AND is the carry to bit 2.
    SharedBit c1 = xorShared(c01, c02);
    SharedBit c1_carry = sand(c01, c02, triples, idx);
    // Add NPL to (s02, c1) → s0_final, c1_next
    SharedBit s0_final, c1_next;
    full_add(s02, mNPL.incl, zero_bit, s0_final, c1_next);
    // c1_next enters bit 1 alongside c1.
    SharedBit c1_final = xorShared(c1, c1_next);
    SharedBit c1_final_carry = sand(c1, c1_next, triples, idx);
    SharedBit c2_final = xorShared(c1_carry, c1_final_carry);
    // Encode avail_core_count in bit slots 0, 1, 2.
    SharedU64Bin acc;
    acc.bits[0] = s0_final;
    acc.bits[1] = c1_final;
    acc.bits[2] = c2_final;
    for (int i = 3; i < 64; ++i) acc.bits[i] = zero_bit;
    e.avail_core_count = acc;

    return e;
}

std::vector<SharedEntityMetricRow>
computeEntityMetricsWireBatch(const std::vector<SharedUnionRow>& rows,
                               const RangeConfig& rc,
                               CoveragePolicy vuln_policy,
                               const std::vector<BeaverTripleBit>& triples) {
    std::vector<SharedEntityMetricRow> out;
    out.reserve(rows.size());
    size_t idx = 0;
    for (const auto& r : rows) {
        out.push_back(computeEntityMetricsWire(r, rc, vuln_policy, triples, idx));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

SharedUnionRow shareUnionRow(uint32_t N, const UnionRow& u, oc::PRNG& prng) {
    SharedUnionRow s;
    s.bin = u.bin;
    s.period = u.period;
    s.sector = u.sector;
    s.sector_conflict = u.sector_conflict;
    s.b_MAS = shareBit(N, u.b_MAS, prng);
    s.b_DOS = shareBit(N, u.b_DOS, prng);
    s.b_MOM = shareBit(N, u.b_MOM, prng);
    s.live  = shareBit(N, u.live, prng);
    auto shareSrc = [&](const PayloadPerSource& p, SharedPayloadPerSource& sp) {
        for (size_t i = 0; i < kPayloadNumFields; ++i) {
            sp.v[i]     = shareU64Bin(N, p.v[i], prng);
            sp.valid[i] = shareBit(N, p.valid[i], prng);
        }
        sp.g   = shareU64Bin(N, p.g, prng);
        sp.v_g = shareBit(N, p.v_g, prng);
    };
    shareSrc(u.p_MAS, s.p_MAS);
    shareSrc(u.p_DOS, s.p_DOS);
    shareSrc(u.p_MOM, s.p_MOM);
    return s;
}

EntityMetricRow reconstructEntityMetricRow(const SharedEntityMetricRow& s) {
    EntityMetricRow r{};
    r.bin = s.bin;
    r.period = s.period;
    r.sector = s.sector;
    r.sector_conflict = s.sector_conflict;
    r.live = s.live.reconstruct();
    r.b_MAS = s.b_MAS.reconstruct();
    r.b_DOS = s.b_DOS.reconstruct();
    r.b_MOM = s.b_MOM.reconstruct();
    for (size_t i = 0; i < kMetricCount; ++i) {
        r.metrics[i].num  = s.metrics[i].num.reconstruct();
        r.metrics[i].den  = s.metrics[i].den.reconstruct();
        r.metrics[i].incl = s.metrics[i].incl.reconstruct();
    }
    r.incl_vuln = s.incl_vuln.reconstruct();
    r.avail_core_count = static_cast<uint8_t>(s.avail_core_count.reconstruct() & 0x7);
    return r;
}

} // namespace mpsvs
} // namespace volePSI
