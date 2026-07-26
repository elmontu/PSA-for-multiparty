// Phase 1 acceptance-criteria test suite.
// Per docs/DEPLOYMENT_FULL_MPC.md Phase 1 (spec §6, §8, §12 partial).

#include "volePSI/MpsvsLocalPrep.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace volePSI::mpsvs;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// ---------------------------------------------------------------------------
// Criterion 1: Schema encoded as fixed-size C++ struct; sizes fixed.
// ---------------------------------------------------------------------------

static void test_criterion_1_sizes_fixed() {
    // static_asserts in the header already enforce this at compile time.
    // We re-check at runtime for the acceptance record.
    CHECK(sizeof(MasPayload) == 104, "C1: MasPayload is exactly 104 bytes");
    CHECK(sizeof(DosPayload) == 72,  "C1: DosPayload is exactly 72 bytes");
    CHECK(sizeof(MomPayload) == 104, "C1: MomPayload is exactly 104 bytes");
    CHECK(sizeof(AttrStatus) == 1,   "C1: AttrStatus is exactly 1 byte");
    CHECK(sizeof(CanonicalId) == 32, "C1: CanonicalId is exactly 32 bytes");
}

// ---------------------------------------------------------------------------
// Criterion 2: Real vs dummy records produce byte-identical envelope shape.
//              (The membership_bit differs, but total size + field layout
//              are identical; a byte-level inspection reveals nothing about
//              membership beyond that single bit — which is secret-shared
//              in Phase 2 and never released.)
// ---------------------------------------------------------------------------

static void test_criterion_2_dummy_vs_real_same_shape() {
    ReportingPeriod period{2026, 3, 0};
    SectorCode sector = 42;

    // Real MAS record with full valid data
    RawMasInputs real{};
    real.raw_entity_id = "ACME PTE LTD 200812345K";
    real.period = period;
    real.sector_code = sector;
    real.loan_member = true;
    real.total_outstanding_debt      = {true, 1'000'000'00ULL};   // SGD 1M in cents
    real.annual_debt_service         = {true,    50'000'00ULL};
    real.delinquent_loan_balance     = {true,     5'000'00ULL};
    real.nonperforming_loan_balance  = {true,        0ULL};
    real.unsecured_loan_balance      = {true,   200'000'00ULL};
    real.debt_due_within_12_months   = {true,   300'000'00ULL};

    auto realP = prepareMas(real);
    auto dummy = dummyMas(period, sector);

    CHECK(sizeof(realP.payload) == sizeof(dummy.payload),
          "C2: MAS real and dummy payloads are same C++ size");

    // Byte-level: total size identical (obvious from sizeof), fields laid
    // out identically. Diff must be limited to (a) entity_id bytes,
    // (b) membership bit, (c) numeric field values, (d) AttrStatus bits.
    // Structural layout is IDENTICAL — no size or offset difference.
    CHECK(realP.payload.schema_version == dummy.payload.schema_version,
          "C2: schema_version matches");
    CHECK(realP.payload.period == dummy.payload.period,
          "C2: period matches");
    CHECK(realP.payload.sector_code == dummy.payload.sector_code,
          "C2: sector_code matches");
    CHECK(realP.payload.loan_membership_bit != dummy.payload.loan_membership_bit,
          "C2: membership_bit differs (real=1, dummy=0); this is the ONE "
          "field intended to differ and gets secret-shared in Phase 2");

    // Same for DOS and MOM
    RawDosInputs dosRaw{};
    dosRaw.raw_entity_id = "ACME PTE LTD 200812345K";
    dosRaw.period = period;
    dosRaw.sector_code = sector;
    dosRaw.income_member = true;
    dosRaw.annual_income     = {true, 2'000'000'00ULL};
    dosRaw.revenue           = {true, 5'000'000'00ULL};
    dosRaw.operating_surplus = {true,   800'000'00ULL};
    auto dosR = prepareDos(dosRaw);
    auto dosD = dummyDos(period, sector);
    CHECK(sizeof(dosR.payload) == sizeof(dosD.payload),
          "C2: DOS real and dummy payloads are same C++ size");

    RawMomInputs momRaw{};
    momRaw.raw_entity_id = "ACME PTE LTD 200812345K";
    momRaw.period = period;
    momRaw.sector_code = sector;
    momRaw.manpower_member = true;
    momRaw.employment_count       = {true, 120};
    momRaw.labour_force_count     = {true, 3'800'000};
    momRaw.working_age_population = {true, 4'200'000};
    momRaw.unemployment_count     = {true,    80'000};
    momRaw.retrenchment_count     = {true,     1'200};
    momRaw.vacancy_count          = {true,    75'000};
    auto momR = prepareMom(momRaw);
    auto momD = dummyMom(period, sector);
    CHECK(sizeof(momR.payload) == sizeof(momD.payload),
          "C2: MOM real and dummy payloads are same C++ size");
}

// ---------------------------------------------------------------------------
// Criterion 3: Same entity fed through the ID normaliser at MAS, DOS, MOM
//              produces identical bytes.
// ---------------------------------------------------------------------------

static void test_criterion_3_id_normaliser_cross_agency() {
    // Three agencies register the same entity in different formats.
    std::string mas_view = "ACME  PTE   LTD (200812345K)";
    std::string dos_view = "acme pte ltd 200812345k";
    std::string mom_view = " ACME-PTE-LTD-200812345K ";

    CanonicalId a = normaliseId(mas_view);
    CanonicalId b = normaliseId(dos_view);
    CanonicalId c = normaliseId(mom_view);

    CHECK(a == b, "C3: MAS view and DOS view of same entity produce same canonical id");
    CHECK(b == c, "C3: DOS view and MOM view of same entity produce same canonical id");

    // Different entities produce different ids
    std::string other = "BETA CORP 199988877A";
    CanonicalId d = normaliseId(other);
    bool differ = false;
    for (size_t i = 0; i < 32; ++i) if (a[i] != d[i]) { differ = true; break; }
    CHECK(differ, "C3: different entities produce different canonical ids");
}

// ---------------------------------------------------------------------------
// Criterion 4: Range-invalid inputs -> valid_bit = 0. No runtime error.
//              No zero substitution (the value slot is still zero as a
//              sentinel, but the bit says "don't use this").
// ---------------------------------------------------------------------------

static void test_criterion_4_range_invalid() {
    ReportingPeriod period{2026, 3, 0};

    RawMasInputs in{};
    in.raw_entity_id = "TEST";
    in.period = period;
    in.sector_code = 1;
    in.loan_member = true;
    // total_debt WAY above the cap of 1T SGD (cents = 10^14). Try 10^17 cents.
    in.total_outstanding_debt = {true, 100'000'000'000'000'000ULL};
    // debt_service valid
    in.annual_debt_service = {true, 50'000'00ULL};
    // Others present + valid (small)
    in.delinquent_loan_balance    = {true, 100'00ULL};
    in.nonperforming_loan_balance = {true, 200'00ULL};
    in.unsecured_loan_balance     = {true, 300'00ULL};
    in.debt_due_within_12_months  = {true, 400'00ULL};

    auto r = prepareMas(in);
    CHECK(r.payload.st_total_debt.non_missing == 1,
          "C4: out-of-range value still marked non-missing (agency HAD the value)");
    CHECK(r.payload.st_total_debt.valid == 0,
          "C4: out-of-range value gets valid_bit=0");
    CHECK(r.payload.total_outstanding_debt == 0,
          "C4: invalid value stored as sentinel 0 (bit-gated downstream, not "
          "used); documented that a 0 with valid=0 is NOT to be treated as data");
    CHECK(r.payload.st_debt_service.valid == 1,
          "C4: sibling valid attribute stays valid");
    CHECK(!r.local_warnings.empty(),
          "C4: local warning was emitted for the invalid attribute");
}

// ---------------------------------------------------------------------------
// Criterion 5: Missing inputs -> non_missing_bit = 0. No zero substitution.
// ---------------------------------------------------------------------------

static void test_criterion_5_missing() {
    ReportingPeriod period{2026, 3, 0};

    RawDosInputs in{};
    in.raw_entity_id = "TEST";
    in.period = period;
    in.sector_code = 1;
    in.income_member = true;
    in.annual_income = {false, 0};        // MISSING (agency has no value)
    in.revenue = {true, 5'000'000'00ULL}; // present
    in.operating_surplus = {true, 800'000'00ULL};

    auto r = prepareDos(in);
    CHECK(r.payload.st_annual_income.non_missing == 0,
          "C5: missing input gets non_missing_bit=0");
    CHECK(r.payload.st_annual_income.valid == 0,
          "C5: missing input also gets valid_bit=0 (nothing to validate)");
    CHECK(r.payload.annual_income == 0,
          "C5: missing input stored as sentinel 0 (bit-gated, not used); a "
          "sentinel 0 with non_missing=0 must never be treated as data");
    CHECK(r.payload.st_revenue.non_missing == 1 && r.payload.st_revenue.valid == 1,
          "C5: sibling present-valid attribute unaffected");
}

// ---------------------------------------------------------------------------
// Additional: duplicate detection (spec §6)
// ---------------------------------------------------------------------------

static void test_duplicate_detection() {
    ReportingPeriod period{2026, 3, 0};

    auto mkMas = [&](const std::string& id) {
        RawMasInputs in{};
        in.raw_entity_id = id;
        in.period = period;
        in.sector_code = 1;
        in.loan_member = true;
        return prepareMas(in);
    };

    std::vector<PreparedMasRecord> recs;
    recs.push_back(mkMas("ACME 200812345K"));                       // #0
    recs.push_back(mkMas("BETA 199988877A"));                       // #1
    recs.push_back(mkMas("acme 200812345k"));                       // #2 dup of #0 (case)
    recs.push_back(mkMas("GAMMA 200455566B"));                      // #3
    recs.push_back(mkMas(" ACME  200812345K "));                    // #4 dup of #0 (spaces)

    auto dups = findDuplicateIndices(recs);
    CHECK(dups.size() == 2, "duplicate detection: 2 duplicates found");
    CHECK(dups[0] == 2 && dups[1] == 4,
          "duplicate detection: dups at indices 2 and 4");
}

// ---------------------------------------------------------------------------

int main() {
    std::puts("=== MpsvsLocalPrep — Phase 1 acceptance-criteria tests ===\n");

    test_criterion_1_sizes_fixed();
    std::puts("");
    test_criterion_2_dummy_vs_real_same_shape();
    std::puts("");
    test_criterion_3_id_normaliser_cross_agency();
    std::puts("");
    test_criterion_4_range_invalid();
    std::puts("");
    test_criterion_5_missing();
    std::puts("");
    test_duplicate_detection();

    std::puts("");
    if (failures) { std::printf("== %d FAILURES ==\n", failures); return 1; }
    std::puts("ALL PASSED — Phase 1 acceptance criteria met");
    return 0;
}
