#pragma once

// MPSVS Phase 1 — Local preparation & payload schema.
//
// Per docs/PROTOCOL.md Phase 1 (spec §6, §8, §12 partial).
//
// This module runs LOCALLY at each agency (MAS, DOS, MOM) BEFORE any
// cross-agency protocol step. It produces validated, fixed-length,
// membership-hiding envelope bytes ready for Phase 2 (OPRF handle
// emission + client peer-mesh secret-sharing).
//
// Invariants enforced (checked in tests/unit/test_mpsvs_local_prep.cpp):
//   * Schema encoded as fixed-size structs; sizes fixed at compile time.
//   * Two records with different membership status but same field types
//     produce byte-identical externally-visible envelopes.
//   * Same entity fed through the ID normaliser at MAS, DOS, MOM produces
//     identical bytes (deterministic, cross-agency consistent).
//   * Range-invalid inputs -> validity_bit = 0; never runtime error;
//     never zero substitution of the numeric value.
//   * Missing inputs -> non_missing_bit = 0; never zero substitution.
//
// This module DOES NOT:
//   * Run any cryptographic protocol.
//   * Send anything on the wire.
//   * Interact with the SP.
//   * Compute any ratio.
// Those come in later Phases.
//
// Versioning (spec §6): the schema and normaliser are versioned constants.
// A schema/normaliser bump is a governance event (spec §24).

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Versioning constants (spec §6 + §22)
// ---------------------------------------------------------------------------

constexpr uint32_t kSchemaVersion         = 1;
constexpr uint32_t kIdNormaliserVersion   = 1;
constexpr uint32_t kSectorTaxonomyVersion = 1;  // e.g. SSIC 2-digit

// ---------------------------------------------------------------------------
// Canonical types
// ---------------------------------------------------------------------------

// 32-byte deterministic identifier (SHA-256 of normalise(id) with versioned
// pepper). Deterministic across agencies for the same entity.
// This is the LOCAL canonical form. Phase 2 turns this into a protected
// handle via server-aided OPRF.
using CanonicalId = std::array<uint8_t, 32>;

// Canonical reporting period tag. Encoding: (year<<8) | quarter (or 0=annual).
struct ReportingPeriod {
    uint16_t year;
    uint8_t  quarter;   // 1..4; 0 = annual
    uint8_t  reserved;  // must be 0

    bool operator==(const ReportingPeriod& o) const {
        return year == o.year && quarter == o.quarter && reserved == o.reserved;
    }
};

// Canonical sector code (SSIC 2-digit by default; extensible per taxonomy).
// 0 = unknown / dummy sentinel.
using SectorCode = uint16_t;

// Fixed-point numeric attribute. All monetary values are u64 in SGD cents
// (scale = 100), giving 63 bits of magnitude (~9.2 × 10^16 SGD). Counts
// (employment, unemployment, etc.) are u64 exact. Rates in bps × 100
// (basis-points-hundredths) as u64.
using FixedPointU64 = uint64_t;

// ---------------------------------------------------------------------------
// Per-attribute bits
// ---------------------------------------------------------------------------

// For every numeric attribute in a payload we track TWO independent bits:
//   * non_missing_bit : 1 iff the source has an actual value for this
//                       attribute (not NULL / not blank / not sentinel).
//   * validity_bit    : 1 iff that value passes the per-attribute range
//                       check (>= min, <= max, not NaN-like, sign check).
// Missing values are NEVER converted to zero. Range-invalid values are
// NEVER converted to zero. Both cases are surfaced via the bits; the
// stored numeric field is retained as-observed for audit, but its
// downstream contribution is gated by these bits.

struct AttrStatus {
    uint8_t non_missing : 1;
    uint8_t valid       : 1;
    uint8_t reserved    : 6;  // must be 0 (padding for fixed size)
};
static_assert(sizeof(AttrStatus) == 1, "AttrStatus must be 1 byte");

// ---------------------------------------------------------------------------
// MAS payload schema (spec §2 MAS holds)
// ---------------------------------------------------------------------------

struct MasPayload {
    CanonicalId     entity_id;                          // 32 B
    ReportingPeriod period;                             //  4 B
    SectorCode      sector_code;                        //  2 B
    uint8_t         loan_membership_bit;                //  1 B (1 = real, 0 = dummy)
    uint8_t         schema_version;                     //  1 B  (= kSchemaVersion)

    FixedPointU64   total_outstanding_debt;             //  8 B (SGD cents)
    FixedPointU64   annual_debt_service;                //  8 B (SGD cents)
    FixedPointU64   delinquent_loan_balance;            //  8 B
    FixedPointU64   nonperforming_loan_balance;         //  8 B
    FixedPointU64   unsecured_loan_balance;             //  8 B
    FixedPointU64   debt_due_within_12_months;          //  8 B

    // One AttrStatus per numeric attribute above (6 attributes).
    AttrStatus      st_total_debt;
    AttrStatus      st_debt_service;
    AttrStatus      st_delinquent;
    AttrStatus      st_nonperforming;
    AttrStatus      st_unsecured;
    AttrStatus      st_due_12m;

    uint8_t         reserved[10];                       // pad to 104 B total

    // Layout invariants: fixed-length; no dynamic sizing; identical size
    // and byte layout for real vs dummy records.
} __attribute__((packed));
static_assert(sizeof(MasPayload) == 104, "MasPayload must be 104 bytes");

// ---------------------------------------------------------------------------
// DOS payload schema (spec §2 DOS holds)
// ---------------------------------------------------------------------------

struct DosPayload {
    CanonicalId     entity_id;                          // 32 B
    ReportingPeriod period;                             //  4 B
    SectorCode      sector_code;                        //  2 B
    uint8_t         income_membership_bit;              //  1 B
    uint8_t         schema_version;                     //  1 B

    FixedPointU64   annual_income;                      //  8 B
    FixedPointU64   revenue;                            //  8 B
    FixedPointU64   operating_surplus;                  //  8 B

    AttrStatus      st_annual_income;
    AttrStatus      st_revenue;
    AttrStatus      st_operating_surplus;

    uint8_t         reserved[5];                        // pad to 72 B

    // 40 + 32 = 72
} __attribute__((packed));
static_assert(sizeof(DosPayload) == 72, "DosPayload must be 72 bytes");

// ---------------------------------------------------------------------------
// MOM payload schema (spec §2 MOM holds)
// ---------------------------------------------------------------------------

struct MomPayload {
    CanonicalId     entity_id;                          // 32 B
    ReportingPeriod period;                             //  4 B
    SectorCode      sector_code;                        //  2 B
    uint8_t         manpower_membership_bit;            //  1 B
    uint8_t         schema_version;                     //  1 B

    FixedPointU64   employment_count;                   //  8 B
    FixedPointU64   labour_force_count;                 //  8 B
    FixedPointU64   working_age_population;             //  8 B
    FixedPointU64   unemployment_count;                 //  8 B
    FixedPointU64   retrenchment_count;                 //  8 B
    FixedPointU64   vacancy_count;                      //  8 B

    AttrStatus      st_employment;
    AttrStatus      st_labour_force;
    AttrStatus      st_working_age;
    AttrStatus      st_unemployment;
    AttrStatus      st_retrenchment;
    AttrStatus      st_vacancy;

    uint8_t         reserved[10];                       // pad to 104 B

    // 32 + 4 + 2 + 1 + 1 + 48 + 6 + 10 = 104
} __attribute__((packed));
static_assert(sizeof(MomPayload) == 104, "MomPayload must be 104 bytes");

// ---------------------------------------------------------------------------
// ID normaliser (spec §6)
// ---------------------------------------------------------------------------

// Config for the normaliser. `pepper` is a run-INDEPENDENT constant that
// pins the taxonomy; it is NOT the per-run OPRF key (that comes in Phase 2).
// This is the "pre-OPRF canonicalisation" — same across all runs of the
// same schema version.
struct IdNormaliserConfig {
    uint32_t version = kIdNormaliserVersion;
    // Fixed pepper string bound to the schema version; not secret, but must
    // be identical at all agencies.
    std::string pepper = "MPSVS-canonical-id-v1";
};

// Normalise a raw agency-provided id string into a canonical 32-byte digest.
//
// Steps:
//   1. Trim leading/trailing whitespace.
//   2. Lowercase (ASCII).
//   3. Remove punctuation: [.,;:'\"/\\()\[\]-_ ] (kept alphanumerics).
//   4. Prepend pepper + version + '|' separator.
//   5. SHA-256; return first 32 bytes.
//
// Deterministic across agencies: same raw id in -> same digest out.
CanonicalId normaliseId(const std::string& raw_id,
                        const IdNormaliserConfig& cfg = {});

// ---------------------------------------------------------------------------
// Range-check policy per attribute (spec §12)
// ---------------------------------------------------------------------------

struct AttrRange {
    FixedPointU64 min_incl;
    FixedPointU64 max_incl;
};

struct MasAttrRanges {
    AttrRange total_debt         = { 0, 100'000'000'000'000ULL };  // <= SGD 1T (cents)
    AttrRange debt_service       = { 0, 100'000'000'000'000ULL };
    AttrRange delinquent         = { 0, 100'000'000'000'000ULL };
    AttrRange nonperforming      = { 0, 100'000'000'000'000ULL };
    AttrRange unsecured          = { 0, 100'000'000'000'000ULL };
    AttrRange due_12m            = { 0, 100'000'000'000'000ULL };
};

struct DosAttrRanges {
    AttrRange annual_income      = { 0, 100'000'000'000'000ULL };
    AttrRange revenue            = { 0, 100'000'000'000'000ULL };
    AttrRange operating_surplus  = { 0, 100'000'000'000'000ULL };
};

struct MomAttrRanges {
    AttrRange employment         = { 0, 10'000'000ULL };
    AttrRange labour_force       = { 0, 10'000'000ULL };
    AttrRange working_age        = { 0, 10'000'000ULL };
    AttrRange unemployment       = { 0, 10'000'000ULL };
    AttrRange retrenchment       = { 0, 1'000'000ULL };
    AttrRange vacancy            = { 0, 1'000'000ULL };
};

// ---------------------------------------------------------------------------
// Envelope builders (spec §8 + §12)
// ---------------------------------------------------------------------------

// Result of preparing a payload from local raw values.
// Missing / invalid inputs set the AttrStatus bits accordingly; the stored
// numeric fields for those attributes are set to a sentinel (0), but the
// bits gate their downstream contribution. This is the ONLY place a zero
// may appear alongside a 0-bit; downstream never treats these as valid.
struct PreparedMasRecord {
    MasPayload payload;
    // Extra diagnostics for local audit (never sent).
    std::vector<std::string> local_warnings;
};
struct PreparedDosRecord {
    DosPayload payload;
    std::vector<std::string> local_warnings;
};
struct PreparedMomRecord {
    MomPayload payload;
    std::vector<std::string> local_warnings;
};

// Raw local inputs. `present` = agency has an actual value (whether or not
// it passes range check). `value` is used only if `present`.
struct RawU64 {
    bool          present = false;
    FixedPointU64 value   = 0;
};

struct RawMasInputs {
    std::string     raw_entity_id;   // agency-native id (any format)
    ReportingPeriod period;
    SectorCode      sector_code;
    bool            loan_member = true;  // false only if the "record" is a padding dummy

    RawU64 total_outstanding_debt;
    RawU64 annual_debt_service;
    RawU64 delinquent_loan_balance;
    RawU64 nonperforming_loan_balance;
    RawU64 unsecured_loan_balance;
    RawU64 debt_due_within_12_months;
};

struct RawDosInputs {
    std::string     raw_entity_id;
    ReportingPeriod period;
    SectorCode      sector_code;
    bool            income_member = true;

    RawU64 annual_income;
    RawU64 revenue;
    RawU64 operating_surplus;
};

struct RawMomInputs {
    std::string     raw_entity_id;
    ReportingPeriod period;
    SectorCode      sector_code;
    bool            manpower_member = true;

    RawU64 employment_count;
    RawU64 labour_force_count;
    RawU64 working_age_population;
    RawU64 unemployment_count;
    RawU64 retrenchment_count;
    RawU64 vacancy_count;
};

// Build a fully-populated envelope from raw inputs. Per-attribute bits are
// derived. Missing => non_missing = 0. Range-invalid => valid = 0. Neither
// case replaces the raw value with zero except in the sense that the
// stored field must be some value (we store 0 as a canonical sentinel and
// the bit gates its use downstream).
PreparedMasRecord prepareMas(const RawMasInputs& in,
                             const MasAttrRanges& ranges = {},
                             const IdNormaliserConfig& id_cfg = {});
PreparedDosRecord prepareDos(const RawDosInputs& in,
                             const DosAttrRanges& ranges = {},
                             const IdNormaliserConfig& id_cfg = {});
PreparedMomRecord prepareMom(const RawMomInputs& in,
                             const MomAttrRanges& ranges = {},
                             const IdNormaliserConfig& id_cfg = {});

// Build a DUMMY envelope for padding to bucket size B (Phase 2 uses this).
// Dummy envelopes are BYTE-IDENTICAL in shape to real envelopes:
//   * membership_bit = 0
//   * entity_id      = random (per call)
//   * period / sector = same run-wide canonical values
//   * numeric fields = 0, non_missing_bit = 0, valid_bit = 0
// The external byte-length and structure are indistinguishable from a real
// record. Only the membership_bit (which is later secret-shared) differs.
PreparedMasRecord dummyMas(const ReportingPeriod& period, SectorCode sector);
PreparedDosRecord dummyDos(const ReportingPeriod& period, SectorCode sector);
PreparedMomRecord dummyMom(const ReportingPeriod& period, SectorCode sector);

// ---------------------------------------------------------------------------
// Duplicate detection (spec §6, §11 partial — enforced fully in Phase 4)
// ---------------------------------------------------------------------------

// Given a set of prepared records from ONE agency, report duplicates at
// (entity_id, period). Returns the indices of duplicate records. Callers
// should REMOVE duplicates before Phase 2 (per spec §6 "remove invalid or
// duplicate entity-period records").
template <typename R>
std::vector<size_t> findDuplicateIndices(const std::vector<R>& records);

} // namespace mpsvs
} // namespace volePSI
