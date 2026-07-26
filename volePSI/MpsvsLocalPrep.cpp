#include "MpsvsLocalPrep.h"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// ID normaliser
// ---------------------------------------------------------------------------

// Kept punctuation set stripped (spec §6 "normalise identifiers"). We keep
// alphanumerics only after case-folding + trimming.
static std::string normaliseString(const std::string& raw) {
    // Trim leading/trailing whitespace
    size_t first = raw.find_first_not_of(" \t\r\n");
    size_t last  = raw.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    std::string trimmed = raw.substr(first, last - first + 1);

    // Lowercase + strip non-alphanumerics
    std::string out;
    out.reserve(trimmed.size());
    for (char c : trimmed) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc)) {
            out.push_back(static_cast<char>(std::tolower(uc)));
        }
    }
    return out;
}

CanonicalId normaliseId(const std::string& raw_id, const IdNormaliserConfig& cfg) {
    std::string normalised = normaliseString(raw_id);

    // Prepend versioned pepper: "<pepper>|<version>|<normalised>"
    std::ostringstream oss;
    oss << cfg.pepper << "|" << cfg.version << "|" << normalised;
    std::string material = oss.str();

    CanonicalId out{};
    // SHA-256 via libsodium (crypto_hash_sha256 -> 32 bytes)
    crypto_hash_sha256(out.data(),
                       reinterpret_cast<const unsigned char*>(material.data()),
                       material.size());
    return out;
}

// ---------------------------------------------------------------------------
// Range-check helper
// ---------------------------------------------------------------------------

static AttrStatus checkAttr(const RawU64& raw, const AttrRange& range,
                            std::vector<std::string>& warnings,
                            const char* attr_name) {
    AttrStatus st{};
    if (!raw.present) {
        st.non_missing = 0;
        st.valid       = 0;
        warnings.emplace_back(std::string(attr_name) + ": missing");
        return st;
    }
    st.non_missing = 1;
    if (raw.value >= range.min_incl && raw.value <= range.max_incl) {
        st.valid = 1;
    } else {
        st.valid = 0;
        warnings.emplace_back(std::string(attr_name) + ": out of range ["
                              + std::to_string(range.min_incl) + ", "
                              + std::to_string(range.max_incl) + "] got "
                              + std::to_string(raw.value));
    }
    return st;
}

// ---------------------------------------------------------------------------
// prepareMas / prepareDos / prepareMom
// ---------------------------------------------------------------------------

PreparedMasRecord prepareMas(const RawMasInputs& in,
                             const MasAttrRanges& ranges,
                             const IdNormaliserConfig& id_cfg) {
    PreparedMasRecord out{};
    std::memset(&out.payload, 0, sizeof(out.payload));

    out.payload.entity_id           = normaliseId(in.raw_entity_id, id_cfg);
    out.payload.period              = in.period;
    out.payload.sector_code         = in.sector_code;
    out.payload.loan_membership_bit = in.loan_member ? 1 : 0;
    out.payload.schema_version      = static_cast<uint8_t>(kSchemaVersion);

    out.payload.st_total_debt      = checkAttr(in.total_outstanding_debt,
                                               ranges.total_debt,
                                               out.local_warnings, "total_debt");
    out.payload.st_debt_service    = checkAttr(in.annual_debt_service,
                                               ranges.debt_service,
                                               out.local_warnings, "debt_service");
    out.payload.st_delinquent      = checkAttr(in.delinquent_loan_balance,
                                               ranges.delinquent,
                                               out.local_warnings, "delinquent");
    out.payload.st_nonperforming   = checkAttr(in.nonperforming_loan_balance,
                                               ranges.nonperforming,
                                               out.local_warnings, "nonperforming");
    out.payload.st_unsecured       = checkAttr(in.unsecured_loan_balance,
                                               ranges.unsecured,
                                               out.local_warnings, "unsecured");
    out.payload.st_due_12m         = checkAttr(in.debt_due_within_12_months,
                                               ranges.due_12m,
                                               out.local_warnings, "due_12m");

    // Store raw values ONLY if present AND valid. Otherwise sentinel = 0
    // (the AttrStatus bits gate downstream use; a stored 0 must NEVER be
    // interpreted as data). Use memcpy because the struct is __packed__
    // and taking a reference to a mis-aligned field is UB.
    auto put = [](void* dst, const RawU64& src, AttrStatus st) {
        FixedPointU64 v = (st.non_missing && st.valid) ? src.value : 0;
        std::memcpy(dst, &v, sizeof(v));
    };
    put(&out.payload.total_outstanding_debt,     in.total_outstanding_debt,     out.payload.st_total_debt);
    put(&out.payload.annual_debt_service,        in.annual_debt_service,        out.payload.st_debt_service);
    put(&out.payload.delinquent_loan_balance,    in.delinquent_loan_balance,    out.payload.st_delinquent);
    put(&out.payload.nonperforming_loan_balance, in.nonperforming_loan_balance, out.payload.st_nonperforming);
    put(&out.payload.unsecured_loan_balance,     in.unsecured_loan_balance,     out.payload.st_unsecured);
    put(&out.payload.debt_due_within_12_months,  in.debt_due_within_12_months,  out.payload.st_due_12m);

    return out;
}

PreparedDosRecord prepareDos(const RawDosInputs& in,
                             const DosAttrRanges& ranges,
                             const IdNormaliserConfig& id_cfg) {
    PreparedDosRecord out{};
    std::memset(&out.payload, 0, sizeof(out.payload));

    out.payload.entity_id             = normaliseId(in.raw_entity_id, id_cfg);
    out.payload.period                = in.period;
    out.payload.sector_code           = in.sector_code;
    out.payload.income_membership_bit = in.income_member ? 1 : 0;
    out.payload.schema_version        = static_cast<uint8_t>(kSchemaVersion);

    out.payload.st_annual_income     = checkAttr(in.annual_income,     ranges.annual_income,
                                                 out.local_warnings, "annual_income");
    out.payload.st_revenue           = checkAttr(in.revenue,           ranges.revenue,
                                                 out.local_warnings, "revenue");
    out.payload.st_operating_surplus = checkAttr(in.operating_surplus, ranges.operating_surplus,
                                                 out.local_warnings, "operating_surplus");

    auto put = [](void* dst, const RawU64& src, AttrStatus st) {
        FixedPointU64 v = (st.non_missing && st.valid) ? src.value : 0;
        std::memcpy(dst, &v, sizeof(v));
    };
    put(&out.payload.annual_income,     in.annual_income,     out.payload.st_annual_income);
    put(&out.payload.revenue,           in.revenue,           out.payload.st_revenue);
    put(&out.payload.operating_surplus, in.operating_surplus, out.payload.st_operating_surplus);

    return out;
}

PreparedMomRecord prepareMom(const RawMomInputs& in,
                             const MomAttrRanges& ranges,
                             const IdNormaliserConfig& id_cfg) {
    PreparedMomRecord out{};
    std::memset(&out.payload, 0, sizeof(out.payload));

    out.payload.entity_id               = normaliseId(in.raw_entity_id, id_cfg);
    out.payload.period                  = in.period;
    out.payload.sector_code             = in.sector_code;
    out.payload.manpower_membership_bit = in.manpower_member ? 1 : 0;
    out.payload.schema_version          = static_cast<uint8_t>(kSchemaVersion);

    out.payload.st_employment    = checkAttr(in.employment_count,       ranges.employment,
                                             out.local_warnings, "employment");
    out.payload.st_labour_force  = checkAttr(in.labour_force_count,     ranges.labour_force,
                                             out.local_warnings, "labour_force");
    out.payload.st_working_age   = checkAttr(in.working_age_population, ranges.working_age,
                                             out.local_warnings, "working_age");
    out.payload.st_unemployment  = checkAttr(in.unemployment_count,     ranges.unemployment,
                                             out.local_warnings, "unemployment");
    out.payload.st_retrenchment  = checkAttr(in.retrenchment_count,     ranges.retrenchment,
                                             out.local_warnings, "retrenchment");
    out.payload.st_vacancy       = checkAttr(in.vacancy_count,          ranges.vacancy,
                                             out.local_warnings, "vacancy");

    auto put = [](void* dst, const RawU64& src, AttrStatus st) {
        FixedPointU64 v = (st.non_missing && st.valid) ? src.value : 0;
        std::memcpy(dst, &v, sizeof(v));
    };
    put(&out.payload.employment_count,       in.employment_count,       out.payload.st_employment);
    put(&out.payload.labour_force_count,     in.labour_force_count,     out.payload.st_labour_force);
    put(&out.payload.working_age_population, in.working_age_population, out.payload.st_working_age);
    put(&out.payload.unemployment_count,     in.unemployment_count,     out.payload.st_unemployment);
    put(&out.payload.retrenchment_count,     in.retrenchment_count,     out.payload.st_retrenchment);
    put(&out.payload.vacancy_count,          in.vacancy_count,          out.payload.st_vacancy);

    return out;
}

// ---------------------------------------------------------------------------
// Dummy envelope builders
// ---------------------------------------------------------------------------

// Fill entity_id with 32 random bytes so different dummies don't collide
// on the same handle and cause false alignment in Phase 4.
static void fillRandomId(CanonicalId& id) {
    randombytes_buf(id.data(), id.size());
}

PreparedMasRecord dummyMas(const ReportingPeriod& period, SectorCode sector) {
    PreparedMasRecord r{};
    std::memset(&r.payload, 0, sizeof(r.payload));
    fillRandomId(r.payload.entity_id);
    r.payload.period              = period;
    r.payload.sector_code         = sector;
    r.payload.loan_membership_bit = 0;
    r.payload.schema_version      = static_cast<uint8_t>(kSchemaVersion);
    // All AttrStatus bits already zero. All numeric fields already zero.
    return r;
}

PreparedDosRecord dummyDos(const ReportingPeriod& period, SectorCode sector) {
    PreparedDosRecord r{};
    std::memset(&r.payload, 0, sizeof(r.payload));
    fillRandomId(r.payload.entity_id);
    r.payload.period                = period;
    r.payload.sector_code           = sector;
    r.payload.income_membership_bit = 0;
    r.payload.schema_version        = static_cast<uint8_t>(kSchemaVersion);
    return r;
}

PreparedMomRecord dummyMom(const ReportingPeriod& period, SectorCode sector) {
    PreparedMomRecord r{};
    std::memset(&r.payload, 0, sizeof(r.payload));
    fillRandomId(r.payload.entity_id);
    r.payload.period                  = period;
    r.payload.sector_code             = sector;
    r.payload.manpower_membership_bit = 0;
    r.payload.schema_version          = static_cast<uint8_t>(kSchemaVersion);
    return r;
}

// ---------------------------------------------------------------------------
// Duplicate detection
// ---------------------------------------------------------------------------

namespace {
struct IdPeriodKey {
    CanonicalId     id;
    ReportingPeriod p;
    bool operator<(const IdPeriodKey& o) const {
        if (id != o.id) return std::lexicographical_compare(
            id.begin(), id.end(), o.id.begin(), o.id.end());
        if (p.year != o.p.year) return p.year < o.p.year;
        return p.quarter < o.p.quarter;
    }
};
}

template <typename R>
std::vector<size_t> findDuplicateIndices(const std::vector<R>& records) {
    std::map<IdPeriodKey, size_t> seen;
    std::vector<size_t> dups;
    for (size_t i = 0; i < records.size(); ++i) {
        IdPeriodKey k{records[i].payload.entity_id, records[i].payload.period};
        auto it = seen.find(k);
        if (it == seen.end()) {
            seen.emplace(k, i);
        } else {
            dups.push_back(i);
        }
    }
    return dups;
}

// Explicit instantiations
template std::vector<size_t> findDuplicateIndices<PreparedMasRecord>(const std::vector<PreparedMasRecord>&);
template std::vector<size_t> findDuplicateIndices<PreparedDosRecord>(const std::vector<PreparedDosRecord>&);
template std::vector<size_t> findDuplicateIndices<PreparedMomRecord>(const std::vector<PreparedMomRecord>&);

} // namespace mpsvs
} // namespace volePSI
