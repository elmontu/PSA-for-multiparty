// Cleartext-parity test for secureDivideU64Bin (bit-shared 64-bit unsigned
// integer division). Building block for the per-firm vuln-score ratio
// pipeline — see docs/DESIGN_VULN_SCORE_V2.md.
//
// Verifies:
//   1. Correctness across representative (num, denom) cases including
//      boundary values and known-ratio financial-style inputs.
//   2. Division-by-zero returns divByZero=1 (caller must mask).
//   3. Exact triple accounting (idx advance == secureDivideU64BinTripleCost).
//   4. Random property tests.

#include "volePSI/MpMpcArithmetic.h"
#include "volePSI/MpSecureCompare.h"
#include "volePSI/MpBeaverTriple.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

namespace mp = volePSI::mpstar;

namespace {

int failures = 0;

// Test one (num, denom) pair. Returns true iff correct.
bool test_one(uint32_t N, uint64_t num, uint64_t denom, const char* label) {
    oc::PRNG prng;
    oc::block seed;
    std::memset(&seed, 0x99, 16);
    prng.SetSeed(seed);

    // Cleartext expected values.
    uint64_t expected_q, expected_r;
    uint8_t  expected_dbz;
    if (denom == 0) {
        // Per API: on divByZero, quotient = 2^64-1 (all ones), remainder = num.
        // See comment in secureDivideU64Bin implementation.
        expected_q   = 0xFFFFFFFFFFFFFFFFULL;
        expected_r   = num;
        expected_dbz = 1;
    } else {
        expected_q   = num / denom;
        expected_r   = num % denom;
        expected_dbz = 0;
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::secureDivideU64BinTripleCost(), prng);
    auto ns = mp::shareU64Bin(N, num, prng);
    auto ds = mp::shareU64Bin(N, denom, prng);

    size_t idx = 0;
    auto res = mp::secureDivideU64Bin(ns, ds, triples, idx);

    uint64_t got_q  = res.quotient.reconstruct();
    uint64_t got_r  = res.remainder.reconstruct();
    uint8_t  got_dbz = res.divByZero.reconstruct() & 1;

    bool ok = (got_q == expected_q) && (got_r == expected_r) &&
              (got_dbz == expected_dbz);
    if (!ok) {
        std::cerr << "FAIL " << label << ": num=" << num << " denom=" << denom
                  << "\n  q   got=" << got_q  << " expected=" << expected_q
                  << "\n  r   got=" << got_r  << " expected=" << expected_r
                  << "\n  dbz got=" << (int)got_dbz << " expected=" << (int)expected_dbz
                  << "\n";
    }
    if (idx != mp::secureDivideU64BinTripleCost()) {
        std::cerr << "  triple accounting: consumed " << idx
                  << " expected " << mp::secureDivideU64BinTripleCost() << "\n";
        return false;
    }
    return ok;
}

struct Case { uint64_t num, denom; const char* label; };

} // namespace

int main() {
    const uint32_t N = 2;

    // ---- Small integer parity cases ----
    Case basics[] = {
        {0,     1,   "0 / 1"},
        {1,     1,   "1 / 1"},
        {7,     3,   "7 / 3"},
        {100,   5,   "100 / 5"},
        {100,   7,   "100 / 7"},
        {100,   100, "100 / 100"},
        {99,    100, "99 / 100 (quotient=0)"},
        {1000,  1,   "1000 / 1"},
    };
    for (const auto& c : basics) {
        bool ok = test_one(N, c.num, c.denom, c.label);
        std::cout << "[basic] " << c.label << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- Financial-style fixed-point cases (scale 10^6) ----
    // loan_to_income = (loan_A + loan_B) / income, values in cents scaled by 10^6.
    // 15M loan A + 20M loan B, 30M income -> 1.166666... ratio => 1166666 fixed-point
    // (numerator = 35M * 10^6 = 35e12, denominator = 30M = 3e7)
    Case financial[] = {
        {35'000'000ULL * 1'000'000ULL, 30'000'000ULL, "loan_to_income ~1.17 (fixed pt)"},
        {50'000'000ULL * 1'000'000ULL, 100'000'000ULL, "loan_to_income = 0.5"},
        {500'000'000ULL * 1'000'000ULL, 100'000'000ULL, "loan_to_income = 5.0"},
        {1'000ULL, 3'000ULL, "small ratio 1000/3000"},
    };
    for (const auto& c : financial) {
        bool ok = test_one(N, c.num, c.denom, c.label);
        std::cout << "[financial] " << c.label << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- Boundary cases ----
    Case boundary[] = {
        {0xFFFFFFFFFFFFFFFFULL, 1, "u64max / 1"},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, "u64max / u64max"},
        {0xFFFFFFFFFFFFFFFFULL, 2, "u64max / 2"},
        {(1ULL << 63), 2, "2^63 / 2"},
        {(1ULL << 32), (1ULL << 16), "2^32 / 2^16"},
    };
    for (const auto& c : boundary) {
        bool ok = test_one(N, c.num, c.denom, c.label);
        std::cout << "[boundary] " << c.label << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- Division by zero ----
    Case dbz[] = {
        {0,     0, "0 / 0"},
        {42,    0, "42 / 0"},
        {0xFFFFFFFFFFFFFFFFULL, 0, "u64max / 0"},
    };
    for (const auto& c : dbz) {
        bool ok = test_one(N, c.num, c.denom, c.label);
        std::cout << "[divByZero] " << c.label << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- Random property test ----
    std::mt19937_64 rng(0xBEEF);
    for (int i = 0; i < 20; ++i) {
        uint64_t num   = rng();
        uint64_t denom = rng() | 1;   // avoid the div-by-zero surprise here
        if (!test_one(N, num, denom, "rand")) ++failures;
    }
    std::cout << "[random] 20 random pairs: "
              << (failures == 0 ? "PASS" : "FAIL") << "\n";

    // ---- N=3 spot check ----
    for (int i = 0; i < 3; ++i) {
        uint64_t num   = rng();
        uint64_t denom = rng() | 1;
        if (!test_one(3, num, denom, "N=3")) ++failures;
    }
    std::cout << "[N=3] 3 spot-checks: "
              << (failures == 0 ? "PASS" : "FAIL") << "\n";

    if (failures == 0) {
        std::cout << "ALL PASSED\n";
        std::cout << "Cost per division: " << mp::secureDivideU64BinTripleCost()
                  << " Beaver bit-triples\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " tests failed\n";
    return 1;
}
