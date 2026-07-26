// Cleartext-parity test for secureAddU64Bin / secureSubU64Bin
// (bit-shared 64-bit arithmetic, foundation for the SP-blind vulnerability
// score protocol -- see docs/DESIGN_VULN_SCORE.md).
//
// Each test case:
//   1. Pre-generate enough Beaver bit triples for the operations.
//   2. Share x and y as SharedU64Bin via shareU64Bin(N=2, ...).
//   3. Run the secure op with a shared triple bag + cursor.
//   4. Reconstruct the result and compare to plain uint64 arithmetic
//      (wrapping at 2^64 for add, wrapping for sub too, borrowOut = (x<y)).
//   5. Verify the reported carry/borrow bit matches cleartext.

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

struct AddCase {
    uint64_t x, y;
    const char* name;
};

bool test_one_add(uint32_t N, uint64_t x, uint64_t y, const char* label) {
    oc::PRNG prng;
    oc::block seed;
    std::memset(&seed, 0x77, 16);
    prng.SetSeed(seed);

    auto triples = mp::generateBeaverTripleBits(
        N, mp::secureAddU64BinTripleCost(), prng);
    auto xs = mp::shareU64Bin(N, x, prng);
    auto ys = mp::shareU64Bin(N, y, prng);

    size_t idx = 0;
    auto res = mp::secureAddU64Bin(xs, ys, triples, idx);

    uint64_t expected_sum   = x + y;                    // wraps mod 2^64
    uint8_t  expected_carry = (expected_sum < x) ? 1 : 0; // canonical overflow test

    uint64_t got_sum   = res.sum.reconstruct();
    uint8_t  got_carry = res.carryOut.reconstruct() & 1;

    bool ok = (got_sum == expected_sum) && (got_carry == expected_carry);
    if (!ok) {
        std::cerr << "FAIL " << label << ": x=" << x << " y=" << y
                  << "\n  sum   got=0x" << std::hex << got_sum
                  << " expected=0x" << expected_sum
                  << "\n  carry got=" << std::dec << (int)got_carry
                  << " expected=" << (int)expected_carry << "\n";
    }
    // Sanity: exactly the expected number of triples consumed.
    if (idx != mp::secureAddU64BinTripleCost()) {
        std::cerr << "  triple accounting: consumed " << idx
                  << " expected " << mp::secureAddU64BinTripleCost() << "\n";
        return false;
    }
    return ok;
}

bool test_one_sub(uint32_t N, uint64_t x, uint64_t y, const char* label) {
    oc::PRNG prng;
    oc::block seed;
    std::memset(&seed, 0x88, 16);
    prng.SetSeed(seed);

    auto triples = mp::generateBeaverTripleBits(
        N, mp::secureSubU64BinTripleCost(), prng);
    auto xs = mp::shareU64Bin(N, x, prng);
    auto ys = mp::shareU64Bin(N, y, prng);

    size_t idx = 0;
    auto res = mp::secureSubU64Bin(xs, ys, triples, idx);

    uint64_t expected_diff   = x - y;                   // wraps mod 2^64
    uint8_t  expected_borrow = (x < y) ? 1 : 0;

    uint64_t got_diff   = res.diff.reconstruct();
    uint8_t  got_borrow = res.borrowOut.reconstruct() & 1;

    bool ok = (got_diff == expected_diff) && (got_borrow == expected_borrow);
    if (!ok) {
        std::cerr << "FAIL " << label << ": x=" << x << " y=" << y
                  << "\n  diff   got=0x" << std::hex << got_diff
                  << " expected=0x" << expected_diff
                  << "\n  borrow got=" << std::dec << (int)got_borrow
                  << " expected=" << (int)expected_borrow << "\n";
    }
    if (idx != mp::secureSubU64BinTripleCost()) {
        std::cerr << "  triple accounting: consumed " << idx
                  << " expected " << mp::secureSubU64BinTripleCost() << "\n";
        return false;
    }
    return ok;
}

} // namespace

int main() {
    int failures = 0;
    const uint32_t N = 2;

    // ---- ADD tests ----
    AddCase cases[] = {
        {0, 0, "0+0"},
        {1, 0, "1+0"},
        {0, 1, "0+1"},
        {42, 100, "42+100"},
        {(1ULL << 32) - 1, 1, "u32-max + 1 (carry into bit 32)"},
        {(1ULL << 32), (1ULL << 32), "2^32 + 2^32"},
        {0xFFFFFFFFFFFFFFFFULL, 1, "u64-max + 1 (overflow to 0)"},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, "u64-max + u64-max"},
        {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, "hex-hex-full-width"},
    };
    for (const auto& c : cases) {
        bool ok = test_one_add(N, c.x, c.y, c.name);
        std::cout << "[add] " << c.name << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- SUB tests ----
    struct SubCase { uint64_t x, y; const char* name; };
    SubCase subCases[] = {
        {0, 0, "0-0"},
        {1, 0, "1-0"},
        {100, 42, "100-42"},
        {42, 100, "42-100 (borrow, wraps)"},
        {(1ULL << 32), 1, "2^32 - 1"},
        {0, 1, "0-1 (underflow to u64-max)"},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL, "u64-max - (u64-max - 1)"},
        {0x8000000000000000ULL, 0x7FFFFFFFFFFFFFFFULL, "sign-boundary"},
        {0xDEADBEEFCAFEBABEULL, 0xFEEDFACEDEADBEEFULL, "x<y bignum"},
    };
    for (const auto& c : subCases) {
        bool ok = test_one_sub(N, c.x, c.y, c.name);
        std::cout << "[sub] " << c.name << ": " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // ---- Random property tests ----
    std::mt19937_64 rng(0x1234);
    for (int i = 0; i < 32; ++i) {
        uint64_t x = rng();
        uint64_t y = rng();
        if (!test_one_add(N, x, y, "rand-add")) ++failures;
        if (!test_one_sub(N, x, y, "rand-sub")) ++failures;
    }
    std::cout << "[rand] 32 random pairs of add+sub: "
              << (failures == 0 ? "PASS" : "FAIL") << "\n";

    // ---- N=3 spot-check ----
    for (int i = 0; i < 5; ++i) {
        uint64_t x = rng();
        uint64_t y = rng();
        if (!test_one_add(3, x, y, "N=3 add")) ++failures;
        if (!test_one_sub(3, x, y, "N=3 sub")) ++failures;
    }
    std::cout << "[N=3] 5 random add+sub triples: "
              << (failures == 0 ? "PASS" : "FAIL") << "\n";

    if (failures == 0) {
        std::cout << "ALL PASSED\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " tests failed\n";
    return 1;
}
