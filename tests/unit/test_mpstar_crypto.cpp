// Offline unit tests for volePSI/MpStarCrypto.h.
// No external test framework: assertions + main()-returns-nonzero pattern.
// Run after build: ./test_mpstar_crypto ; echo $?

#include "volePSI/MpStarCrypto.h"
#include "cryptoTools/Common/block.h"
#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;

static std::mt19937_64 rng(0x12345ULL);

static std::array<uint8_t, 32> randomKey() {
    std::array<uint8_t, 32> k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(rng() & 0xFF);
    return k;
}

static oc::block randomBlock() {
    uint64_t a = rng();
    uint64_t b = rng();
    oc::block blk;
    std::memcpy(reinterpret_cast<uint8_t*>(&blk),         &a, sizeof(a));
    std::memcpy(reinterpret_cast<uint8_t*>(&blk) + 8,     &b, sizeof(b));
    return blk;
}

static std::vector<oc::block> randomBlocks(size_t n) {
    std::vector<oc::block> v(n);
    for (auto& b : v) b = randomBlock();
    return v;
}

// ---------------------------------------------------------------------------

bool test_aead_roundtrip() {
    auto key = randomKey();
    std::vector<uint8_t> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    auto ct = mp::aeadEncrypt(plain, key);
    auto dec = mp::aeadDecrypt(ct, key);
    return dec == plain;
}

bool test_aead_empty_plain() {
    auto key = randomKey();
    std::vector<uint8_t> plain;
    auto ct = mp::aeadEncrypt(plain, key);
    auto dec = mp::aeadDecrypt(ct, key);
    return dec.empty();
}

bool test_aead_mac_mismatch() {
    auto key = randomKey();
    std::vector<uint8_t> plain = {1, 2, 3};
    auto ct = mp::aeadEncrypt(plain, key);
    ct.back() ^= 0xFF;                       // flip a MAC bit
    try {
        mp::aeadDecrypt(ct, key);
        return false;
    } catch (...) { return true; }
}

bool test_aead_nonce_mismatch() {
    auto key = randomKey();
    std::vector<uint8_t> plain = {4, 5, 6};
    auto ct = mp::aeadEncrypt(plain, key);
    ct[0] ^= 0xFF;                           // flip a nonce bit
    try {
        mp::aeadDecrypt(ct, key);
        return false;
    } catch (...) { return true; }
}

bool test_aead_wrong_key() {
    auto k1 = randomKey();
    auto k2 = randomKey();
    std::vector<uint8_t> plain = {7, 8, 9};
    auto ct = mp::aeadEncrypt(plain, k1);
    try {
        mp::aeadDecrypt(ct, k2);
        return false;
    } catch (...) { return true; }
}

bool test_aead_short_input() {
    auto key = randomKey();
    std::vector<uint8_t> tooShort;          // empty — under NONCE+MAC
    try {
        mp::aeadDecrypt(tooShort, key);
        return false;
    } catch (...) { return true; }
}

bool test_serialize_roundtrip() {
    constexpr size_t N = 100;
    auto blocks = randomBlocks(N);
    auto data = mp::serializeBlocks(blocks);
    auto out = mp::deserializeBlocks(data, N);
    if (out.size() != N) return false;
    for (size_t i = 0; i < N; ++i) {
        if (std::memcmp(&blocks[i], &out[i], sizeof(oc::block)) != 0) return false;
    }
    return true;
}

bool test_deserialize_wrong_count() {
    constexpr size_t N = 100;
    auto blocks = randomBlocks(N);
    auto data = mp::serializeBlocks(blocks);
    try {
        mp::deserializeBlocks(data, N * 2);
        return false;
    } catch (...) { return true; }
}

bool test_empty_blocks() {
    std::vector<oc::block> empty;
    auto data = mp::serializeBlocks(empty);
    if (!data.empty()) return false;
    auto out = mp::deserializeBlocks(data, 0);
    return out.empty();
}

// ---------------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init() failed\n";
        return 2;
    }

    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"aead_roundtrip",        test_aead_roundtrip},
        {"aead_empty_plain",      test_aead_empty_plain},
        {"aead_mac_mismatch",     test_aead_mac_mismatch},
        {"aead_nonce_mismatch",   test_aead_nonce_mismatch},
        {"aead_wrong_key",        test_aead_wrong_key},
        {"aead_short_input",      test_aead_short_input},
        {"serialize_roundtrip",   test_serialize_roundtrip},
        {"deserialize_wrong_cnt", test_deserialize_wrong_count},
        {"empty_blocks",          test_empty_blocks},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try {
            if (fn()) {
                std::cout << "PASS\n";
            } else {
                std::cout << "FAIL\n";
                ++failures;
            }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")\n";
            ++failures;
        } catch (...) {
            std::cout << "FAIL (unknown exception)\n";
            ++failures;
        }
    }

    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
