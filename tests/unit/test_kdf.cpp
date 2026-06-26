// Offline unit tests for KDF correctness:
//   1. volePSI::mpstar::deriveSessionKey domain separation + determinism.
//   2. The min(i,j) || max(i,j) info-string trick used by MpStarSetup,
//      verified at the KDF layer (we recompute it standalone to confirm
//      symmetry — both sides produce the same key).
//
// Standalone: no external test framework, no network.

#include "volePSI/MpStarCrypto.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include <sodium.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;

static std::mt19937_64 rng(0xC0FFEEULL);

static std::array<uint8_t, 32> randomKey() {
    std::array<uint8_t, 32> k{};
    for (auto& b : k) b = static_cast<uint8_t>(rng() & 0xFF);
    return k;
}

// ----------------------------------------------------------------------

bool test_session_determinism() {
    auto base = randomKey();
    auto sid  = randomKey();
    auto k1 = mp::deriveSessionKey(base, sid, "purpose-x");
    auto k2 = mp::deriveSessionKey(base, sid, "purpose-x");
    return k1 == k2;
}

bool test_session_purpose_separation() {
    auto base = randomKey();
    auto sid  = randomKey();
    auto k1 = mp::deriveSessionKey(base, sid, "purpose-a");
    auto k2 = mp::deriveSessionKey(base, sid, "purpose-b");
    return k1 != k2;
}

bool test_session_sid_separation() {
    auto base = randomKey();
    auto sid1 = randomKey();
    auto sid2 = randomKey();
    auto k1 = mp::deriveSessionKey(base, sid1, "purpose");
    auto k2 = mp::deriveSessionKey(base, sid2, "purpose");
    return k1 != k2;
}

bool test_session_base_separation() {
    auto base1 = randomKey();
    auto base2 = randomKey();
    auto sid   = randomKey();
    auto k1 = mp::deriveSessionKey(base1, sid, "purpose");
    auto k2 = mp::deriveSessionKey(base2, sid, "purpose");
    return k1 != k2;
}

// Recompute the MpStarSetup KDF inline. Both sides (selfIdx=i sees peer=j,
// and selfIdx=j sees peer=i) should produce the same k_{i,j}.
static std::array<uint8_t, 32> setupKdf(const std::array<uint8_t, 32>& shared,
                                        uint32_t selfIdx, uint32_t peer)
{
    std::array<uint8_t, 32> out;
    oc::RandomOracle ro(32);
    ro.Update(shared.data(), shared.size());
    uint32_t a = std::min(selfIdx, peer);
    uint32_t b = std::max(selfIdx, peer);
    std::array<uint8_t, 8> info;
    info[0] = static_cast<uint8_t>(a >> 24);
    info[1] = static_cast<uint8_t>(a >> 16);
    info[2] = static_cast<uint8_t>(a >> 8);
    info[3] = static_cast<uint8_t>(a);
    info[4] = static_cast<uint8_t>(b >> 24);
    info[5] = static_cast<uint8_t>(b >> 16);
    info[6] = static_cast<uint8_t>(b >> 8);
    info[7] = static_cast<uint8_t>(b);
    ro.Update(info.data(), static_cast<uint32_t>(info.size()));
    ro.Final(out.data());
    return out;
}

bool test_setup_kdf_symmetric() {
    // Both endpoints share the same DH secret. Each independently runs the
    // KDF with their (selfIdx, peer) pair. The min/max trick must produce
    // the same key regardless of role direction.
    auto shared = randomKey();
    uint32_t i = 3;
    uint32_t j = 7;
    auto k_from_i = setupKdf(shared, i, j);
    auto k_from_j = setupKdf(shared, j, i);
    return k_from_i == k_from_j;
}

bool test_setup_kdf_pair_separation() {
    // Different pairs must produce different keys even with the same
    // shared secret (so a malicious party can't replay across pairs).
    auto shared = randomKey();
    auto k_pair_a = setupKdf(shared, 0, 1);
    auto k_pair_b = setupKdf(shared, 0, 2);
    auto k_pair_c = setupKdf(shared, 1, 2);
    return k_pair_a != k_pair_b
        && k_pair_a != k_pair_c
        && k_pair_b != k_pair_c;
}

// ----------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init() failed\n";
        return 2;
    }

    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"session_determinism",         test_session_determinism},
        {"session_purpose_separation",  test_session_purpose_separation},
        {"session_sid_separation",      test_session_sid_separation},
        {"session_base_separation",     test_session_base_separation},
        {"setup_kdf_symmetric",         test_setup_kdf_symmetric},
        {"setup_kdf_pair_separation",   test_setup_kdf_pair_separation},
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
