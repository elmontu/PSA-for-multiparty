// MPSVS KeyStore tests: bootstrap, encryption at rest, put/get/list/delete,
// tampering detection, wrong passphrase rejection.

#include "volePSI/MpsvsKeyStore.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static std::string g_path;
static void unlinkStore() { if (!g_path.empty()) std::remove(g_path.c_str()); }

static KeyRecord makeRecord(const std::string& id, KeyPurpose p, size_t n) {
    KeyRecord r;
    r.key_id = id;
    r.purpose = p;
    r.created_unix_s = 1000000000ULL;
    r.version = 1;
    r.secret.resize(n);
    for (size_t i = 0; i < n; ++i)
        r.secret[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    return r;
}

static void test_bootstrap_and_reopen() {
    std::printf("--- C1: bootstrap empty store, reopen with same passphrase ---\n");
    unlinkStore();
    {
        FileKeyStore ks(g_path, "pass-alpha");
        CHECK(ks.listKeyIds().empty(), "C1a: fresh store is empty");
    }
    {
        FileKeyStore ks(g_path, "pass-alpha");
        CHECK(ks.listKeyIds().empty(), "C1b: reopened store still empty");
    }
}

static void test_put_get_roundtrip() {
    std::printf("--- C2: put/get record roundtrip ---\n");
    unlinkStore();
    KeyRecord r = makeRecord("MAS.longterm.v1", KeyPurpose::PARTY_LONGTERM_X25519, 32);
    {
        FileKeyStore ks(g_path, "pw");
        ks.putKey(r);
    }
    {
        FileKeyStore ks(g_path, "pw");
        CHECK(ks.hasKey("MAS.longterm.v1"), "C2a: key present after reopen");
        KeyRecord got = ks.getKey("MAS.longterm.v1");
        CHECK(got.purpose == r.purpose,               "C2b: purpose preserved");
        CHECK(got.secret == r.secret,                 "C2c: secret bytes preserved");
        CHECK(got.created_unix_s == r.created_unix_s, "C2d: ts preserved");
    }
}

static void test_multiple_keys() {
    std::printf("--- C3: multiple keys coexist ---\n");
    unlinkStore();
    {
        FileKeyStore ks(g_path, "pw");
        ks.putKey(makeRecord("A", KeyPurpose::SPDZ_ALPHA_U64, 8));
        ks.putKey(makeRecord("B", KeyPurpose::DKG_SHARE_32, 32));
        ks.putKey(makeRecord("C", KeyPurpose::AUDIT_HMAC_KEY_32, 32));
    }
    FileKeyStore ks(g_path, "pw");
    CHECK(ks.listKeyIds().size() == 3, "C3a: 3 keys listed");
    CHECK(ks.hasKey("A") && ks.hasKey("B") && ks.hasKey("C"),
          "C3b: all keys present");
}

static void test_overwrite() {
    std::printf("--- C4: putKey overwrites existing id ---\n");
    unlinkStore();
    FileKeyStore ks(g_path, "pw");
    KeyRecord a = makeRecord("dup", KeyPurpose::SPDZ_ALPHA_U64, 8);
    ks.putKey(a);
    KeyRecord b = makeRecord("dup", KeyPurpose::SPDZ_ALPHA_U64, 8);
    b.secret[0] = 0xFF;   // distinguishable content
    ks.putKey(b);
    KeyRecord got = ks.getKey("dup");
    CHECK(got.secret[0] == 0xFF, "C4a: overwrite retains new value");
    CHECK(ks.listKeyIds().size() == 1, "C4b: still only one entry");
}

static void test_delete() {
    std::printf("--- C5: deleteKey removes record ---\n");
    unlinkStore();
    FileKeyStore ks(g_path, "pw");
    ks.putKey(makeRecord("gone", KeyPurpose::SPDZ_ALPHA_U64, 8));
    ks.deleteKey("gone");
    CHECK(!ks.hasKey("gone"), "C5: key removed");
    bool threw = false;
    try { ks.deleteKey("gone"); } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C5b: deleting missing key throws");
}

static void test_wrong_passphrase_rejected() {
    std::printf("--- C6: wrong passphrase yields auth failure on decrypt ---\n");
    unlinkStore();
    {
        FileKeyStore ks(g_path, "correct-pw");
        ks.putKey(makeRecord("x", KeyPurpose::SPDZ_ALPHA_U64, 8));
    }
    bool threw = false;
    try {
        FileKeyStore ks(g_path, "wrong-pw");
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C6: wrong passphrase throws (auth tag mismatch)");
}

static void test_tampered_file_detected() {
    std::printf("--- C7: bit-flip in ciphertext detected ---\n");
    unlinkStore();
    {
        FileKeyStore ks(g_path, "pw");
        ks.putKey(makeRecord("t", KeyPurpose::SPDZ_ALPHA_U64, 8));
    }
    // Flip a byte in the encrypted body (well past the header).
    std::fstream f(g_path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekg(0, std::ios::end);
    auto end = f.tellg();
    f.seekp(static_cast<std::streamoff>(end) - 10);
    char b;
    f.read(&b, 1);
    b ^= 0x01;
    f.seekp(static_cast<std::streamoff>(end) - 10);
    f.write(&b, 1);
    f.close();
    bool threw = false;
    try {
        FileKeyStore ks(g_path, "pw");
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "C7: tampered file rejected on open");
}

static void test_secrets_not_visible_in_file() {
    std::printf("--- C8: secret bytes are NOT visible in raw file ---\n");
    unlinkStore();
    KeyRecord r = makeRecord("secret1", KeyPurpose::AUDIT_HMAC_KEY_32, 32);
    // Make the secret trivially findable if plaintext:
    for (int i = 0; i < 32; ++i) r.secret[i] = 0xA5;
    {
        FileKeyStore ks(g_path, "pw");
        ks.putKey(r);
    }
    // Scan file for a run of 0xA5A5A5A5 — should NOT appear.
    std::ifstream f(g_path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
    bool found_plain = false;
    for (size_t i = 0; i + 4 <= content.size(); ++i) {
        if ((uint8_t)content[i] == 0xA5 && (uint8_t)content[i+1] == 0xA5 &&
            (uint8_t)content[i+2] == 0xA5 && (uint8_t)content[i+3] == 0xA5) {
            found_plain = true;
            break;
        }
    }
    CHECK(!found_plain, "C8: 0xA5-run absent from encrypted file");
}

static void test_hsm_stub_throws() {
    std::printf("--- C9: HsmKeyStore stub throws logic_error ---\n");
    HsmKeyStore hsm;
    bool threw = false;
    try { hsm.putKey(makeRecord("x", KeyPurpose::SPDZ_ALPHA_U64, 8)); }
    catch (const std::logic_error&) { threw = true; }
    CHECK(threw, "C9a: putKey throws logic_error");
    CHECK(!hsm.hasKey("x"), "C9b: hasKey returns false (safe default)");
    CHECK(hsm.listKeyIds().empty(), "C9c: listKeyIds empty");
}

static void test_missing_key_throws() {
    std::printf("--- C10: getKey on unknown id throws ---\n");
    unlinkStore();
    FileKeyStore ks(g_path, "pw");
    bool threw = false;
    try { (void)ks.getKey("does-not-exist"); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw, "C10: missing key throws");
}

static void test_factory() {
    std::printf("--- C11: openFileKeyStore factory ---\n");
    unlinkStore();
    auto ks = openFileKeyStore(g_path, "pw");
    ks->putKey(makeRecord("f", KeyPurpose::SPDZ_ALPHA_U64, 8));
    CHECK(ks->hasKey("f"), "C11: factory-built store works");
}

int main() {
    ensureSodiumInit();
    // Unique temp path per pid to avoid cross-process interference.
    char buf[128];
    std::snprintf(buf, sizeof(buf), "/tmp/mpsvs_ks_test_%d.bin", (int)getpid());
    g_path = buf;
    std::printf("=== MPSVS KeyStore (path: %s) ===\n\n", g_path.c_str());

    test_bootstrap_and_reopen();
    test_put_get_roundtrip();
    test_multiple_keys();
    test_overwrite();
    test_delete();
    test_wrong_passphrase_rejected();
    test_tampered_file_detected();
    test_secrets_not_visible_in_file();
    test_hsm_stub_throws();
    test_missing_key_throws();
    test_factory();

    unlinkStore();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — KeyStore encrypted-at-rest works end-to-end.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
