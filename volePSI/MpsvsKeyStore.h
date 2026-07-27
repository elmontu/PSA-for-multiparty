#pragma once

// MPSVS Key Store — abstract persistent store for long-term identities.
//
// Manages secret material that must survive across sessions:
//
//   1. Party long-term X25519 identity keys (mutual authentication in
//      MpsvsSecureChannel).
//   2. SPDZ α MAC keys per session (SPDZ tuples are generated once and
//      used across many operations within the session; α must not be
//      re-sampled mid-session and must be reproducible for audit replay).
//   3. Threshold-DH-OPRF DKG share (S1's k1, S2's k2), if the ceremony
//      persists these rather than re-running DKG each release.
//   4. Encrypted audit-log HMAC key (for tamper-evident chain).
//
// Two backends are provided:
//
//   - `FileKeyStore` — a single encrypted file (libsodium
//     `crypto_secretstream_xchacha20poly1305`, full re-write on each
//     mutation). Master key is derived from a passphrase via Argon2id
//     (`crypto_pwhash`, INTERACTIVE cost — ~250 ms/derive; sufficient
//     with a strong passphrase, but bump to SENSITIVE for high-value
//     stores if the ~1 s derivation cost is acceptable at process start).
//     File format is a bespoke length-prefixed binary encoding — NOT
//     JSON — chosen to minimise plaintext-observability of key metadata.
//     Suitable for dev and small-team production where an HSM is not
//     yet procured.
//
//   - `HsmKeyStore` — stub interface for PKCS#11-backed HSMs (SafeNet
//     Luna, YubiHSM 2, cloud HSMs). Currently throws `std::logic_error`
//     with a documented attachment point. The intent is that regulators
//     will require this backend before production launch, and the
//     concrete PKCS#11 code lives here when written.
//
// Threat model for FileKeyStore:
//   - Confidentiality: full-disk-encrypted file at rest, secretstream
//     for authenticated encryption per record. An attacker who steals
//     the file cannot decrypt without the passphrase.
//   - Integrity: secretstream provides MAC per chunk. Tampering detected
//     on read.
//   - Available: single-node file, not replicated. Callers must arrange
//     backup/replication separately.
//   - Passphrase strength: Argon2id with `crypto_pwhash_OPSLIMIT_SENSITIVE`
//     and `MEMLIMIT_SENSITIVE` — costs ~1 GB RAM, ~1s CPU. Weak passphrases
//     still weak.

#include "MpsvsProdHygiene.h"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// KeyRecord — a single named secret.
// ---------------------------------------------------------------------------

enum class KeyPurpose : uint8_t {
    UNKNOWN            = 0,
    PARTY_LONGTERM_X25519 = 1,   // 32 bytes: X25519 secret key
    SPDZ_ALPHA_U64        = 2,   // 8 bytes: MAC α mod 2^64
    DKG_SHARE_32          = 3,   // 32 bytes: OPRF DKG partial key
    AUDIT_HMAC_KEY_32     = 4,   // 32 bytes: audit chain HMAC key
    APP_DEFINED           = 99,  // caller-defined purpose (opaque)
};

const char* keyPurposeName(KeyPurpose p);

struct KeyRecord {
    std::string   key_id;         // canonical identifier (e.g. "MAS.longterm.v1")
    KeyPurpose    purpose = KeyPurpose::UNKNOWN;
    uint64_t      created_unix_s = 0;
    uint32_t      version = 1;
    // secret body — length determined by purpose (see enum comments).
    std::vector<uint8_t> secret;
};

// ---------------------------------------------------------------------------
// Abstract interface.
// ---------------------------------------------------------------------------

class IKeyStore {
public:
    virtual ~IKeyStore() = default;

    // Store or overwrite a record. Throws on IO / crypto failure.
    virtual void putKey(const KeyRecord& rec) = 0;

    // Retrieve a record by id. Throws if missing.
    virtual KeyRecord getKey(const std::string& key_id) const = 0;

    // Check existence without throwing.
    virtual bool hasKey(const std::string& key_id) const = 0;

    // List all known key ids (for audit).
    virtual std::vector<std::string> listKeyIds() const = 0;

    // Delete a record. Throws if missing.
    virtual void deleteKey(const std::string& key_id) = 0;

    // Zeroise all in-memory copies of secret material. The backing store
    // remains intact. Callers should invoke this on shutdown.
    virtual void zeroiseMemory() = 0;
};

// ---------------------------------------------------------------------------
// FileKeyStore — encrypted-at-rest, single-file.
// ---------------------------------------------------------------------------

class FileKeyStore : public IKeyStore {
public:
    // Open (or create) an encrypted store at `path` using `passphrase`.
    // Throws std::runtime_error on IO, KDF, or authenticator failure.
    // File format:
    //   magic(8)  version(4)  argon2_salt(crypto_pwhash_SALTBYTES = 16)
    //   secretstream_header(crypto_secretstream_..._HEADERBYTES = 24)
    //   ciphertext body (single secretstream frame with TAG_FINAL)
    // The body decrypts to a length-prefixed binary encoding of records.
    FileKeyStore(std::string path, const std::string& passphrase);
    ~FileKeyStore() override;

    void putKey(const KeyRecord& rec) override;
    KeyRecord getKey(const std::string& key_id) const override;
    bool hasKey(const std::string& key_id) const override;
    std::vector<std::string> listKeyIds() const override;
    void deleteKey(const std::string& key_id) override;
    void zeroiseMemory() override;

private:
    void flushToDiskLocked() const;   // caller holds mutex_

    std::string path_;
    // Master key derived once from passphrase; zeroised on dtor.
    std::array<uint8_t, crypto_secretstream_xchacha20poly1305_KEYBYTES> master_key_{};
    // Salt cached from disk / freshly generated at bootstrap. Immutable
    // for the lifetime of this FileKeyStore.
    std::array<uint8_t, crypto_pwhash_SALTBYTES> salt_{};
    // Guards records_ and disk flushes.
    mutable std::mutex mutex_;
    std::vector<KeyRecord> records_;
};

// ---------------------------------------------------------------------------
// HsmKeyStore — stub for PKCS#11 HSM integration.
// ---------------------------------------------------------------------------

// Attachment point for production HSM. Left as a stub deliberately — a real
// PKCS#11 implementation is out of scope for the reference build. Callers
// that want to swap in an HSM implement this interface (or the base
// IKeyStore) directly, without touching MPSVS protocol code.
//
// TODO(deployment):
//   - Load pkcs11 library via C_GetFunctionList
//   - C_Initialize, C_OpenSession with slot pin
//   - Map key_id → PKCS#11 CKA_LABEL
//   - putKey → C_GenerateKey (never returns secret to caller for
//     PARTY_LONGTERM_X25519) — signing/kx becomes an HSM operation
//   - getKey → refuses to export secret; return handle wrapper
//   - Sign/kx operations must call back into HSM
//
// Once wrapped this way, IKeyStore's getKey() cannot return raw secrets
// for the classes of keys the HSM is authoritative over — callers of
// SPDZ_ALPHA_U64 etc. that need the plaintext must use FileKeyStore
// or (better) a hybrid store that HSM-wraps only the identity key.
class HsmKeyStore : public IKeyStore {
public:
    HsmKeyStore();
    ~HsmKeyStore() override;

    void putKey(const KeyRecord& rec) override;
    KeyRecord getKey(const std::string& key_id) const override;
    bool hasKey(const std::string& key_id) const override;
    std::vector<std::string> listKeyIds() const override;
    void deleteKey(const std::string& key_id) override;
    void zeroiseMemory() override;
};

// ---------------------------------------------------------------------------
// Convenience factories.
// ---------------------------------------------------------------------------

// Open a FileKeyStore, creating an empty encrypted file if it does not
// exist. Wrapper for the common case.
std::unique_ptr<IKeyStore> openFileKeyStore(const std::string& path,
                                              const std::string& passphrase);

} // namespace mpsvs
} // namespace volePSI
