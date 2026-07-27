#include "MpsvsKeyStore.h"

#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Purpose-name lookup
// ---------------------------------------------------------------------------

const char* keyPurposeName(KeyPurpose p) {
    switch (p) {
        case KeyPurpose::UNKNOWN: return "UNKNOWN";
        case KeyPurpose::PARTY_LONGTERM_X25519: return "PARTY_LONGTERM_X25519";
        case KeyPurpose::SPDZ_ALPHA_U64: return "SPDZ_ALPHA_U64";
        case KeyPurpose::DKG_SHARE_32: return "DKG_SHARE_32";
        case KeyPurpose::AUDIT_HMAC_KEY_32: return "AUDIT_HMAC_KEY_32";
        case KeyPurpose::APP_DEFINED: return "APP_DEFINED";
    }
    return "??";
}

// ---------------------------------------------------------------------------
// File format constants & helpers
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t kMagic = 0x4d505356534b5301ULL;
constexpr uint32_t kFileVersion = 1;
constexpr size_t kSaltBytes = crypto_pwhash_SALTBYTES;

void appendU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((v >> (8*i)) & 0xFF);
}
void appendU64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back((v >> (8*i)) & 0xFF);
}
void appendBytes(std::vector<uint8_t>& b, const void* p, size_t n) {
    const uint8_t* q = static_cast<const uint8_t*>(p);
    b.insert(b.end(), q, q + n);
}
uint32_t readU32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
uint64_t readU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t(p[i]) << (8*i));
    return v;
}

std::vector<uint8_t> serialiseRecords(const std::vector<KeyRecord>& recs) {
    std::vector<uint8_t> b;
    appendU32(b, static_cast<uint32_t>(recs.size()));
    for (const auto& r : recs) {
        if (r.key_id.size() > 4096)
            throw std::runtime_error("KeyStore: key_id too long (>4096B)");
        if (r.secret.size() > (1u << 20))
            throw std::runtime_error("KeyStore: secret too large (>1MB)");
        appendU32(b, static_cast<uint32_t>(r.key_id.size()));
        appendBytes(b, r.key_id.data(), r.key_id.size());
        b.push_back(static_cast<uint8_t>(r.purpose));
        appendU64(b, r.created_unix_s);
        appendU32(b, r.version);
        appendU32(b, static_cast<uint32_t>(r.secret.size()));
        appendBytes(b, r.secret.data(), r.secret.size());
    }
    return b;
}

std::vector<KeyRecord> deserialiseRecords(const uint8_t* p, size_t n) {
    if (n < 4) throw std::runtime_error("KeyStore body: truncated header");
    uint32_t count = readU32(p); p += 4; n -= 4;
    std::vector<KeyRecord> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (n < 4) throw std::runtime_error("KeyStore body: truncated key_id_len");
        uint32_t klen = readU32(p); p += 4; n -= 4;
        if (klen > 4096) throw std::runtime_error("KeyStore body: key_id length invalid");
        if (n < klen) throw std::runtime_error("KeyStore body: truncated key_id");
        KeyRecord r;
        r.key_id.assign(reinterpret_cast<const char*>(p), klen);
        p += klen; n -= klen;

        if (n < 1 + 8 + 4 + 4) throw std::runtime_error("KeyStore body: truncated meta");
        r.purpose = static_cast<KeyPurpose>(*p); p += 1; n -= 1;
        r.created_unix_s = readU64(p); p += 8; n -= 8;
        r.version = readU32(p); p += 4; n -= 4;
        uint32_t slen = readU32(p); p += 4; n -= 4;
        if (slen > (1u << 20))
            throw std::runtime_error("KeyStore body: secret length invalid");
        if (n < slen) throw std::runtime_error("KeyStore body: truncated secret");
        r.secret.assign(p, p + slen); p += slen; n -= slen;

        out.push_back(std::move(r));
    }
    if (n != 0) throw std::runtime_error("KeyStore body: trailing bytes");
    return out;
}

std::vector<uint8_t> readEntireFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("KeyStore: cannot open " + path);
    std::ostringstream buf;
    buf << f.rdbuf();
    const std::string s = buf.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

void atomicWriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("KeyStore: cannot open temp " + tmp);
        f.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
        f.flush();
        if (!f) throw std::runtime_error("KeyStore: write failed on " + tmp);
    }
    // Restrict permissions on the tmp file BEFORE it becomes visible under
    // its final name, so the final file is never briefly world-readable.
    (void)chmod(tmp.c_str(), S_IRUSR | S_IWUSR);
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::string err = "KeyStore: rename " + tmp + " → " + path + " failed";
        std::remove(tmp.c_str());
        throw std::runtime_error(err);
    }
    // Belt-and-suspenders: reassert perms on final path in case rename
    // preserved a stricter permission (some filesystems merge modes).
    (void)chmod(path.c_str(), S_IRUSR | S_IWUSR);
}

// Encrypt an entire body as a single secretstream frame.
// Layout returned:  header(24) || ciphertext(body_len + 17)
// NOTE: caller must zeroise `body` after this returns — encryptBody
// itself does not (the vector is const&, so we cannot mutate it here).
std::vector<uint8_t> encryptBody(
        const std::array<uint8_t, crypto_secretstream_xchacha20poly1305_KEYBYTES>& key,
        const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out(
        crypto_secretstream_xchacha20poly1305_HEADERBYTES
        + body.size() + crypto_secretstream_xchacha20poly1305_ABYTES);

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &state, out.data(), key.data()) != 0) {
        throw std::runtime_error("KeyStore: secretstream init_push failed");
    }
    unsigned long long clen = 0;
    if (crypto_secretstream_xchacha20poly1305_push(
            &state,
            out.data() + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
            &clen,
            body.data(), body.size(),
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
        throw std::runtime_error("KeyStore: secretstream push failed");
    }
    out.resize(crypto_secretstream_xchacha20poly1305_HEADERBYTES
                + static_cast<size_t>(clen));
    sodium_memzero(&state, sizeof(state));
    return out;
}

// Decrypt a header||ciphertext frame → plaintext body.
std::vector<uint8_t> decryptBody(
        const std::array<uint8_t, crypto_secretstream_xchacha20poly1305_KEYBYTES>& key,
        const uint8_t* buf, size_t n) {
    if (n < crypto_secretstream_xchacha20poly1305_HEADERBYTES
             + crypto_secretstream_xchacha20poly1305_ABYTES) {
        throw std::runtime_error("KeyStore: encrypted body too short");
    }
    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &state, buf, key.data()) != 0) {
        throw std::runtime_error("KeyStore: secretstream init_pull failed "
                                    "(wrong passphrase or file corrupted)");
    }
    const uint8_t* c = buf + crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    size_t clen = n - crypto_secretstream_xchacha20poly1305_HEADERBYTES;

    std::vector<uint8_t> body(clen);
    unsigned long long mlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &state, body.data(), &mlen, &tag,
            c, clen, nullptr, 0) != 0) {
        sodium_memzero(&state, sizeof(state));
        throw std::runtime_error("KeyStore: decrypt failed (auth tag mismatch)");
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        sodium_memzero(&state, sizeof(state));
        throw std::runtime_error("KeyStore: missing FINAL tag");
    }
    body.resize(static_cast<size_t>(mlen));
    sodium_memzero(&state, sizeof(state));
    return body;
}

} // namespace

// ---------------------------------------------------------------------------
// FileKeyStore
// ---------------------------------------------------------------------------

FileKeyStore::FileKeyStore(std::string path, const std::string& passphrase)
    : path_(std::move(path)) {
    ensureSodiumInit();
    if (passphrase.empty())
        throw std::runtime_error("FileKeyStore: passphrase must be nonempty");

    struct stat st{};
    bool exists = (stat(path_.c_str(), &st) == 0);

    if (!exists) {
        // Bootstrap: sample salt (cached as member), derive master key,
        // write empty encrypted body.
        randombytes_buf(salt_.data(), salt_.size());
        if (crypto_pwhash(master_key_.data(), master_key_.size(),
                            passphrase.c_str(), passphrase.size(),
                            salt_.data(),
                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_DEFAULT) != 0) {
            throw std::runtime_error("FileKeyStore: Argon2id failed (out of memory?)");
        }
        std::vector<uint8_t> body = serialiseRecords({});
        std::vector<uint8_t> enc = encryptBody(master_key_, body);
        sodium_memzero(body.data(), body.size());

        std::vector<uint8_t> file;
        appendU64(file, kMagic);
        appendU32(file, kFileVersion);
        appendBytes(file, salt_.data(), salt_.size());
        appendBytes(file, enc.data(), enc.size());
        atomicWriteFile(path_, file);
        return;
    }

    // Existing file: read header, derive master key, decrypt body once.
    std::vector<uint8_t> file = readEntireFile(path_);
    const size_t header = 8 + 4 + kSaltBytes;
    if (file.size() < header) throw std::runtime_error("FileKeyStore: file too short");
    if (readU64(file.data()) != kMagic)
        throw std::runtime_error("FileKeyStore: bad magic");
    uint32_t ver = readU32(file.data() + 8);
    if (ver != kFileVersion)
        throw std::runtime_error("FileKeyStore: unsupported version "
                                    + std::to_string(ver));

    std::memcpy(salt_.data(), file.data() + 12, kSaltBytes);

    if (crypto_pwhash(master_key_.data(), master_key_.size(),
                        passphrase.c_str(), passphrase.size(),
                        salt_.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("FileKeyStore: Argon2id failed");
    }

    std::vector<uint8_t> body = decryptBody(
        master_key_, file.data() + header, file.size() - header);
    records_ = deserialiseRecords(body.data(), body.size());
    sodium_memzero(body.data(), body.size());
}

FileKeyStore::~FileKeyStore() {
    zeroiseMemory();
    sodium_memzero(master_key_.data(), master_key_.size());
    sodium_memzero(salt_.data(), salt_.size());
}

void FileKeyStore::putKey(const KeyRecord& rec) {
    if (rec.key_id.empty())
        throw std::runtime_error("KeyStore: key_id must be nonempty");
    std::lock_guard<std::mutex> lk(mutex_);
    // Replace-or-append semantics.
    auto it = std::find_if(records_.begin(), records_.end(),
                            [&](const KeyRecord& r){ return r.key_id == rec.key_id; });
    if (it != records_.end()) {
        sodium_memzero(it->secret.data(), it->secret.size());
        *it = rec;
    } else {
        records_.push_back(rec);
    }
    flushToDiskLocked();
}

KeyRecord FileKeyStore::getKey(const std::string& key_id) const {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& r : records_) {
        if (r.key_id == key_id) return r;   // caller receives a copy
    }
    throw std::runtime_error("KeyStore: no such key " + key_id);
}

bool FileKeyStore::hasKey(const std::string& key_id) const {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& r : records_) if (r.key_id == key_id) return true;
    return false;
}

std::vector<std::string> FileKeyStore::listKeyIds() const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<std::string> out;
    out.reserve(records_.size());
    for (const auto& r : records_) out.push_back(r.key_id);
    return out;
}

void FileKeyStore::deleteKey(const std::string& key_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = std::find_if(records_.begin(), records_.end(),
                            [&](const KeyRecord& r){ return r.key_id == key_id; });
    if (it == records_.end())
        throw std::runtime_error("KeyStore: no such key " + key_id);
    sodium_memzero(it->secret.data(), it->secret.size());
    records_.erase(it);
    flushToDiskLocked();
}

void FileKeyStore::zeroiseMemory() {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& r : records_)
        if (!r.secret.empty())
            sodium_memzero(r.secret.data(), r.secret.size());
    records_.clear();
}

void FileKeyStore::flushToDiskLocked() const {
    // Caller MUST hold mutex_. Uses the cached salt_ (never re-reads disk).
    std::vector<uint8_t> body = serialiseRecords(records_);
    std::vector<uint8_t> enc = encryptBody(master_key_, body);
    sodium_memzero(body.data(), body.size());

    std::vector<uint8_t> file;
    file.reserve(8 + 4 + kSaltBytes + enc.size());
    appendU64(file, kMagic);
    appendU32(file, kFileVersion);
    appendBytes(file, salt_.data(), salt_.size());
    appendBytes(file, enc.data(), enc.size());
    atomicWriteFile(path_, file);
}

// ---------------------------------------------------------------------------
// HsmKeyStore — stub
// ---------------------------------------------------------------------------

HsmKeyStore::HsmKeyStore() {}
HsmKeyStore::~HsmKeyStore() {}

[[noreturn]] static void hsmNotImplemented(const char* op) {
    throw std::logic_error(
        std::string("HsmKeyStore::") + op + " not implemented — "
        "wire PKCS#11 provider here (see MpsvsKeyStore.h TODO block)");
}

void HsmKeyStore::putKey(const KeyRecord&) { hsmNotImplemented("putKey"); }
KeyRecord HsmKeyStore::getKey(const std::string&) const { hsmNotImplemented("getKey"); }
bool HsmKeyStore::hasKey(const std::string&) const { return false; }
std::vector<std::string> HsmKeyStore::listKeyIds() const { return {}; }
void HsmKeyStore::deleteKey(const std::string&) { hsmNotImplemented("deleteKey"); }
void HsmKeyStore::zeroiseMemory() { /* no in-memory secrets */ }

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<IKeyStore> openFileKeyStore(const std::string& path,
                                              const std::string& passphrase) {
    return std::unique_ptr<IKeyStore>(new FileKeyStore(path, passphrase));
}

} // namespace mpsvs
} // namespace volePSI
