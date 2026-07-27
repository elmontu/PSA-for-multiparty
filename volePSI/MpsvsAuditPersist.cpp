#include "MpsvsAuditPersist.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// File format:
//   [magic:4 bytes = "MPAA"] [version:2 bytes] [reserved:2 bytes]
//   { entry_frame }*
//
// entry_frame:
//   [len:4] [reason:1] [party_id:4] [ts_ns:8] [prev_link:32] [this_link:32]
//   [phase_len:2] [phase_bytes]
//   [cell_len:2] [cell_bytes]
//   [notes_len:2] [notes_bytes]

static constexpr uint32_t kMagic = 0x41415041;   // "APAA" (little-endian "AAPA")
static constexpr uint16_t kVersion = 1;
static constexpr size_t kHeaderSize = 8;   // magic + version + reserved

static void putU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(v & 0xff); b.push_back((v >> 8) & 0xff);
}
static void putU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((v >> (i * 8)) & 0xff);
}
static void putU64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back((v >> (i * 8)) & 0xff);
}
static uint16_t getU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
static uint32_t getU32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (i * 8);
    return v;
}
static uint64_t getU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

std::vector<uint8_t>
PersistentAuditLog::serializeEntry(const AbortReport& r) {
    std::vector<uint8_t> body;
    body.push_back(static_cast<uint8_t>(r.reason));
    putU32(body, r.ctx.party_id);
    putU64(body, r.timestamp_ns);
    body.insert(body.end(), r.prev_link.begin(), r.prev_link.end());
    body.insert(body.end(), r.this_link.begin(), r.this_link.end());
    auto put_str = [&](const std::string& s) {
        uint16_t len = static_cast<uint16_t>(std::min<size_t>(s.size(), 65535));
        putU16(body, len);
        body.insert(body.end(), s.begin(), s.begin() + len);
    };
    put_str(r.ctx.protocol_phase);
    put_str(r.ctx.cell_key);
    put_str(r.ctx.extra_notes);

    std::vector<uint8_t> frame;
    putU32(frame, static_cast<uint32_t>(body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

AbortReport
PersistentAuditLog::deserializeEntry(const uint8_t* data, size_t len) {
    if (len < 1 + 4 + 8 + 32 + 32 + 6)
        throw std::runtime_error("audit entry truncated");
    AbortReport r;
    size_t o = 0;
    r.reason = static_cast<AbortReason>(data[o++]);
    r.ctx.party_id = getU32(data + o); o += 4;
    r.timestamp_ns = getU64(data + o); o += 8;
    std::memcpy(r.prev_link.data(), data + o, 32); o += 32;
    std::memcpy(r.this_link.data(), data + o, 32); o += 32;
    auto read_str = [&]() {
        if (o + 2 > len) throw std::runtime_error("audit entry truncated (str)");
        uint16_t slen = getU16(data + o); o += 2;
        if (o + slen > len) throw std::runtime_error("audit entry truncated (payload)");
        std::string s(reinterpret_cast<const char*>(data + o), slen);
        o += slen;
        return s;
    };
    r.ctx.protocol_phase = read_str();
    r.ctx.cell_key = read_str();
    r.ctx.extra_notes = read_str();
    return r;
}

PersistentAuditLog::PersistentAuditLog(const std::string& path) : path_(path) {
    last_link_.fill(0);
    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd_ < 0) throw std::runtime_error("open audit file: " + path);
    // Advisory lock — one writer per file.
    if (flock(fd_, LOCK_EX | LOCK_NB) < 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("audit file locked by another process: " + path);
    }
    // Every error path below MUST close fd_ before re-throwing (RAII helper).
    // Using try/catch instead of a dedicated scope guard to keep header simple.
    try {
        struct stat st{};
        if (fstat(fd_, &st) < 0)
            throw std::runtime_error("audit fstat: " + path);
        if (st.st_size == 0) {
            std::vector<uint8_t> hdr(kHeaderSize, 0);
            std::memcpy(hdr.data(), &kMagic, 4);
            hdr[4] = kVersion & 0xff;
            hdr[5] = (kVersion >> 8) & 0xff;
            ssize_t w = ::write(fd_, hdr.data(), hdr.size());
            if (w != static_cast<ssize_t>(hdr.size()))
                throw std::runtime_error("audit header write: " + path);
            if (fsync(fd_) < 0)
                throw std::runtime_error("audit fsync: " + path);
        }
        // Load and verify existing chain — uses the locked fd_ via pread.
        loadFromDisk();
        if (!verifyChain()) {
            throw std::runtime_error(
                "audit chain verification FAILED on load — file tampered: " + path);
        }
    } catch (...) {
        flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
        throw;   // re-raise; caller sees the exception
    }
}

PersistentAuditLog::~PersistentAuditLog() {
    if (fd_ >= 0) {
        fsync(fd_);
        flock(fd_, LOCK_UN);
        ::close(fd_);
    }
}

void PersistentAuditLog::loadFromDisk() {
    // Read from the SAME fd_ we hold the flock on. Uses pread() to avoid
    // interfering with the O_APPEND write offset. Prior implementation used
    // a separate std::ifstream which bypassed the flock — a concurrency bug.
    struct stat st{};
    if (fstat(fd_, &st) < 0) throw std::runtime_error("audit fstat (load)");
    if (static_cast<size_t>(st.st_size) < kHeaderSize) return;
    std::vector<uint8_t> all(st.st_size);
    ssize_t total = 0;
    while (total < st.st_size) {
        ssize_t n = ::pread(fd_, all.data() + total, st.st_size - total, total);
        if (n < 0) throw std::runtime_error("audit pread");
        if (n == 0) break;   // EOF (shouldn't happen mid-read)
        total += n;
    }
    if (getU32(all.data()) != kMagic)
        throw std::runtime_error("audit magic mismatch");
    if (getU16(all.data() + 4) != kVersion)
        throw std::runtime_error("audit version mismatch");
    size_t o = kHeaderSize;
    chain_.clear();
    last_link_.fill(0);
    while (o + 4 <= all.size()) {
        uint32_t entry_len = getU32(all.data() + o);
        o += 4;
        if (o + entry_len > all.size())
            throw std::runtime_error("audit truncated entry");
        AbortReport r = deserializeEntry(all.data() + o, entry_len);
        chain_.push_back(r);
        last_link_ = r.this_link;
        o += entry_len;
    }
}

void PersistentAuditLog::writeEntry(const std::vector<uint8_t>& bytes) {
    ssize_t w = ::write(fd_, bytes.data(), bytes.size());
    if (w != static_cast<ssize_t>(bytes.size()))
        throw std::runtime_error("audit write short");
    if (fsync(fd_) < 0) throw std::runtime_error("audit fsync");
}

AbortReport PersistentAuditLog::append(AbortReason reason, AbortContext ctx) {
    std::lock_guard<std::mutex> lg(mu_);
    AbortReport r = makeAbortReport(reason, std::move(ctx), last_link_);
    auto bytes = serializeEntry(r);
    writeEntry(bytes);
    last_link_ = r.this_link;
    chain_.push_back(r);
    return r;
}

std::vector<AbortReport> PersistentAuditLog::readAll() const {
    std::lock_guard<std::mutex> lg(mu_);
    return chain_;
}

bool PersistentAuditLog::verifyChain() const {
    std::lock_guard<std::mutex> lg(mu_);
    return verifyAbortChain(chain_);
}

std::array<uint8_t, 32> PersistentAuditLog::currentLink() const {
    std::lock_guard<std::mutex> lg(mu_);
    return last_link_;
}

size_t PersistentAuditLog::entryCount() const {
    std::lock_guard<std::mutex> lg(mu_);
    return chain_.size();
}

bool verifyPersistedAudit(const std::string& path) {
    try {
        PersistentAuditLog log(path);
        return log.verifyChain();
    } catch (const std::exception&) {
        // Narrower than catch(...); still returns false for any expected
        // failure (magic mismatch, chain break, IO error). Catches all
        // std::exception-derived errors; propagates non-std (e.g., abi).
        return false;
    }
}

} // namespace mpsvs
} // namespace volePSI
