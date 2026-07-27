#pragma once

// MPSVS Audit Persistence — append-only tamper-evident log on disk.
//
// Extends SessionAuditLog (in-memory hash chain) to a persistent file:
//   - Binary format: [magic:4] [version:2] [entry_count:8]
//                    { [len:4] [reason:1] [ts:8] [prev_link:32] [this_link:32]
//                      [ctx_bytes:variable] } ...
//   - Hash chain enforced across restarts: on open, verify chain from
//     file's stored head_link back to genesis
//   - fsync() after every append (durability)
//   - File locking prevents concurrent writers
//
// Threat model:
//   - Adversary can read the file (public audit trail)
//   - Adversary can modify or truncate the file offline
//   - Detection: any modification breaks the hash chain → verify() fails
//   - Doesn't protect against complete deletion (need external backup)

#include "MpsvsProdHygiene.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

class PersistentAuditLog {
public:
    // Open (or create) an audit log at `path`. On open of an existing file,
    // verifies the on-disk hash chain. Throws on corruption.
    explicit PersistentAuditLog(const std::string& path);
    ~PersistentAuditLog();

    // Non-copyable.
    PersistentAuditLog(const PersistentAuditLog&) = delete;
    PersistentAuditLog& operator=(const PersistentAuditLog&) = delete;

    // Append one abort event. Returns the entry with computed link.
    // Thread-safe. fsync()s after write.
    AbortReport append(AbortReason reason, AbortContext ctx);

    // Read entire chain from disk (for external verification / replay).
    std::vector<AbortReport> readAll() const;

    // Verify the on-disk chain end-to-end. Returns true iff every link
    // matches. Called automatically on open; can be re-called any time.
    bool verifyChain() const;

    // Current head link (deterministic function of the chain).
    std::array<uint8_t, 32> currentLink() const;

    size_t entryCount() const;
    const std::string& path() const { return path_; }

private:
    // Serialise / deserialise one entry into a binary buffer.
    static std::vector<uint8_t> serializeEntry(const AbortReport& r);
    static AbortReport deserializeEntry(const uint8_t* data, size_t len);

    // Load and verify chain from disk into memory.
    void loadFromDisk();

    // Append serialised entry to file with fsync.
    void writeEntry(const std::vector<uint8_t>& bytes);

    std::string path_;
    mutable std::mutex mu_;
    std::vector<AbortReport> chain_;   // in-memory mirror
    std::array<uint8_t, 32> last_link_;
    int fd_;   // file descriptor for append + fsync
};

// Standalone verify helper for a file written by PersistentAuditLog.
// Useful for offline audit tools that only need to read + verify.
bool verifyPersistedAudit(const std::string& path);

} // namespace mpsvs
} // namespace volePSI
