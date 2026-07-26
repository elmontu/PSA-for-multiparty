#include "MpOiraBudget.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace volePSI {
namespace mpstar {

namespace {

// File per scope; keeps things independent and lock-scoped.
std::string filePathFor(const OIRABudgetConfig& cfg) {
    return cfg.budgetFile + "." + cfg.scopeId;
}

// Best-effort file-existence check.
bool fileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

// Read current (spent, count) from file. Returns (0, 0) if file is missing.
bool readState(int fd, double& outSpent, uint32_t& outCount) {
    outSpent = 0.0;
    outCount = 0;
    // Rewind and read whole file.
    if (::lseek(fd, 0, SEEK_SET) < 0) return false;
    char buf[128];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    if (n < 0) return false;
    if (n == 0) return true;   // empty file = fresh scope
    buf[n] = 0;
    std::istringstream is(buf);
    if (!(is >> outSpent >> outCount)) {
        // Malformed: treat as fresh, don't fail.
        outSpent = 0.0;
        outCount = 0;
    }
    return true;
}

// Overwrite file with (spent, count). Truncates.
bool writeState(int fd, double spent, uint32_t count) {
    if (::lseek(fd, 0, SEEK_SET) < 0) return false;
    if (::ftruncate(fd, 0) < 0) return false;
    char buf[128];
    int n = std::snprintf(buf, sizeof(buf), "%.10f %u\n", spent, count);
    if (n <= 0) return false;
    ssize_t w = ::write(fd, buf, static_cast<size_t>(n));
    return (w == n);
}

} // namespace

OIRABudgetCheckResult oiraBudgetCheckAndReserve(
    const OIRABudgetConfig& cfg,
    double epsilonForThisQuery)
{
    OIRABudgetCheckResult r;
    if (cfg.scopeId.empty()) {
        r.reason = "budget check skipped: no scopeId";
        r.allowed = true;   // no scope = no budget = allow (opt-out)
        return r;
    }
    if (cfg.budgetFile.empty()) {
        r.reason = "budget check misconfigured: no budgetFile";
        return r;
    }
    if (epsilonForThisQuery < 0.0) {
        r.reason = "budget check invalid: negative epsilon";
        return r;
    }

    std::string path = filePathFor(cfg);

    // Open with O_CREAT so first call bootstraps the file; O_RDWR so we can
    // read the current state and then overwrite it under an exclusive lock.
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        r.reason = std::string("open failed: ") + std::strerror(errno);
        return r;
    }
    if (::flock(fd, LOCK_EX) < 0) {
        int e = errno;
        ::close(fd);
        r.reason = std::string("flock failed: ") + std::strerror(e);
        return r;
    }

    double spent = 0.0;
    uint32_t count = 0;
    if (!readState(fd, spent, count)) {
        ::flock(fd, LOCK_UN);
        ::close(fd);
        r.reason = "read state failed";
        return r;
    }

    r.spentBefore = spent;
    r.countBefore = count;

    double newSpent = spent + epsilonForThisQuery;
    uint32_t newCount = count + 1;

    if (newSpent > cfg.epsilonCap) {
        r.allowed = false;
        r.reason = "budget_exhausted: cumulative epsilon "
                 + std::to_string(newSpent)
                 + " would exceed cap "
                 + std::to_string(cfg.epsilonCap);
        // No state change; release lock and return.
        ::flock(fd, LOCK_UN);
        ::close(fd);
        return r;
    }
    if (newCount > cfg.queryCap) {
        r.allowed = false;
        r.reason = "budget_exhausted: query count "
                 + std::to_string(newCount)
                 + " would exceed cap "
                 + std::to_string(cfg.queryCap);
        ::flock(fd, LOCK_UN);
        ::close(fd);
        return r;
    }

    // Reserve.
    if (!writeState(fd, newSpent, newCount)) {
        ::flock(fd, LOCK_UN);
        ::close(fd);
        r.reason = "write state failed";
        return r;
    }
    r.allowed = true;
    r.spentAfter = newSpent;
    r.countAfter = newCount;
    // fsync to ensure durability across crashes.
    ::fsync(fd);
    ::flock(fd, LOCK_UN);
    ::close(fd);
    return r;
}

OIRABudgetCheckResult oiraBudgetPeek(const OIRABudgetConfig& cfg) {
    OIRABudgetCheckResult r;
    if (cfg.scopeId.empty() || cfg.budgetFile.empty()) {
        r.reason = "peek misconfigured";
        return r;
    }
    std::string path = filePathFor(cfg);
    if (!fileExists(path)) {
        r.allowed = true;   // fresh scope; nothing spent
        return r;
    }
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        r.reason = std::string("peek open failed: ") + std::strerror(errno);
        return r;
    }
    if (::flock(fd, LOCK_SH) < 0) { ::close(fd); r.reason = "flock SH failed"; return r; }
    double spent = 0.0; uint32_t count = 0;
    readState(fd, spent, count);
    ::flock(fd, LOCK_UN);
    ::close(fd);
    r.spentBefore = spent;
    r.countBefore = count;
    r.spentAfter  = spent;
    r.countAfter  = count;
    r.allowed = (spent < cfg.epsilonCap) && (count < cfg.queryCap);
    return r;
}

void oiraBudgetReset(const OIRABudgetConfig& cfg) {
    if (cfg.scopeId.empty() || cfg.budgetFile.empty()) return;
    ::unlink(filePathFor(cfg).c_str());
}

} // namespace mpstar
} // namespace volePSI
