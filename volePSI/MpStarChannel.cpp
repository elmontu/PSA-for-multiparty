#include "MpStarChannel.h"
#include <cstring>
#include <cassert>
#include <tuple>

// TODO(multipsa): std::mutex held across co_await in relayLoop() is unsafe
// under a single-threaded coproto executor (blocking lock deadlocks the
// executor) and unsound under a multi-threaded one (mutex unlock may happen
// on a different thread than lock). Replace with a coroutine-aware mutex
// or with a single-task-per-destination pattern (per-dest send queue +
// dedicated drain task) before production use.

namespace volePSI {

// ---------- helpers ----------

static inline uint32_t readU32BE(const uint8_t* buf) noexcept {
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8)  |
           (static_cast<uint32_t>(buf[3]));
}

static inline void writeU32BE(uint8_t* buf, uint32_t val) noexcept {
    buf[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 8)  & 0xFF);
    buf[3] = static_cast<uint8_t>(val & 0xFF);
}

static macoro::task<std::vector<uint8_t>> recvExact(coproto::Socket& sock, std::size_t size) {
    std::vector<uint8_t> buf(size);
    std::size_t received = 0;
    while (received < size) {
        auto span = coproto::span<uint8_t>(buf.data() + received, size - received);
        auto n = co_await sock.recv(span);
        if (n == 0) {
            throw std::runtime_error("MpStarChannel: connection closed while reading");
        }
        received += n;
    }
    co_return buf;
}

static macoro::task<> sendExact(coproto::Socket& sock, const uint8_t* data, std::size_t size) {
    std::size_t sent = 0;
    while (sent < size) {
        auto span = coproto::span<const uint8_t>(data + sent, size - sent);
        auto n = co_await sock.send(span);
        if (n == 0) {
            throw std::runtime_error("MpStarChannel: send returned 0");
        }
        sent += n;
    }
}

// Returns (fromIdx, toIdx, payload)
// Max single-frame payload accepted off the wire. Hard upper bound to
// prevent untrusted-len DoS (audit-driven).
static constexpr std::size_t kMaxFramePayloadBytes = 64ULL * 1024 * 1024;

static macoro::task<std::tuple<uint32_t, uint32_t, std::vector<uint8_t>>>
recvFrame(coproto::Socket& sock) {
    auto headerBuf = co_await recvExact(sock, 12);
    uint32_t fromIdx = readU32BE(headerBuf.data());
    uint32_t toIdx   = readU32BE(headerBuf.data() + 4);
    uint32_t len     = readU32BE(headerBuf.data() + 8);

    if (len > kMaxFramePayloadBytes) {
        throw std::runtime_error("MpStarChannel: frame payload exceeds max size");
    }

    auto payload = co_await recvExact(sock, len);
    co_return std::make_tuple(fromIdx, toIdx, std::move(payload));
}

// ---------- constructors ----------

MpStarChannel::MpStarChannel(coproto::Socket spSock, uint32_t selfIdx, uint32_t senderCount)
    : mIsSp(false)
    , mSelfIdx(selfIdx)
    , mSenderCount(senderCount)
    , mSpSock(std::move(spSock))
{
    if (selfIdx >= senderCount) {
        throw std::runtime_error("MpStarChannel: selfIdx out of range");
    }
}

MpStarChannel::MpStarChannel(std::vector<coproto::Socket> senderSocks)
    : mIsSp(true)
    , mSelfIdx(0)            // unused on SP side
    , mSenderCount(static_cast<uint32_t>(senderSocks.size()))
    , mSenderSocks(std::move(senderSocks))
    , mSenderSendMutex(mSenderCount)   // one mutex per possible destination
{
    if (mSenderCount == 0) {
        throw std::runtime_error("MpStarChannel: senderCount must be > 0 for SP");
    }
}

MpStarChannel MpStarChannel::makeSp(std::vector<coproto::Socket> senderSocks) {
    return MpStarChannel(std::move(senderSocks));
}

// ---------- sender methods ----------

macoro::task<> MpStarChannel::sendTo(uint32_t toIdx, std::vector<uint8_t> data) {
    if (mIsSp) {
        throw std::runtime_error("sendTo called on SP instance");
    }
    if (toIdx >= mSenderCount) {
        throw std::runtime_error("MpStarChannel::sendTo: invalid toIdx");
    }

    std::array<uint8_t, 12> header;
    writeU32BE(header.data(), mSelfIdx);
    writeU32BE(header.data() + 4, toIdx);
    writeU32BE(header.data() + 8, static_cast<uint32_t>(data.size()));

    co_await sendExact(mSpSock, header.data(), header.size());
    co_await sendExact(mSpSock, data.data(), data.size());
}

macoro::task<std::vector<uint8_t>> MpStarChannel::recvFrom(uint32_t fromIdx) {
    if (mIsSp) {
        throw std::runtime_error("recvFrom called on SP instance");
    }
    if (fromIdx >= mSenderCount) {
        throw std::runtime_error("MpStarChannel::recvFrom: invalid fromIdx");
    }

    // check local buffer first
    auto it = mRecvBuf.find(fromIdx);
    if (it != mRecvBuf.end() && !it->second.empty()) {
        auto payload = std::move(it->second.front());
        it->second.pop();
        auto& cnt = mRecvFrameCount[fromIdx];
        auto& bytes = mRecvTotalBytes[fromIdx];
        assert(cnt > 0);
        --cnt;
        bytes -= payload.size();
        co_return payload;
    }

    while (true) {
        auto [incomingFrom, toIdx, payload] = co_await recvFrame(mSpSock);

        if (toIdx != mSelfIdx) {
            throw std::runtime_error("MpStarChannel::recvFrom: frame destined for another sender");
        }

        if (incomingFrom == fromIdx) {
            co_return payload;
        }

        auto& q = mRecvBuf[incomingFrom];
        auto& cnt = mRecvFrameCount[incomingFrom];
        auto& total = mRecvTotalBytes[incomingFrom];

        if (cnt >= kMaxBufferedFrames || total + payload.size() > kMaxBufferedBytes) {
            throw std::runtime_error("MpStarChannel::recvFrom: per-source buffer limit exceeded");
        }

        cnt++;
        total += payload.size();
        q.push(std::move(payload));
    }
}

// ---------- SP relay loop ----------

macoro::task<> MpStarChannel::relayLoop() {
    if (!mIsSp) {
        throw std::runtime_error("relayLoop called on sender instance");
    }

    std::vector<macoro::task<>> tasks;
    for (uint32_t i = 0; i < mSenderCount; ++i) {
        tasks.push_back(
            [this, i]() -> macoro::task<> {
                while (true) {
                    auto [fromIdx, toIdx, payload] = co_await recvFrame(mSenderSocks[i]);

                    if (fromIdx != i) {
                        throw std::runtime_error("MpStarChannel::relayLoop: fromIdx spoofed");
                    }
                    if (toIdx >= mSenderCount) {
                        throw std::runtime_error("MpStarChannel::relayLoop: invalid toIdx");
                    }

                    std::array<uint8_t, 12> outHeader;
                    writeU32BE(outHeader.data(), i);
                    writeU32BE(outHeader.data() + 4, toIdx);
                    writeU32BE(outHeader.data() + 8, static_cast<uint32_t>(payload.size()));

                    // See TODO at top of file: this lock is unsafe across co_await.
                    {
                        std::lock_guard<std::mutex> lock(mSenderSendMutex[toIdx]);
                        co_await sendExact(mSenderSocks[toIdx], outHeader.data(), outHeader.size());
                        co_await sendExact(mSenderSocks[toIdx], payload.data(), payload.size());
                    }
                }
            }()
        );
    }

    co_await macoro::when_all(std::move(tasks));
}

} // namespace volePSI
