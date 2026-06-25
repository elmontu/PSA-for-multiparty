#include "MpStarChannel.h"
#include "macoro/sync_wait.h"
#include <cstring>
#include <cassert>
#include <condition_variable>
#include <tuple>
#include <deque>
#include <mutex>
#include <thread>
#include <iostream>

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

// Max single-frame payload accepted off the wire. Hard upper bound to
// prevent untrusted-len DoS (audit-driven).
static constexpr std::size_t kMaxFramePayloadBytes = 64ULL * 1024 * 1024;

// Returns (fromIdx, toIdx, payload).
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
    , mSelfIdx(0)
    , mSenderCount(static_cast<uint32_t>(senderSocks.size()))
    , mSenderSocks(std::move(senderSocks))
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

// ---------- SP relay (per-destination drain pattern) ----------

namespace {

struct FrameForDest {
    std::vector<uint8_t> payload;
    uint32_t fromIdx;
};

// Thread-blocking queue with condition_variable. The lock is NEVER held
// across co_await. pop() blocks the calling thread (via wait) until push()
// signals. Each consumer runs in its own std::thread (see relayLoop) so
// blocking is correct.
template<typename T>
class AsyncQueue {
    std::deque<T> mItems;
    std::mutex mMu;
    std::condition_variable mCv;

public:
    AsyncQueue() = default;
    AsyncQueue(const AsyncQueue&) = delete;
    AsyncQueue& operator=(const AsyncQueue&) = delete;

    void push(T v) {
        {
            std::lock_guard<std::mutex> lk(mMu);
            mItems.push_back(std::move(v));
        }
        mCv.notify_one();
    }

    // Synchronous blocking pop. Returned as a macoro::task<T> so the call
    // site reads naturally (`co_await q.pop()`) but no real coroutine
    // suspension happens — the calling thread blocks on the cv.
    macoro::task<T> pop() {
        std::unique_lock<std::mutex> lk(mMu);
        mCv.wait(lk, [this] { return !mItems.empty(); });
        T val = std::move(mItems.front());
        mItems.pop_front();
        co_return val;
    }
};

} // anonymous namespace

macoro::task<> MpStarChannel::relayLoop() {
    if (!mIsSp) {
        throw std::runtime_error("relayLoop called on sender instance");
    }

    // One queue per destination. Construct at size; AsyncQueue holds
    // std::mutex (non-movable) so we cannot resize.
    std::vector<AsyncQueue<FrameForDest>> queues(mSenderCount);

    // We spawn one std::thread per producer and per consumer. macoro
    // doesn't expose a vector-of-task primitive in the version this build
    // pulls (only variadic when_all_ready), and using a vector with
    // serial co_await would starve everything but the first task. Each
    // thread drives its own coroutine via sync_wait.
    //
    // TODO: replace with a proper macoro task scheduler if one becomes
    // available.
    std::vector<std::thread> threads;
    threads.reserve(2 * mSenderCount);

    // Producers: one per sender socket.
    for (uint32_t i = 0; i < mSenderCount; ++i) {
        threads.emplace_back([this, i, &queues]() {
            try {
                auto body = [this, i, &queues]() -> macoro::task<> {
                    while (true) {
                        auto [fromIdx, toIdx, payload] = co_await recvFrame(mSenderSocks[i]);

                        if (fromIdx != i) {
                            throw std::runtime_error("MpStarChannel::relayLoop: fromIdx spoofed");
                        }
                        if (toIdx >= mSenderCount) {
                            throw std::runtime_error("MpStarChannel::relayLoop: invalid toIdx");
                        }

                        queues[toIdx].push(FrameForDest{std::move(payload), i});
                    }
                };
                macoro::sync_wait(body());
            } catch (const std::exception& e) {
                std::cerr << "MpStarChannel SP relay: producer " << i
                          << " error: " << e.what() << std::endl;
            }
        });
    }

    // Consumers: one per destination socket. Only this thread writes to
    // mSenderSocks[j].
    for (uint32_t j = 0; j < mSenderCount; ++j) {
        threads.emplace_back([this, j, &queues]() {
            try {
                auto body = [this, j, &queues]() -> macoro::task<> {
                    while (true) {
                        auto item = co_await queues[j].pop();

                        std::array<uint8_t, 12> header;
                        writeU32BE(header.data(), item.fromIdx);
                        writeU32BE(header.data() + 4, j);
                        writeU32BE(header.data() + 8,
                                   static_cast<uint32_t>(item.payload.size()));

                        co_await sendExact(mSenderSocks[j], header.data(), header.size());
                        co_await sendExact(mSenderSocks[j],
                                           item.payload.data(),
                                           item.payload.size());
                    }
                };
                macoro::sync_wait(body());
            } catch (const std::exception& e) {
                std::cerr << "MpStarChannel SP relay: consumer " << j
                          << " error: " << e.what() << std::endl;
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    co_return;
}

} // namespace volePSI
