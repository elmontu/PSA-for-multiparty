#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <queue>
#include <stdexcept>
#include <vector>
#include <memory>
#include <utility>
#include <array>
#include <mutex>

#include "coproto/coproto.h"
#include "macoro/task.h"

namespace volePSI {

class MpStarChannel {
public:
    // Sender constructor
    MpStarChannel(coproto::Socket spSock, uint32_t selfIdx, uint32_t senderCount);

    // Send to another sender (via SP)
    macoro::task<> sendTo(uint32_t toIdx, std::vector<uint8_t> data);

    // Receive from another sender
    macoro::task<std::vector<uint8_t>> recvFrom(uint32_t fromIdx);

    // Factory for the star point
    static MpStarChannel makeSp(std::vector<coproto::Socket> senderSocks);

    // SP main loop. Runs until requestStop() is called (or every sender
    // socket has errored). Safe to call concurrently with sendTo/recvFrom
    // on sender instances elsewhere.
    macoro::task<> relayLoop();

    // Request a clean shutdown of relayLoop. Producer and consumer tasks
    // each wake from their next blocking call (or socket-close), check the
    // flag, and exit. Idempotent.
    void requestStop();

private:
    explicit MpStarChannel(std::vector<coproto::Socket> senderSocks);

    bool mIsSp = false;
    uint32_t mSelfIdx = 0;
    uint32_t mSenderCount = 0;
    coproto::Socket mSpSock;                     // used by sender
    std::vector<coproto::Socket> mSenderSocks;   // used by SP
    std::atomic<bool> mStop{false};              // SP only; signal relayLoop

    // sender-side receive buffer + per-source limits
    static constexpr uint32_t kMaxBufferedFrames = 1024;
    static constexpr std::size_t kMaxBufferedBytes = 64ULL * 1024 * 1024; // 64 MiB

    std::map<uint32_t, std::queue<std::vector<uint8_t>>> mRecvBuf;
    std::map<uint32_t, uint32_t> mRecvFrameCount;
    std::map<uint32_t, std::size_t> mRecvTotalBytes;
};

} // namespace volePSI
