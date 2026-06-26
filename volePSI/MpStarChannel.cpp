#include "MpStarChannel.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace volePSI {

namespace {

static inline uint32_t readU32BE(const uint8_t* buf) {
    return (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16)
         | (uint32_t(buf[2]) << 8)  |  uint32_t(buf[3]);
}

static inline void writeU32BE(uint8_t* buf, uint32_t val) {
    buf[0] = uint8_t(val >> 24);
    buf[1] = uint8_t(val >> 16);
    buf[2] = uint8_t(val >> 8);
    buf[3] = uint8_t(val);
}

constexpr std::size_t kMaxPayloadBytes = 64ULL * 1024 * 1024;

} // anonymous namespace

MpStarChannel::MpStarChannel(std::vector<coproto::Socket> peerSocks,
                             uint32_t selfIdx,
                             uint32_t senderCount)
    : mSelfIdx(selfIdx)
    , mSenderCount(senderCount)
    , mPeerSocks(std::move(peerSocks))
{
    if (selfIdx >= senderCount) {
        throw std::runtime_error("MpStarChannel: selfIdx out of range");
    }
    if (mPeerSocks.size() != senderCount) {
        throw std::runtime_error("MpStarChannel: peerSocks size != senderCount");
    }
}

macoro::task<> MpStarChannel::sendTo(uint32_t toIdx, std::vector<uint8_t> data) {
    if (toIdx == mSelfIdx)
        throw std::runtime_error("MpStarChannel::sendTo: cannot send to self");
    if (toIdx >= mSenderCount)
        throw std::runtime_error("MpStarChannel::sendTo: invalid toIdx");

    std::array<uint8_t, 4> hdr;
    writeU32BE(hdr.data(), static_cast<uint32_t>(data.size()));
    co_await mPeerSocks[toIdx].send(coproto::span<const uint8_t>(hdr.data(), hdr.size()));
    co_await mPeerSocks[toIdx].send(std::move(data));
    // coproto requires flush before destructor or terminate() fires.
    // Flush per send for the prototype; can batch later.
    co_await mPeerSocks[toIdx].flush();
}

macoro::task<std::vector<uint8_t>> MpStarChannel::recvFrom(uint32_t fromIdx) {
    if (fromIdx == mSelfIdx)
        throw std::runtime_error("MpStarChannel::recvFrom: cannot recv from self");
    if (fromIdx >= mSenderCount)
        throw std::runtime_error("MpStarChannel::recvFrom: invalid fromIdx");

    std::array<uint8_t, 4> hdr;
    co_await mPeerSocks[fromIdx].recv(coproto::span<uint8_t>(hdr.data(), hdr.size()));
    uint32_t len = readU32BE(hdr.data());
    if (len > kMaxPayloadBytes)
        throw std::runtime_error("MpStarChannel::recvFrom: payload exceeds limit");

    std::vector<uint8_t> data(len);
    co_await mPeerSocks[fromIdx].recv(coproto::span<uint8_t>(data.data(), data.size()));
    co_return data;
}

} // namespace volePSI
