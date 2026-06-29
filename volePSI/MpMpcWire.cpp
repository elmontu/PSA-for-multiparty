#include "MpMpcWire.h"

#include <stdexcept>
#include <string>

namespace volePSI {
namespace mpstar {

namespace {

void requireParty01(uint64_t partyIdx, const char* who) {
    if (partyIdx > 1)
        throw std::runtime_error(
            std::string(who) + ": partyIdx must be 0 or 1");
}

} // namespace

macoro::task<uint8_t> wireOpenBit(
    uint8_t myShare,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    requireParty01(partyIdx, "wireOpenBit");
    // Use std::array for the send/recv buffer — matches the existing
    // coproto pattern used by MpsaDriver / MpSpHandshake / MpOleTriple.
    // Bare POD send/recv via template-deduced Container has edge cases
    // (rvalue lifetime + buffering) that can deadlock LocalAsyncSocket.
    std::array<uint8_t, 1> mine = {myShare};
    std::array<uint8_t, 1> theirs = {0};
    co_await sock.send(mine);
    co_await sock.flush();   // small payload — coproto buffers; flush to actually transmit
    co_await sock.recv(theirs);
    co_return static_cast<uint8_t>((myShare ^ theirs[0]) & 1);
}

macoro::task<uint8_t> wireSecureAnd(
    uint8_t myX,
    uint8_t myY,
    uint8_t myTripleU,
    uint8_t myTripleV,
    uint8_t myTripleW,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    requireParty01(partyIdx, "wireSecureAnd");
    // Beaver multiplication over Z_2:
    //   d = x XOR u, e = y XOR v, both opened.
    //   z = w XOR (d AND v) XOR (e AND u) XOR (d AND e)
    // Each party computes its share of d and e locally; opens batched
    // by packing both into one 2-byte send + 2-byte recv round-trip.
    uint8_t myD = static_cast<uint8_t>((myX ^ myTripleU) & 1);
    uint8_t myE = static_cast<uint8_t>((myY ^ myTripleV) & 1);
    std::array<uint8_t, 2> myPair = {myD, myE};
    std::array<uint8_t, 2> theirPair = {0, 0};
    co_await sock.send(myPair);
    co_await sock.flush();   // small payload; flush to actually transmit
    co_await sock.recv(theirPair);
    uint8_t d = static_cast<uint8_t>((myD ^ theirPair[0]) & 1);
    uint8_t e = static_cast<uint8_t>((myE ^ theirPair[1]) & 1);

    uint8_t z = static_cast<uint8_t>(
        (myTripleW ^ (d & myTripleV) ^ (e & myTripleU)) & 1);
    if (partyIdx == 0) {
        z ^= static_cast<uint8_t>(d & e);  // d·e is a public constant; party 0 absorbs
    }
    co_return static_cast<uint8_t>(z & 1);
}

macoro::task<uint8_t> wireSecureAndT(
    uint8_t myX,
    uint8_t myY,
    const BeaverTripleBit& triple,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    if (triple.u.N() < 2 || triple.v.N() < 2 || triple.w.N() < 2)
        throw std::runtime_error("wireSecureAndT: triple must be 2-party");
    co_return co_await wireSecureAnd(
        myX, myY,
        triple.u.shares[partyIdx],
        triple.v.shares[partyIdx],
        triple.w.shares[partyIdx],
        partyIdx, sock);
}

macoro::task<uint8_t> wireSecureOr(
    uint8_t myA,
    uint8_t myB,
    const BeaverTripleBit& triple,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    // a OR b = NOT (NOT a AND NOT b)
    uint8_t myNa = wireNotBit(myA, partyIdx);
    uint8_t myNb = wireNotBit(myB, partyIdx);
    uint8_t myAnd = co_await wireSecureAndT(myNa, myNb, triple, partyIdx, sock);
    co_return wireNotBit(myAnd, partyIdx);
}

size_t wireSecureLessThanTripleCost() {
    // 4 triples per bit position (first, contrib, two ORs) × 64 = 256.
    return 64 * 4;
}

size_t wireSecureEqualTripleCost() {
    // AND-tree over 64 leaves: 63 ANDs.
    return 63;
}

macoro::task<uint8_t> wireSecureLessThan(
    const std::array<uint8_t, 64>& myX,
    const std::array<uint8_t, 64>& myY,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    requireParty01(partyIdx, "wireSecureLessThan");
    auto takeTriple = [&]() -> const BeaverTripleBit& {
        if (tripleIdx >= triples.size())
            throw std::runtime_error("wireSecureLessThan: triple bag exhausted");
        return triples[tripleIdx++];
    };

    // Same circuit as in-memory secureLessThan (MpSecureCompare.cpp):
    // walk bits MSB → LSB; first differing bit decides.
    uint8_t result = 0;
    uint8_t decided = 0;
    for (int i = 63; i >= 0; --i) {
        uint8_t diff = static_cast<uint8_t>((myX[i] ^ myY[i]) & 1);
        uint8_t notDecided = wireNotBit(decided, partyIdx);
        uint8_t first   = co_await wireSecureAndT(diff, notDecided, takeTriple(), partyIdx, sock);
        uint8_t contrib = co_await wireSecureAndT(first, myY[i],     takeTriple(), partyIdx, sock);
        result  = co_await wireSecureOr(result,  contrib, takeTriple(), partyIdx, sock);
        decided = co_await wireSecureOr(decided, first,   takeTriple(), partyIdx, sock);
    }
    co_return result;
}

macoro::task<uint8_t> wireSecureEqual(
    const std::array<uint8_t, 64>& myX,
    const std::array<uint8_t, 64>& myY,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock)
{
    requireParty01(partyIdx, "wireSecureEqual");
    auto takeTriple = [&]() -> const BeaverTripleBit& {
        if (tripleIdx >= triples.size())
            throw std::runtime_error("wireSecureEqual: triple bag exhausted");
        return triples[tripleIdx++];
    };

    // eq_i = NOT (x_i XOR y_i) — free
    std::vector<uint8_t> level(64);
    for (uint32_t i = 0; i < 64; ++i) {
        uint8_t diff = static_cast<uint8_t>((myX[i] ^ myY[i]) & 1);
        level[i] = wireNotBit(diff, partyIdx);
    }
    // AND-tree.
    while (level.size() > 1) {
        std::vector<uint8_t> next;
        next.reserve((level.size() + 1) / 2);
        size_t i = 0;
        for (; i + 1 < level.size(); i += 2) {
            uint8_t a = co_await wireSecureAndT(level[i], level[i + 1],
                                                 takeTriple(), partyIdx, sock);
            next.push_back(a);
        }
        if (i < level.size()) next.push_back(level[i]);
        level = std::move(next);
    }
    co_return level.empty() ? uint8_t{1} : level[0];
}

} // namespace mpstar
} // namespace volePSI
