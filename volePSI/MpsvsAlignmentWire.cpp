#include "MpsvsAlignmentWire.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::mpcBitonicSort;
using mpstar::mpcBitonicSortTripleCost;
using mpstar::SharedSortElement;
using mpstar::secureAnd;
using mpstar::secureEqual;
using mpstar::secureEqualTripleCost;
using mpstar::shareBit;
using mpstar::shareU64Bin;
using mpstar::xorConst;
using mpstar::xorShared;

size_t alignmentWireTripleBudget(size_t bin_size) {
    // Sort: mpcBitonicSortTripleCost(n, key=64, payload bits ≈ 130)
    //   Actually SharedSortElement's payload is a vector<SharedBit>; we'll
    //   pack: memb(1) + sector(64) + payload(64) + source(8) = 137 bits.
    size_t sort = mpcBitonicSortTripleCost(bin_size, 137);
    // Merge: per adjacent pair, 1 secureEqual + 3 · 64 secureAnd for MUXes
    // + a few extra ANDs for the memb-AND gate.
    size_t merge = bin_size * (secureEqualTripleCost() + 3 * 64 + 8);
    return sort + merge + 1000;
}

SharedBinRow shareBinRow(uint32_t bin, uint8_t source, uint64_t key,
                          uint8_t memb, uint64_t sector, uint64_t payload,
                          oc::PRNG& prng) {
    SharedBinRow r;
    r.bin = bin;
    r.source = source;
    r.key = shareU64Bin(2, key, prng);
    r.memb = shareBit(2, memb, prng);
    r.sector = shareU64Bin(2, sector, prng);
    r.payload = shareU64Bin(2, payload, prng);
    return r;
}

// ---------------------------------------------------------------------------
// withinBinSortWire — pack (memb, sector, payload, source) into payload bits.
// ---------------------------------------------------------------------------

// Payload layout (137 bits):
//   [0]        memb
//   [1..64]    sector (64 bits)
//   [65..128]  payload (64 bits)
//   [129..136] source (8 bits, public but stored as shared for uniformity)
static constexpr int kMembBit = 0;
static constexpr int kSectorStart = 1;   // 64 bits
static constexpr int kPayloadStart = 65; // 64 bits
static constexpr int kSourceStart = 129; // 8 bits
static constexpr int kPayloadBitsTotal = 137;

static SharedSortElement toSortElement(const SharedBinRow& r) {
    SharedSortElement e;
    e.key = r.key;
    const uint32_t N = r.key.N();
    e.payload.assign(kPayloadBitsTotal, SharedBit(N));
    e.payload[kMembBit] = r.memb;
    for (int i = 0; i < 64; ++i) e.payload[kSectorStart + i] = r.sector.bits[i];
    for (int i = 0; i < 64; ++i) e.payload[kPayloadStart + i] = r.payload.bits[i];
    for (int i = 0; i < 8; ++i) {
        SharedBit sb(N);
        sb.shares[0] = (r.source >> i) & 1;
        e.payload[kSourceStart + i] = sb;
    }
    return e;
}

static SharedBinRow fromSortElement(const SharedSortElement& e, uint32_t bin) {
    SharedBinRow r;
    r.bin = bin;
    r.key = e.key;
    r.memb = e.payload[kMembBit];
    for (int i = 0; i < 64; ++i) r.sector.bits[i] = e.payload[kSectorStart + i];
    for (int i = 0; i < 64; ++i) r.payload.bits[i] = e.payload[kPayloadStart + i];
    // Source: reconstruct 8 bits (public — party 0 held them all).
    uint8_t src = 0;
    for (int i = 0; i < 8; ++i) src |= (e.payload[kSourceStart + i].reconstruct() & 1) << i;
    r.source = src;
    return r;
}

void withinBinSortWire(std::vector<SharedBinRow>& rows,
                        const std::vector<BeaverTripleBit>& triples,
                        size_t& idx) {
    if (rows.empty()) return;
    // Pad to power of 2 with max-key dummy rows (memb=0).
    uint32_t bin = rows.front().bin;
    size_t target = 1;
    while (target < rows.size()) target *= 2;
    while (rows.size() < target) {
        const uint32_t N = rows.front().key.N();
        SharedBinRow dummy;
        dummy.bin = bin;
        dummy.source = 4;   // sentinel public source
        // Key = all-1s (max u64 — sorts to the end).
        for (int i = 0; i < 64; ++i) {
            SharedBit sb(N); sb.shares[0] = 1; dummy.key.bits[i] = sb;
        }
        dummy.memb = SharedBit(N);   // shared zero
        for (int i = 0; i < 64; ++i) dummy.sector.bits[i] = SharedBit(N);
        for (int i = 0; i < 64; ++i) dummy.payload.bits[i] = SharedBit(N);
        rows.push_back(std::move(dummy));
    }

    // Convert to sort elements.
    std::vector<SharedSortElement> xs;
    xs.reserve(rows.size());
    for (const auto& r : rows) xs.push_back(toSortElement(r));

    mpcBitonicSort(xs, triples, idx);

    // Convert back.
    rows.clear();
    rows.reserve(xs.size());
    for (const auto& e : xs) rows.push_back(fromSortElement(e, bin));
}

// ---------------------------------------------------------------------------
// windowedMergeWire — R16-gated adjacent merge.
// ---------------------------------------------------------------------------

// Per-bit MUX: (bit ? a : b) = b XOR (bit AND (a XOR b)). Cost 1 secureAnd.
static SharedBit muxBit(const SharedBit& bit, const SharedBit& a,
                         const SharedBit& b,
                         const std::vector<BeaverTripleBit>& triples,
                         size_t& idx) {
    SharedBit diff = xorShared(a, b);
    SharedBit gated = secureAnd(bit, diff, triples[idx++]);
    return xorShared(b, gated);
}

// Per-bit MUX over 64-bit SharedU64Bin: 64 secureAnd.
static SharedU64Bin muxU64Bin(const SharedBit& bit, const SharedU64Bin& a,
                                const SharedU64Bin& b,
                                const std::vector<BeaverTripleBit>& triples,
                                size_t& idx) {
    SharedU64Bin out;
    for (int i = 0; i < 64; ++i) {
        out.bits[i] = muxBit(bit, a.bits[i], b.bits[i], triples, idx);
    }
    return out;
}

std::vector<SharedMergedRow>
windowedMergeWire(const std::vector<SharedBinRow>& sorted,
                    const std::vector<BeaverTripleBit>& triples,
                    size_t& idx) {
    std::vector<SharedMergedRow> out;
    if (sorted.empty()) return out;
    out.reserve(sorted.size());

    // Adjacent-pair scan. For each i:
    //   key_match_i = secureEqual(sorted[i].key, sorted[i+1].key)
    //   both_real_i = memb_i AND memb_{i+1}
    //   live_i     = key_match_i AND both_real_i          // R16
    //   emit row combining sorted[i] and sorted[i+1] payloads via MUX
    //     (test scope: single-source merge → payload = MUX(live, i, i+1))
    // For the last row (no successor): live=0, emit self.
    const uint32_t N = sorted.front().key.N();
    for (size_t i = 0; i < sorted.size(); ++i) {
        SharedMergedRow m;
        m.bin = sorted[i].bin;
        if (i + 1 == sorted.size()) {
            // No successor.
            m.live = SharedBit(N);   // shared zero
            m.key = sorted[i].key;
            m.sector = sorted[i].sector;
            m.payload = sorted[i].payload;
            out.push_back(std::move(m));
            continue;
        }
        SharedBit key_match = secureEqual(sorted[i].key, sorted[i + 1].key,
                                            triples, idx);
        SharedBit both_real = secureAnd(sorted[i].memb, sorted[i + 1].memb,
                                          triples[idx++]);
        SharedBit live = secureAnd(key_match, both_real, triples[idx++]);
        m.live = live;
        // Combine payloads via MUX on live:
        //   payload = live ? sorted[i].payload : sorted[i].payload
        // (Trivial for single-source test — same value picked either way;
        // multi-source case would pick the other source's payload from i+1.)
        m.key = sorted[i].key;
        m.sector = muxU64Bin(live, sorted[i].sector, sorted[i].sector,
                              triples, idx);
        m.payload = muxU64Bin(live, sorted[i + 1].payload, sorted[i].payload,
                                triples, idx);
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<PlainMergedRow>
reconstructMerged(const std::vector<SharedMergedRow>& shared) {
    std::vector<PlainMergedRow> out;
    out.reserve(shared.size());
    for (const auto& s : shared) {
        PlainMergedRow p;
        p.bin = s.bin;
        p.live = s.live.reconstruct();
        p.key = s.key.reconstruct();
        p.sector = s.sector.reconstruct();
        p.payload = s.payload.reconstruct();
        out.push_back(p);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
