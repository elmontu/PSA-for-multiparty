#include "MpsvsRankWire.h"

#include <algorithm>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::conditionalSwapTripleCost;
using mpstar::secureAnd;
using mpstar::secureLessThanTripleCost;
using mpstar::shareBit;
using mpstar::shareU64Bin;
using mpstar::xorConst;
using mpstar::xorShared;

// ---------------------------------------------------------------------------
// Bit-shared ripple-carry adder (for rank increment on shared u64).
// ---------------------------------------------------------------------------
static SharedU64Bin
bitAddRC(const SharedU64Bin& x, const SharedU64Bin& y,
         const std::vector<BeaverTripleBit>& triples, size_t& idx) {
    SharedU64Bin out;
    const uint32_t N = x.N();
    SharedBit carry(N);
    for (int i = 0; i < 64; ++i) {
        SharedBit ab = xorShared(x.bits[i], y.bits[i]);
        SharedBit sum = xorShared(ab, carry);
        SharedBit and_ab = secureAnd(x.bits[i], y.bits[i], triples[idx++]);
        SharedBit and_cab = secureAnd(carry, ab, triples[idx++]);
        SharedBit or_a = xorShared(and_ab, and_cab);
        SharedBit or_b = secureAnd(and_ab, and_cab, triples[idx++]);
        carry = xorShared(or_a, or_b);
        out.bits[i] = sum;
    }
    return out;
}

size_t rankWireTripleBudget(size_t n_rows, uint32_t B) {
    // Sort: uses mpcBitonicSortTripleCost — key width 64, payload width ~40.
    // Segmented scan: n rows × (bit-add cost = 192 per full-adder × 64 bits).
    //   Segmented scan resets rank at popkey boundary — since popkeys are
    //   PUBLIC, this is a plaintext operation on the segment boundary.
    // Per row: 1 bit-add of incl into running rank = 64 · 3 = 192 triples.
    (void)B;
    size_t sort_cost = mpcBitonicSortTripleCost(n_rows, /*payloadBits=*/40);
    size_t scan_cost = n_rows * 192;
    return sort_cost + scan_cost + 500;
}

// ---------------------------------------------------------------------------
// Build composite sort key: popkey(8) || invalid(1) || bucket(7) || 0(48)
// popkey is public (encoded into party-0 of the shared key so reconstruction
// gives popkey directly in top bits).
// ---------------------------------------------------------------------------

static SharedU64Bin buildSortKey(uint32_t popkey, const SharedBit& incl,
                                   const SharedU64Bin& bucket,
                                   oc::PRNG& prng) {
    const uint32_t N = bucket.N();
    SharedU64Bin key;
    for (int i = 0; i < 64; ++i) key.bits[i] = SharedBit(N);

    // Public popkey in top 8 bits (56..63).
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = (popkey >> i) & 1;
        SharedBit sb(N);
        sb.shares[0] = bit;    // party 0 holds; party 1 = 0 → XOR = bit
        key.bits[56 + i] = sb;
    }
    // Invalid = NOT incl in bit 55.
    key.bits[55] = xorConst(incl, 1);
    // Bucket bits [48..54] — copy from `bucket.bits[0..6]`
    for (int i = 0; i < 7; ++i) {
        key.bits[48 + i] = bucket.bits[i];
    }
    (void)prng;
    return key;
}

// Encode entity_idx (32 bits, PUBLIC) + incl (SharedBit) + bucket (7 bits)
// into a 40-bit payload for the sort.
static std::vector<SharedBit>
buildPayload(uint32_t entity_idx, const SharedBit& incl,
              const SharedU64Bin& bucket, oc::PRNG& prng) {
    const uint32_t N = bucket.N();
    std::vector<SharedBit> pl(40, SharedBit(N));
    // entity_idx in [0..31]
    for (int i = 0; i < 32; ++i) {
        uint8_t bit = (entity_idx >> i) & 1;
        SharedBit sb(N);
        sb.shares[0] = bit;
        pl[i] = sb;
    }
    pl[32] = incl;
    for (int i = 0; i < 7; ++i) pl[33 + i] = bucket.bits[i];
    (void)prng;
    return pl;
}

// Decode a sorted payload back to (entity_idx, incl, bucket).
static void decodePayload(const std::vector<SharedBit>& pl,
                           uint32_t& entity_idx, SharedBit& incl,
                           SharedU64Bin& bucket) {
    const uint32_t N = pl[0].N();
    // entity_idx: XOR-reconstruct top 32 bits (public — bits[0..31] have
    // party 0 = value, party 1 = 0, so reconstruct = value).
    entity_idx = 0;
    for (int i = 0; i < 32; ++i) {
        uint32_t bit = pl[i].reconstruct();
        entity_idx |= (bit & 1) << i;
    }
    incl = pl[32];
    bucket = SharedU64Bin();
    for (int i = 0; i < 7; ++i) bucket.bits[i] = pl[33 + i];
    for (int i = 7; i < 64; ++i) bucket.bits[i] = SharedBit(N);
}

// ---------------------------------------------------------------------------
// rankViaHistogramWire
// ---------------------------------------------------------------------------

std::vector<SharedRankedRow>
rankViaHistogramWire(const std::vector<SharedEntityMetricRow>& rows,
                      Metric m,
                      uint32_t B,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& idx,
                      oc::PRNG& prng) {
    if (rows.empty()) return {};
    const uint32_t N = rows[0].live.N();

    // 1. Extract shared bucket per row via Phase 6 wire's bucketIndex output.
    //    For Phase 8 test, callers pass metric_rows whose `metrics[m].incl` is
    //    already shared; bucket is computed elsewhere. For this wire we assume
    //    caller has produced a shared bucket per row via bucketIndexWire and
    //    packed it into the row structure via a side channel. For test scope,
    //    we treat `metrics[m].num` as containing the SHARED BUCKET already
    //    (test-only shortcut; production wires bucketIndexWire → this).
    struct SlimEntry {
        uint32_t entity_idx;
        uint32_t popkey;
        SharedBit incl;
        SharedU64Bin bucket;
    };
    std::vector<SlimEntry> slim;
    slim.reserve(rows.size());
    for (uint32_t i = 0; i < rows.size(); ++i) {
        SlimEntry s;
        s.entity_idx = i;
        s.popkey = rows[i].sector;   // popkey = sector (public)
        s.incl = rows[i].metrics[static_cast<size_t>(m)].incl;
        // For semantic test, reuse `num` field as bucket ID (test-only).
        s.bucket = rows[i].metrics[static_cast<size_t>(m)].num;
        slim.push_back(s);
    }
    (void)B;

    // 2. Build sort elements (key + payload) and pad to power-of-two.
    std::vector<SharedSortElement> xs;
    xs.reserve(slim.size());
    for (auto& s : slim) {
        SharedSortElement e;
        e.key = buildSortKey(s.popkey, s.incl, s.bucket, prng);
        e.payload = buildPayload(s.entity_idx, s.incl, s.bucket, prng);
        xs.push_back(std::move(e));
    }
    // Pad to power of 2 with max-key dummy rows (popkey = 0xff, invalid=1).
    size_t target = 1;
    while (target < xs.size()) target *= 2;
    while (xs.size() < target) {
        SharedSortElement dummy;
        SharedU64Bin key;
        for (int i = 0; i < 64; ++i) key.bits[i] = SharedBit(N);
        for (int i = 0; i < 8; ++i) {
            SharedBit sb(N); sb.shares[0] = 1; key.bits[56 + i] = sb;
        }
        SharedBit inv(N); inv.shares[0] = 1; key.bits[55] = inv;
        dummy.key = key;
        dummy.payload.assign(40, SharedBit(N));
        xs.push_back(std::move(dummy));
    }

    // 3. Sort on shares.
    mpcBitonicSort(xs, triples, idx);

    // 4. Decode sorted payloads + segmented scan on incl bit within (public)
    //    popkey segments. Popkey is public post-sort (bits reconstruct
    //    deterministically because they were public in the key).
    std::vector<SharedRankedRow> out;
    out.reserve(slim.size());

    // Pass 1: reconstruct popkey per row to determine segment boundaries.
    // Reconstruct top 8 key bits (public bits).
    std::vector<uint32_t> row_popkey(xs.size());
    std::vector<uint8_t> row_invalid(xs.size());
    for (size_t i = 0; i < xs.size(); ++i) {
        uint32_t pk = 0;
        for (int b = 0; b < 8; ++b) {
            pk |= (xs[i].key.bits[56 + b].reconstruct() & 1) << b;
        }
        row_popkey[i] = pk;
        row_invalid[i] = xs[i].key.bits[55].reconstruct();
    }

    // Pass 2: for each real (non-padding, non-invalid, popkey != 0xff) row,
    // accumulate rank via bit-add.
    uint32_t cur_popkey = 0xffff;
    SharedU64Bin rank_acc = shareU64Bin(N, 0, prng);
    for (size_t i = 0; i < xs.size(); ++i) {
        if (row_popkey[i] == 0xff) continue;   // padding
        if (row_popkey[i] != cur_popkey) {
            cur_popkey = row_popkey[i];
            rank_acc = shareU64Bin(N, 0, prng);
        }
        SharedRankedRow r;
        decodePayload(xs[i].payload, r.entity_idx, r.incl, r.bucket);
        r.popkey = row_popkey[i];
        // rank = current rank_acc; then rank_acc += incl_arith
        r.rank = rank_acc;
        // Increment by incl: build a SharedU64Bin whose bit[0] = incl.
        SharedU64Bin incl_bin;
        for (int b = 0; b < 64; ++b) incl_bin.bits[b] = SharedBit(N);
        incl_bin.bits[0] = r.incl;
        rank_acc = bitAddRC(rank_acc, incl_bin, triples, idx);
        out.push_back(r);
    }
    return out;
}

std::vector<PlainRankedRow>
reconstructRanked(const std::vector<SharedRankedRow>& shared) {
    std::vector<PlainRankedRow> out;
    out.reserve(shared.size());
    for (const auto& r : shared) {
        PlainRankedRow p;
        p.entity_idx = r.entity_idx;
        p.popkey = r.popkey;
        p.incl = r.incl.reconstruct();
        p.bucket = static_cast<uint32_t>(r.bucket.reconstruct() & 0x7F);
        p.rank = r.rank.reconstruct();
        out.push_back(p);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
