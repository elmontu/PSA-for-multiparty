#include "MpMpcArithmetic.h"

#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

const BeaverTripleBit& takeTriple(
    const std::vector<BeaverTripleBit>& triples, size_t& idx)
{
    if (idx >= triples.size())
        throw std::runtime_error("MpMpcArithmetic::takeTriple: bag exhausted");
    return triples[idx++];
}

// Bitwise NOT of a XOR-shared bit: party 0 flips its share (xorConst(a, 1)).
// Local, free.
SharedBit notShared(const SharedBit& a) {
    return xorConst(a, 1);
}

} // namespace

// --------- ripple-carry adder -------------------------------------------

size_t secureAddU64BinTripleCost() {
    // bit 0: c_out = a_0 AND b_0                 -> 1 triple
    // bits 1..63: full-adder using propagate/generate:
    //   p_i = a_i XOR b_i                        (free)
    //   g_i = a_i AND b_i                        -> 1 triple
    //   s_i = p_i XOR c_in                       (free)
    //   c_out = g_i XOR (p_i AND c_in)           -> 1 triple
    //   Total per bit: 2 triples
    // Grand total: 1 + 2 * 63 = 127 triples.
    return 1 + 2 * 63;
}

AddResult secureAddU64Bin(const SharedU64Bin& x,
                          const SharedU64Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex)
{
    if (x.N() != y.N())
        throw std::runtime_error("secureAddU64Bin: N mismatch");

    AddResult out;
    // Carry chain. Start with no carry-in for bit 0.
    // Bit 0 special case: no c_in.
    out.sum.bits[0] = xorShared(x.bits[0], y.bits[0]);      // s_0 = a XOR b
    SharedBit carry = secureAnd(x.bits[0], y.bits[0],
                                takeTriple(triples, tripleIndex)); // c_0 = a AND b

    for (uint32_t i = 1; i < 64; ++i) {
        SharedBit p    = xorShared(x.bits[i], y.bits[i]);   // propagate
        SharedBit g    = secureAnd(x.bits[i], y.bits[i],
                                   takeTriple(triples, tripleIndex));  // generate
        out.sum.bits[i] = xorShared(p, carry);              // s_i = p XOR c_in
        SharedBit pc   = secureAnd(p, carry,
                                   takeTriple(triples, tripleIndex));
        carry = xorShared(g, pc);                           // c_out = g XOR (p AND c_in)
    }
    out.carryOut = carry;
    return out;
}

// --------- subtraction via two's complement -----------------------------

size_t secureSubU64BinTripleCost() {
    // x - y = x + (~y + 1) = x + (~y) with an extra c_in = 1.
    //
    // We implement this by inlining the adder with y replaced by ~y and
    // an initial carry-in of 1. The cost is the same as the plain adder:
    //   bit 0: c_out = (a AND ~b) OR (a XOR ~b) AND 1  -> simplifies to
    //          full-adder with c_in=1, 2 triples
    //   bits 1..63: 2 triples each
    // Total: 2 * 64 = 128 triples. Slightly more than plain add because
    // bit 0 now has a non-zero c_in.
    return 2 * 64;
}

SubResult secureSubU64Bin(const SharedU64Bin& x,
                          const SharedU64Bin& y,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex)
{
    if (x.N() != y.N())
        throw std::runtime_error("secureSubU64Bin: N mismatch");
    const uint32_t N = x.N();

    // Compute ny_i = NOT y_i (bitwise, local free).
    SharedU64Bin ny;
    for (uint32_t i = 0; i < 64; ++i)
        ny.bits[i] = notShared(y.bits[i]);

    // Adder with c_in = 1 (public constant). We manually run the full-adder
    // formula so bit 0 also uses 2 triples (matching the cost model).
    SubResult out;
    // Initial c_in = 1 (public constant). Represented as SharedBit with
    // party-0 share = 1, others = 0. This is what xorConst does at bit 0.
    SharedBit carry(N);
    carry.shares[0] = 1;   // public constant 1 as an additive share

    for (uint32_t i = 0; i < 64; ++i) {
        SharedBit p = xorShared(x.bits[i], ny.bits[i]);
        SharedBit g = secureAnd(x.bits[i], ny.bits[i],
                                takeTriple(triples, tripleIndex));
        out.diff.bits[i] = xorShared(p, carry);
        SharedBit pc = secureAnd(p, carry,
                                 takeTriple(triples, tripleIndex));
        carry = xorShared(g, pc);
    }
    // In two's-complement subtraction, borrow_out = NOT (final carry_out).
    //   x - y = x + ~y + 1. If x >= y: this wraps up to 2^64 or more, so
    //   the adder's carry-out is 1. If x < y: no wrap, carry-out is 0.
    // Therefore borrow_out (i.e., "did we underflow, meaning x < y") is
    // exactly NOT carry_out.
    out.borrowOut = notShared(carry);
    return out;
}

// ---------- secure 1-bit multiplexer -----------------------------------
// select(cond, a, b) = cond ? a : b, for XOR-shared bits.
// Standard identity: cond ? a : b  =  b XOR (cond AND (a XOR b)).
// Cost: 1 Beaver bit-triple.
namespace {
SharedBit secureSelectBit(const SharedBit& cond,
                          const SharedBit& a,
                          const SharedBit& b,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex)
{
    SharedBit axb = xorShared(a, b);
    SharedBit maybe = secureAnd(cond, axb, takeTriple(triples, tripleIndex));
    return xorShared(b, maybe);
}
} // namespace

// ---------- secure integer division ------------------------------------

size_t secureDivideU64BinTripleCost() {
    // 64 iterations of the division loop, each doing:
    //   1x secureSubU64Bin (trial subtract): 128 triples
    //   64x secureSelectBit (MUX between R and R_minus_denom, one per bit): 64 triples
    // Plus 1 divByZero check via secureEqual on denom vs 0: 63 triples.
    //
    // Total per division:
    //   64 * (128 + 64) + 63  =  64 * 192 + 63  =  12288 + 63 = 12351 triples
    return 64 * (secureSubU64BinTripleCost() + 64) + 63;
}

DivResult secureDivideU64Bin(const SharedU64Bin& num,
                             const SharedU64Bin& denom,
                             const std::vector<BeaverTripleBit>& triples,
                             size_t& tripleIndex)
{
    if (num.N() != denom.N())
        throw std::runtime_error("secureDivideU64Bin: N mismatch");
    const uint32_t N = num.N();

    // ---- Step 1: divByZero check (denom == 0) ----
    // secureEqual compares two SharedU64Bin; we compare denom vs a canonical
    // all-zero SharedU64Bin. All-zero is just SharedBit(N)*64 (default ctor).
    SharedU64Bin zero;
    for (uint32_t i = 0; i < 64; ++i) {
        zero.bits[i] = SharedBit(N);   // default = all-zero shares
    }
    SharedBit dbz = secureEqual(denom, zero, triples, tripleIndex);

    // If divByZero, we want the arithmetic loop below to behave "as if
    // denom = 1" so the outputs stay well-defined (quotient=num, remainder=0
    // for that case). Cheapest way: substitute denom with denom_effective =
    // denom OR (divByZero shifted into bit 0). But secure-OR isn't strictly
    // needed — we just use denom as-is; when denom=0, every trial subtract
    // "succeeds" (R - 0 = R, borrow=0), so every quotient bit becomes 1,
    // giving quotient=2^64-1, remainder=num. Caller inspects divByZero and
    // discards. This is fine for the primitive; the CALLER masks. If a
    // safer output is required (quotient=num, remainder=0 on dbz), the
    // caller layers another select after this call.

    // ---- Step 2: long division loop ----
    DivResult out;
    // Initialize R = 0, Q = 0.
    for (uint32_t i = 0; i < 64; ++i) {
        out.remainder.bits[i] = SharedBit(N);
        out.quotient.bits[i]  = SharedBit(N);
    }

    for (int32_t i = 63; i >= 0; --i) {
        // Shift R left by 1: R.bits[j] = R.bits[j-1] for j > 0; R.bits[0] = num.bits[i].
        // (LSB is bits[0]; MSB is bits[63]. Left shift means bit j becomes
        //  bit j+1; we shift toward the MSB; the low bit fills from num.)
        SharedU64Bin Rshift;
        for (int32_t j = 63; j >= 1; --j) {
            Rshift.bits[j] = out.remainder.bits[j - 1];
        }
        Rshift.bits[0] = num.bits[static_cast<uint32_t>(i)];

        // Trial subtract: R_minus = Rshift - denom.
        SubResult sub = secureSubU64Bin(Rshift, denom, triples, tripleIndex);

        // borrow = 1 iff Rshift < denom (i.e., trial subtract underflowed).
        // If borrow == 0: take Rshift - denom (new R = R_minus), quotient bit = 1.
        // If borrow == 1: keep Rshift as-is (new R = Rshift),   quotient bit = 0.
        SharedBit qbit = notShared(sub.borrowOut);

        // Multiplex: new_R = borrow ? Rshift : R_minus.
        SharedU64Bin newR;
        for (uint32_t j = 0; j < 64; ++j) {
            newR.bits[j] = secureSelectBit(sub.borrowOut,
                                           Rshift.bits[j],
                                           sub.diff.bits[j],
                                           triples, tripleIndex);
        }
        out.remainder = newR;
        out.quotient.bits[static_cast<uint32_t>(i)] = qbit;
    }

    out.divByZero = dbz;
    return out;
}

} // namespace mpstar
} // namespace volePSI
