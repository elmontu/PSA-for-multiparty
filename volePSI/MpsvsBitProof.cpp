#include "MpsvsBitProof.h"

#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::hashToScalar;
using mpstar::pointAdd;
using mpstar::pointSub;
using mpstar::scalarAdd;
using mpstar::scalarMult;
using mpstar::scalarMultBase;
using mpstar::scalarMul;
using mpstar::scalarNegate;
using mpstar::scalarSub;

// Fiat-Shamir challenge: hash( C || A0 || A1 ) → scalar.
static R255Scalar fsChallenge(const R255Point& C,
                                const R255Point& A0,
                                const R255Point& A1) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), C.bytes.begin(), C.bytes.end());
    buf.insert(buf.end(), A0.bytes.begin(), A0.bytes.end());
    buf.insert(buf.end(), A1.bytes.begin(), A1.bytes.end());
    return hashToScalar(buf);
}

// Helper: h = pedersenH.
static R255Point H() { return R255Point::pedersenH(); }

PedersenCommitment commitBit(int b, const R255Scalar& r) {
    // Enforce the bit precondition symmetrically with proveBit — the earlier
    // permissive branch (accepting any int) invited API misuse where a caller
    // could commit to non-boolean values then be surprised when proveBit
    // rejects them. Only b ∈ {0, 1}.
    if (b != 0 && b != 1)
        throw std::invalid_argument("commitBit: b must be 0 or 1");
    R255Point hr = scalarMult(r, H());
    PedersenCommitment c;
    if (b == 0) {
        c.c = hr;   // g^0 · h^r = h^r  (libsodium rejects scalarMultBase(0))
    } else {
        c.c = pointAdd(R255Point::generator(), hr);   // g^1 · h^r
    }
    return c;
}

BitProof proveBit(int bit, const R255Scalar& r, const PedersenCommitment& C) {
    if (bit != 0 && bit != 1)
        throw std::invalid_argument("proveBit: bit must be 0 or 1");

    BitProof pi;
    // Two branches: branch 0 proves C = h^r (so b=0); branch 1 proves C·g^-1 = h^r' (so b=1).
    // Point representing branch-1 target: T1 = C·g^-1.
    R255Point g = R255Point::generator();
    R255Point T0 = C.c;
    R255Point T1 = pointSub(C.c, g);   // C - g

    if (bit == 0) {
        // Real Schnorr on branch 0: prove DL of T0 w.r.t. h.
        // Real: pick fresh w0, compute A0 = h^w0. Later s0 = w0 + c0·r.
        R255Scalar w0 = R255Scalar::random();
        pi.A0 = scalarMult(w0, H());
        // Simulated branch 1: pick c1, s1 uniform; compute A1 = h^s1 · T1^-c1.
        pi.c1 = R255Scalar::random();
        pi.s1 = R255Scalar::random();
        R255Point term1 = scalarMult(pi.s1, H());
        R255Point term2 = scalarMult(pi.c1, T1);
        pi.A1 = pointSub(term1, term2);
        // FS challenge combining A0, A1.
        R255Scalar c_combined = fsChallenge(C.c, pi.A0, pi.A1);
        pi.c0 = scalarSub(c_combined, pi.c1);   // c0 = c - c1
        // Real response for branch 0.
        pi.s0 = scalarAdd(w0, scalarMul(pi.c0, r));
    } else {
        // bit == 1. Real Schnorr on branch 1: prove DL of T1 w.r.t. h with witness r.
        R255Scalar w1 = R255Scalar::random();
        pi.A1 = scalarMult(w1, H());
        // Simulated branch 0.
        pi.c0 = R255Scalar::random();
        pi.s0 = R255Scalar::random();
        R255Point term1 = scalarMult(pi.s0, H());
        R255Point term2 = scalarMult(pi.c0, T0);
        pi.A0 = pointSub(term1, term2);
        R255Scalar c_combined = fsChallenge(C.c, pi.A0, pi.A1);
        pi.c1 = scalarSub(c_combined, pi.c0);
        pi.s1 = scalarAdd(w1, scalarMul(pi.c1, r));
    }
    return pi;
}

bool verifyBit(const BitProof& pi, const PedersenCommitment& C) {
    // Recompute Fiat-Shamir challenge.
    R255Scalar c_combined = fsChallenge(C.c, pi.A0, pi.A1);
    R255Scalar c_sum = scalarAdd(pi.c0, pi.c1);
    if (!(c_sum == c_combined)) return false;

    R255Point g = R255Point::generator();
    R255Point T0 = C.c;
    R255Point T1 = pointSub(C.c, g);

    // Branch 0 check: h^s0 == A0 + T0^c0
    R255Point lhs0 = scalarMult(pi.s0, H());
    R255Point rhs0 = pointAdd(pi.A0, scalarMult(pi.c0, T0));
    if (!(lhs0 == rhs0)) return false;

    // Branch 1 check: h^s1 == A1 + T1^c1
    R255Point lhs1 = scalarMult(pi.s1, H());
    R255Point rhs1 = pointAdd(pi.A1, scalarMult(pi.c1, T1));
    if (!(lhs1 == rhs1)) return false;

    return true;
}

} // namespace mpsvs
} // namespace volePSI
