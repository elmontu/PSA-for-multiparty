#include "MpsvsConstTime.h"

namespace volePSI {
namespace mpsvs {

const char* ctSelfCheck() {
    // Equality
    if (ctEqU64(0, 0) != 1) return "ctSelfCheck: ctEqU64(0,0) != 1";
    if (ctEqU64(1, 0) != 0) return "ctSelfCheck: ctEqU64(1,0) != 0";
    if (ctEqU64(~0ULL, ~0ULL) != 1) return "ctSelfCheck: ctEqU64(~0,~0) != 1";
    if (ctEqU64(0x8000000000000000ULL, 0) != 0)
        return "ctSelfCheck: ctEqU64(msb,0) != 0";

    // Less-than
    if (ctLtU64(0, 1) != 1) return "ctSelfCheck: ctLtU64(0,1) != 1";
    if (ctLtU64(1, 0) != 0) return "ctSelfCheck: ctLtU64(1,0) != 0";
    if (ctLtU64(0, 0) != 0) return "ctSelfCheck: ctLtU64(0,0) != 0";
    if (ctLtU64(~0ULL - 1, ~0ULL) != 1)
        return "ctSelfCheck: ctLtU64(max-1,max) != 1";
    // Wrap edge: MSB set on both operands
    if (ctLtU64(0x8000000000000000ULL, 0x8000000000000001ULL) != 1)
        return "ctSelfCheck: ctLtU64(msb, msb+1) != 1";

    // Mux
    if (ctMuxU64(1, 0xAA, 0xBB) != 0xAA)
        return "ctSelfCheck: ctMuxU64(1, .., ..) wrong";
    if (ctMuxU64(0, 0xAA, 0xBB) != 0xBB)
        return "ctSelfCheck: ctMuxU64(0, .., ..) wrong";
    // sel with high bits set — should still select on low bit only
    if (ctMuxU64(0xFFFFFFFFFFFFFFFEULL, 0xAA, 0xBB) != 0xBB)
        return "ctSelfCheck: ctMuxU64(even-with-hi-bits) wrong";
    if (ctMuxU64(0xFFFFFFFFFFFFFFFFULL, 0xAA, 0xBB) != 0xAA)
        return "ctSelfCheck: ctMuxU64(all-ones) wrong";

    // Derived Ne/Le/Ge/Gt
    if (ctNeqU64(1, 1) != 0) return "ctSelfCheck: ctNeqU64(1,1) != 0";
    if (ctNeqU64(1, 2) != 1) return "ctSelfCheck: ctNeqU64(1,2) != 1";
    if (ctLeU64(1, 1) != 1)  return "ctSelfCheck: ctLeU64(1,1) != 1";
    if (ctLeU64(2, 1) != 0)  return "ctSelfCheck: ctLeU64(2,1) != 0";
    if (ctGtU64(2, 1) != 1)  return "ctSelfCheck: ctGtU64(2,1) != 1";
    if (ctGeU64(1, 1) != 1)  return "ctSelfCheck: ctGeU64(1,1) != 1";

    // Signed
    if (ctLtI64(-1, 1) != 1) return "ctSelfCheck: ctLtI64(-1, 1) != 1";
    if (ctLtI64(1, -1) != 0) return "ctSelfCheck: ctLtI64(1, -1) != 0";
    if (ctLtI64(-2, -1) != 1) return "ctSelfCheck: ctLtI64(-2, -1) != 1";

    // Byte compare
    unsigned char a[8] = {1,2,3,4,5,6,7,8};
    unsigned char b[8] = {1,2,3,4,5,6,7,8};
    unsigned char c[8] = {1,2,3,4,5,6,7,9};
    if (ctMemcmpEq(a, b, 8) != 1) return "ctSelfCheck: ctMemcmpEq(a,b) != 1";
    if (ctMemcmpEq(a, c, 8) != 0) return "ctSelfCheck: ctMemcmpEq(a,c) != 0";

    return "";
}

} // namespace mpsvs
} // namespace volePSI
