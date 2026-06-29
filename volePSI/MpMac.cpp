#include "MpMac.h"

#include "cryptoTools/Crypto/PRNG.h"
#include <stdexcept>

namespace volePSI {
namespace mpstar {

AuthShare xorAuth(const AuthShare& a, const AuthShare& b)
{
    if (a.size() != b.size())
        throw std::runtime_error("xorAuth: size mismatch");
    AuthShare out;
    out.data.resize(a.size());
    out.tag.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out.data[i] = a.data[i] ^ b.data[i];
        out.tag[i]  = a.tag[i]  ^ b.tag[i];
    }
    return out;
}

AuthShare xorConstAuth(const AuthShare& a,
                       const std::vector<oc::block>& c,
                       const oc::block& alpha)
{
    if (a.size() != c.size())
        throw std::runtime_error("xorConstAuth: size mismatch");
    AuthShare out;
    out.data.resize(a.size());
    out.tag.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out.data[i] = a.data[i] ^ c[i];
        out.tag[i]  = a.tag[i]  ^ alpha.gf128Mul(c[i]);
    }
    return out;
}

AuthShare permuteAuth(const AuthShare& a, const std::vector<int>& dest)
{
    if (a.size() != dest.size())
        throw std::runtime_error("permuteAuth: size mismatch");
    AuthShare out;
    out.data.resize(a.size());
    out.tag.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        int src = dest[i];
        if (src < 0 || static_cast<size_t>(src) >= a.size())
            throw std::runtime_error("permuteAuth: dest out of range");
        out.data[i] = a.data[src];
        out.tag[i]  = a.tag[src];
    }
    return out;
}

std::vector<oc::block> tagVector(const oc::block& alpha,
                                 const std::vector<oc::block>& plain)
{
    std::vector<oc::block> out(plain.size());
    for (size_t i = 0; i < plain.size(); ++i) {
        out[i] = alpha.gf128Mul(plain[i]);
    }
    return out;
}

std::pair<AuthShare, AuthShare> randomAuthShare(
    const std::vector<oc::block>& plain,
    const oc::block& alpha,
    oc::PRNG& prng)
{
    size_t C = plain.size();
    AuthShare s1, s2;
    s1.data.resize(C);
    s1.tag.resize(C);
    s2.data.resize(C);
    s2.tag.resize(C);
    for (size_t i = 0; i < C; ++i) {
        // Pick s1.data uniformly at random; derive s2.data = plain ⊕ s1.data.
        s1.data[i] = prng.get<oc::block>();
        s2.data[i] = s1.data[i] ^ plain[i];
        // Tag homomorphism: tag1 ⊕ tag2 = α · plain.
        // Pick tag1 uniformly; derive tag2 = α·plain ⊕ tag1.
        s1.tag[i] = prng.get<oc::block>();
        s2.tag[i] = s1.tag[i] ^ alpha.gf128Mul(plain[i]);
    }
    return {std::move(s1), std::move(s2)};
}

bool verifyAuthShares(const AuthShare& a1, const AuthShare& a2,
                      const oc::block& alpha)
{
    if (a1.size() != a2.size()) return false;
    for (size_t i = 0; i < a1.size(); ++i) {
        oc::block joint_data = a1.data[i] ^ a2.data[i];
        oc::block joint_tag  = a1.tag[i]  ^ a2.tag[i];
        oc::block expected   = alpha.gf128Mul(joint_data);
        if (!(joint_tag == expected)) return false;
    }
    return true;
}

bool verifyAuthSharesBatched(const AuthShare& a1, const AuthShare& a2,
                             const oc::block& alpha,
                             const std::vector<oc::block>& challenge)
{
    if (a1.size() != a2.size()) return false;
    if (a1.size() != challenge.size()) return false;

    // <challenge, joint_tag> = α · <challenge, joint_data>?
    // All dot products in GF(2^128).
    oc::block left_acc  = oc::block(0, 0);
    oc::block right_acc = oc::block(0, 0);
    for (size_t i = 0; i < a1.size(); ++i) {
        oc::block joint_data = a1.data[i] ^ a2.data[i];
        oc::block joint_tag  = a1.tag[i]  ^ a2.tag[i];
        left_acc  = left_acc  ^ challenge[i].gf128Mul(joint_tag);
        right_acc = right_acc ^ challenge[i].gf128Mul(joint_data);
    }
    oc::block expected_right = alpha.gf128Mul(right_acc);
    return left_acc == expected_right;
}

} // namespace mpstar
} // namespace volePSI
