#include "MpCgpShuffle.h"

#include "MpStarCrypto.h"  // for RandomOracle-based commitments

#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

// Apply permutation π row-wise: out[i] = in[pi[i]]. Matches OSN
// init_wj_seeded semantics ("π routes element at position pi[i] to
// position i"). Operates on whole rows (each W blocks wide).
RowVec applyPiRows(const RowVec& in, const std::vector<int>& pi)
{
    if (in.size() != pi.size())
        throw std::runtime_error("applyPiRows: size mismatch");
    RowVec out(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        int s = pi[i];
        if (s < 0 || static_cast<size_t>(s) >= in.size())
            throw std::runtime_error("applyPiRows: pi out of range");
        out[i] = in[s];  // copy whole row
    }
    return out;
}

// Componentwise row-wise XOR: out[i][j] = a[i][j] ⊕ b[i][j].
RowVec xorRows(const RowVec& a, const RowVec& b)
{
    if (a.size() != b.size())
        throw std::runtime_error("xorRows: row count mismatch");
    RowVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].size() != b[i].size())
            throw std::runtime_error("xorRows: row width mismatch");
        out[i].resize(a[i].size());
        for (size_t j = 0; j < a[i].size(); ++j)
            out[i][j] = a[i][j] ^ b[i][j];
    }
    return out;
}

// Allocate an n × W RowVec.
RowVec makeRowVec(uint32_t n, uint32_t W)
{
    RowVec rv(n);
    for (auto& r : rv) r.resize(W);
    return rv;
}

// Assert that all rows of a RowVec have width W; throw with a diagnostic
// otherwise. Single-block bugs (W=1 vs W=k mismatch) are easy to
// introduce; this catches them at the boundary.
void requireWidth(const RowVec& rv, uint32_t W, const char* who)
{
    for (size_t i = 0; i < rv.size(); ++i) {
        if (rv[i].size() != W) {
            std::string msg = std::string(who) + ": row width mismatch at idx "
                              + std::to_string(i);
            throw std::runtime_error(msg);
        }
    }
}

uint32_t widthOf(const RowVec& rv, const char* who)
{
    if (rv.empty())
        throw std::runtime_error(std::string(who) + ": empty RowVec");
    return static_cast<uint32_t>(rv[0].size());
}

} // namespace

void cgpDealerGenerate(uint32_t n, uint32_t W,
                       oc::PRNG& prng,
                       CgpCorrelationA& outA,
                       CgpCorrelationB& outB)
{
    if (W == 0)
        throw std::runtime_error("cgpDealerGenerate: W must be >= 1");

    outA.a     = makeRowVec(n, W);
    outA.alpha = makeRowVec(n, W);
    outB.b     = makeRowVec(n, W);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < W; ++j) {
            outA.a[i][j] = prng.get<oc::block>();
            outB.b[i][j] = prng.get<oc::block>();
        }
    }

    // Generate uniform random permutation via Fisher-Yates.
    outB.pi.resize(n);
    std::iota(outB.pi.begin(), outB.pi.end(), 0);
    for (uint32_t i = n; i > 1; --i) {
        uint32_t j = prng.get<uint32_t>() % i;
        std::swap(outB.pi[i - 1], outB.pi[j]);
    }

    // α = π(a) ⊕ b row-wise. This is the CGP correlation invariant. In
    // the production OT-based preprocessing, A learns α without learning
    // π or b, and B learns π and b without learning a.
    auto pi_a = applyPiRows(outA.a, outB.pi);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < W; ++j) {
            outA.alpha[i][j] = pi_a[i][j] ^ outB.b[i][j];
        }
    }
}

void cgpOnlineA(const RowVec& x_A,
                const CgpCorrelationA& corrA,
                RowVec& outMessageToB,
                RowVec& outYa)
{
    const size_t n = x_A.size();
    if (corrA.a.size() != n || corrA.alpha.size() != n)
        throw std::runtime_error("cgpOnlineA: correlation size mismatch");
    if (n == 0) { outMessageToB.clear(); outYa.clear(); return; }
    const uint32_t W = static_cast<uint32_t>(x_A[0].size());
    requireWidth(x_A,       W, "cgpOnlineA(x_A)");
    requireWidth(corrA.a,   W, "cgpOnlineA(corrA.a)");
    requireWidth(corrA.alpha, W, "cgpOnlineA(corrA.alpha)");

    // m = x_A ⊕ a row-wise. Blinds A's input so B learns nothing about x_A
    // when it processes m.
    outMessageToB = xorRows(x_A, corrA.a);

    // A's output share is α.
    outYa = corrA.alpha;
}

void cgpOnlineB(const RowVec& x_B,
                const CgpCorrelationB& corrB,
                const RowVec& messageFromA,
                RowVec& outYb)
{
    const size_t n = x_B.size();
    if (corrB.pi.size() != n || corrB.b.size() != n)
        throw std::runtime_error("cgpOnlineB: correlation size mismatch");
    if (messageFromA.size() != n)
        throw std::runtime_error("cgpOnlineB: message size mismatch");
    if (n == 0) { outYb.clear(); return; }
    const uint32_t W = static_cast<uint32_t>(x_B[0].size());
    requireWidth(x_B,       W, "cgpOnlineB(x_B)");
    requireWidth(corrB.b,   W, "cgpOnlineB(corrB.b)");
    requireWidth(messageFromA, W, "cgpOnlineB(messageFromA)");

    // y_B = π(m ⊕ x_B) ⊕ b
    auto mb = xorRows(messageFromA, x_B);
    auto pi_mb = applyPiRows(mb, corrB.pi);
    outYb = xorRows(pi_mb, corrB.b);
}

CgpShuffleResult cgpRunInMemory(const RowVec& x_A,
                                const RowVec& x_B,
                                const CgpCorrelationA& corrA,
                                const CgpCorrelationB& corrB)
{
    CgpShuffleResult result;
    RowVec m;
    cgpOnlineA(x_A, corrA, m, result.y_A);
    cgpOnlineB(x_B, corrB, m, result.y_B);
    return result;
}

bool cgpCascadeRound(const CascadeStateCgp& incoming,
                     const CgpCorrelationA& corrA,
                     const CgpCorrelationB& corrB,
                     MaliciousMode mode,
                     CascadeStateCgp& out)
{
    const size_t n = incoming.spShare.size();
    if (incoming.peerShare.size() != n) { out = {}; return false; }
    if (corrA.a.size() != n || corrA.alpha.size() != n) { out = {}; return false; }
    if (corrB.pi.size() != n || corrB.b.size() != n) { out = {}; return false; }

    // Width is inferred from the first row of incoming.spShare. All other
    // inputs must agree on width — checked inside cgpOnlineA/B.
    RowVec m;
    cgpOnlineA(incoming.spShare,  corrA, m, out.spShare);
    cgpOnlineB(incoming.peerShare, corrB, m, out.peerShare);

    if (mode == MaliciousMode::Malicious) {
        // Verify the correlation invariant α = π(a) ⊕ b row-wise. In the
        // wire protocol this happens after A and B exchange commitments
        // (committed at preprocessing, opened post-online); failing the
        // check ⇒ abort with attribution.
        auto pi_a = applyPiRows(corrA.a, corrB.pi);
        const uint32_t W = pi_a.empty() ? 0 : widthOf(pi_a, "malicious check");
        for (size_t i = 0; i < n; ++i) {
            for (uint32_t j = 0; j < W; ++j) {
                oc::block expected = pi_a[i][j] ^ corrB.b[i][j];
                if (!(expected == corrA.alpha[i][j])) { out = {}; return false; }
            }
        }
    }
    return true;
}

RowVec cgpFinalReveal(const CascadeStateCgp& state)
{
    return xorRows(state.spShare, state.peerShare);
}

} // namespace mpstar
} // namespace volePSI
