#pragma once

// MPSVS Phase 2 — Server-aided blind DH-OPRF over ristretto255.
//
// Per docs/PROTOCOL.md Phase 2 + docs/PROTOCOL.md §2
// (ThresholdDKG) + §3 (DeriveEntityKey / DeriveRowTag).
//
// Cryptographic construction: 2-of-2 multiplicative case of JKK 2HashTDH /
// TOPPSS-class threshold DH-OPRF, evaluated as two sequential blind
// exponentiations with per-hop DLEQ verification.
//
// Group: ristretto255 (libsodium `crypto_core_ristretto255*`).
// H1(msg): hash-to-group via crypto_core_ristretto255_from_hash(SHA-512(msg)).
// H2(msg): SHA-256(msg) with mandatory 16-byte domain-separator prefix per
//          Rev 6 Notation.
// LP(x):   length-prefixed encoding (4-byte big-endian length ‖ bytes) —
//          Rev 7 R23 injectivity.
//
// This module provides IN-PROCESS 2-server simulator + real primitives. Real
// TCP wiring (S1↔S2, agency↔S1/S2) is a separate deployment step; the
// protocol messages defined here are agnostic to transport.
//
// Threat model this file targets:
//   * Semi-honest (Phase 2 baseline).
//   * Any coalition NOT containing both S1 and S2 (Protocol §0 non-collude).
//   * Metering: each server counts distinct-id OPRF queries per party per
//     epoch and refuses > Q̃_P (Protocol §3 QueryPad).

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ristretto255 element (32 bytes compressed).
using GroupElement = std::array<uint8_t, 32>;
// ristretto255 scalar (32 bytes little-endian mod q).
using Scalar       = std::array<uint8_t, 32>;
// SHA-256 digest.
using Hash256      = std::array<uint8_t, 32>;
// Entity key W = M^{k1 k2} (a group element).
using EntityKey    = GroupElement;
// Context bytes: (protocol_version ‖ epoch_id ‖ session_id ‖ nonce). Public.
using Context      = std::vector<uint8_t>;

// Fiat–Shamir domain prefix — 16 ASCII bytes, padded with '.'.
// Rev 6 Notation requires distinct prefix per H2 usage.
constexpr size_t kDomainPrefixBytes = 16;

// ---------------------------------------------------------------------------
// Length-prefix encoding (R23)
// ---------------------------------------------------------------------------

// LP(x) = 4-byte big-endian length ‖ bytes. Injective concatenation:
// distinct (a, b) never produce identical LP(a)‖LP(b) byte streams.
void appendLP(std::vector<uint8_t>& dst, const uint8_t* data, size_t len);
inline void appendLP(std::vector<uint8_t>& dst, const std::string& s) {
    appendLP(dst, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
inline void appendLP(std::vector<uint8_t>& dst, const std::vector<uint8_t>& v) {
    appendLP(dst, v.data(), v.size());
}
inline void appendLP(std::vector<uint8_t>& dst, const GroupElement& g) {
    appendLP(dst, g.data(), g.size());
}
// Fixed-width uint encoded big-endian (NOT length-prefixed — for canonical
// numeric fields like period).
void appendFixedWidthU32(std::vector<uint8_t>& dst, uint32_t v);
void appendFixedWidthU64(std::vector<uint8_t>& dst, uint64_t v);

// ---------------------------------------------------------------------------
// Ristretto255 helpers (thin libsodium wrappers)
// ---------------------------------------------------------------------------

void randomScalar(Scalar& out);
void scalarInvert(Scalar& out, const Scalar& in);
void scalarMultBase(GroupElement& out, const Scalar& s);      // g^s
void scalarMult(GroupElement& out, const Scalar& s, const GroupElement& p);  // p^s
void hashToGroup(GroupElement& out, const uint8_t* msg, size_t len);
void hashToGroup(GroupElement& out, const std::vector<uint8_t>& msg);
bool isValidPoint(const GroupElement& p);
GroupElement generatorBase();

// ---------------------------------------------------------------------------
// Fiat–Shamir hash-to-scalar (ctx-bound)
// ---------------------------------------------------------------------------

// hashToScalarCtx(prefix, ctx, transcript_bytes) → scalar mod q.
// Wraps SHA-512 → reduce mod ristretto255 scalar order (crypto_core_
// ristretto255_scalar_reduce over 64-byte hash).
Scalar hashToScalarCtx(const std::array<uint8_t, kDomainPrefixBytes>& prefix,
                       const Context& ctx,
                       const std::vector<uint8_t>& transcript);

// ---------------------------------------------------------------------------
// Schnorr proof of knowledge (ctx-bound Fiat–Shamir)
// ---------------------------------------------------------------------------

// π = SchnorrPoK_ctx { k : Y = g^k }.
// Represented as (c, s) where c is challenge, s = r + c·k (r = per-proof
// random nonce).
struct SchnorrProof {
    Scalar c;
    Scalar s;
};

SchnorrProof schnorrProve(const Scalar& k,
                          const GroupElement& Y,
                          const Context& ctx);
bool schnorrVerify(const GroupElement& Y,
                   const SchnorrProof& pi,
                   const Context& ctx);

// ---------------------------------------------------------------------------
// Chaum–Pedersen DLEQ proof (ctx-bound Fiat–Shamir)
// ---------------------------------------------------------------------------

// π = DLEQ_ctx { k : Y = g^k ∧ V = U^k }.
// Verifier already knows (g, Y, U, V). Represented as (c, s).
struct DLEQProof {
    Scalar c;
    Scalar s;
};

DLEQProof dleqProve(const Scalar& k,
                    const GroupElement& Y,
                    const GroupElement& U,
                    const GroupElement& V,
                    const Context& ctx);
bool dleqVerify(const GroupElement& Y,
                const GroupElement& U,
                const GroupElement& V,
                const DLEQProof& pi,
                const Context& ctx);

// ---------------------------------------------------------------------------
// Threshold DKG (Protocol §2, bias-frozen)
// ---------------------------------------------------------------------------

// Message S2 → S1 (commit only).
struct DkgCommit {
    Hash256 commit;   // SHA-256(Y2 ‖ π2)
};

// Message S1 → S2.
struct DkgHop1 {
    GroupElement Y1;
    SchnorrProof pi1;
};

// Message S2 → S1 (final).
struct DkgHop2Final {
    GroupElement Y2;      // opening of commit
    SchnorrProof pi2;     // opening of commit
    GroupElement Y;       // = Y1^k2
    DLEQProof    piY;     // DLEQ{k2 : Y2 = g^k2 ∧ Y = Y1^k2}
    // Commitment opening is (Y2, pi2) — the commit hash is DkgCommit.commit.
    // The verifier recomputes SHA-256(Y2 ‖ pi2) and checks equality.
};

// S1 keeps k1; S2 keeps k2. Both hold Y (public epoch key).
struct DkgS1State { Scalar k1; GroupElement Y; GroupElement Y1; GroupElement Y2; };
struct DkgS2State { Scalar k2; GroupElement Y; GroupElement Y1; GroupElement Y2; };

// S2 side of DKG. Call before receiving anything from S1.
// Returns commit to send to S1; populates internal state which is
// completed after receiving DkgHop1 via dkgS2Finalize.
struct DkgS2Prep {
    Scalar k2;
    GroupElement Y2;
    SchnorrProof pi2;
    DkgCommit commit;   // SHA-256(Y2 ‖ π2)
};
DkgS2Prep dkgS2Prepare(const Context& ctx);

// S1 side of DKG. Call after receiving DkgCommit from S2.
// Returns DkgHop1 to send to S2; populates DkgS1State (missing Y until finalization).
struct DkgS1Msg1 {
    GroupElement Y1;
    SchnorrProof pi1;
};
DkgS1Msg1 dkgS1SendHop1(const Context& ctx, Scalar& out_k1);

// S2 side, finalization. Called after receiving DkgHop1 from S1.
// Verifies pi1; computes Y and DLEQ; returns final message + updates state.
DkgHop2Final dkgS2Finalize(const Context& ctx,
                           const DkgS2Prep& prep,
                           const DkgHop1& hop1,
                           DkgS2State& out_state);

// S1 side, finalization. Called after receiving DkgHop2Final from S2.
// Verifies commit opening, pi2, piY. Populates DkgS1State.
bool dkgS1Finalize(const Context& ctx,
                   const DkgCommit& commit_received,
                   const Scalar& k1,
                   const GroupElement& Y1,
                   const DkgHop2Final& final_msg,
                   DkgS1State& out_state);

// ---------------------------------------------------------------------------
// OPRF messages (Protocol §3)
// ---------------------------------------------------------------------------

// Hop 1: P → S1 sends U; S1 → P sends (V1, DLEQ).
struct OprfHop1Response { GroupElement V1; DLEQProof dleq; };
// Hop 2: P → S2 sends V1; S2 → P sends (V2, DLEQ).
struct OprfHop2Response { GroupElement V2; DLEQProof dleq; };

// S1 side: given secret k1 and query U, produce V1 + DLEQ against Y1.
OprfHop1Response oprfServerHop1(const DkgS1State& s1, const GroupElement& U,
                                const Context& ctx);
// S2 side: given secret k2 and query V1, produce V2 + DLEQ against Y2.
OprfHop2Response oprfServerHop2(const DkgS2State& s2, const GroupElement& V1,
                                const Context& ctx);

// Party side: DeriveEntityKey — one distinct id per call.
// Returns the entity key W = M^{k1 k2} where M = H1(LP("REAL") ‖ LP(id_type) ‖ LP(x)).
// If any DLEQ fails, returns std::optional-empty via the OK flag; abort is
// data-independent per Rev 7 §3.
struct EntityKeyResult { EntityKey W; bool ok; };
EntityKeyResult deriveEntityKey(
    const std::string& id_type, const std::string& canonical_id,
    const Context& ctx,
    const GroupElement& Y1, const GroupElement& Y2, const GroupElement& Y,
    // Callbacks for the two-hop OPRF (in real deployment, these are TCP RPCs;
    // in tests, they're in-process function calls to S1/S2 processes).
    const std::function<OprfHop1Response(const GroupElement&)>& hop1_call,
    const std::function<OprfHop2Response(const GroupElement&)>& hop2_call);

// ---------------------------------------------------------------------------
// Tag derivation (Protocol §3 DeriveRowTag)
// ---------------------------------------------------------------------------

struct RowTag {
    // Full 256-bit tag; caller slices bin = t[0:β/8], key = t[β/8:(β+τ)/8].
    Hash256 t;
    // Convenience slice helpers:
    uint64_t bin(int beta_bits) const;         // low beta_bits of t interpreted big-endian
    std::vector<uint8_t> key(int beta_bits, int tau_bits) const;
};

// t = H2( LP("ALIGN|.........") ‖ LP(ctx) ‖ LP(id_type) ‖ LP(x) ‖ FixedWidth(p) ‖ LP(Ser(W)) )
RowTag deriveRowTag(const std::string& id_type, const std::string& canonical_id,
                    uint32_t period, const EntityKey& W, const Context& ctx);

// Dummy tag: key uniformly random; membership=0 externally (row constructed
// by caller). This does not go through the OPRF (Rev 7 §3).
RowTag dummyRowTag();

} // namespace mpsvs
} // namespace volePSI
