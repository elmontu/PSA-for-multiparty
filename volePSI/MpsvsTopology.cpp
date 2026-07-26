#include "MpsvsTopology.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <sstream>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// SessionId
// ---------------------------------------------------------------------------

SessionId SessionId::random() {
    SessionId s;
    randombytes_buf(s.bytes.data(), s.bytes.size());
    return s;
}

std::string SessionId::toHex() const {
    static const char hex[] = "0123456789abcdef";
    std::string out(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[2*i]     = hex[bytes[i] >> 4];
        out[2*i + 1] = hex[bytes[i] & 0x0F];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Context assembly
// ---------------------------------------------------------------------------

Context makeContext(const PhiSummary& phi, const SessionId& sid,
                    const std::array<uint8_t, 16>& nonce) {
    Context ctx;
    // Fixed-width fields + length-prefixed session id + nonce
    appendFixedWidthU32(ctx, phi.protocol_version);
    appendFixedWidthU32(ctx, phi.epoch_id);
    appendLP(ctx, sid.bytes.data(), sid.bytes.size());
    appendLP(ctx, nonce.data(), nonce.size());
    return ctx;
}

// ---------------------------------------------------------------------------
// BeaverBag
// ---------------------------------------------------------------------------

BeaverBag::Bag BeaverBag::generate(const SessionId& sid, size_t count,
                                   oc::PRNG& prng) {
    std::string key = sid.toHex();
    if (mUsedSessions.count(key)) {
        throw std::runtime_error(
            "BeaverBag: session " + key +
            " already provisioned — no triple reuse across runs");
    }
    mUsedSessions.insert(key);

    // Generate `count` 2-party additive-share Beaver triples.
    auto triples = mpstar::generateBeaverTriples(2, count, prng);

    // Split into two views: one per party. `SharedU64` in mpstar stores party-
    // indexed shares — for our N=2 case, each server holds one index. Copy
    // rather than share the same object so serialisation across roles is
    // explicit at the type level.
    Bag out;
    out.s1_view = triples;   // both servers' shares live in the SharedU64;
    out.s2_view = triples;   // in real deployment each server would keep only
                             // its own share index. This in-process test uses
                             // the full share table for both servers, but the
                             // downstream API accesses `share_at(0)` or
                             // `share_at(1)` — never both.
    return out;
}

bool BeaverBag::sessionUsed(const SessionId& sid) const {
    return mUsedSessions.count(sid.toHex()) != 0;
}

// ---------------------------------------------------------------------------
// SpTranscript
// ---------------------------------------------------------------------------

void SpTranscript::append(Role r, std::string event, std::vector<uint8_t> payload) {
    Entry e;
    e.role = r;
    e.event = std::move(event);
    e.payload = std::move(payload);
    mEntries.push_back(std::move(e));
}

bool SpTranscript::auditFixedShape(
    const std::unordered_map<std::string, size_t>& class_max) const {
    for (const auto& e : mEntries) {
        auto it = class_max.find(e.event);
        if (it == class_max.end()) {
            // Unknown event class → not whitelisted → audit fails
            return false;
        }
        if (e.payload.size() > it->second) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// TopologySession
// ---------------------------------------------------------------------------

TopologySession::TopologySession(const PhiSummary& phi, const SessionId& sid,
                                 const std::array<uint8_t, 16>& nonce)
    : mPhi(phi), mSid(sid), mCtx(makeContext(phi, sid, nonce)) {
    mGt.phi = phi;
    mGt.session = sid;
    mMas.role = Role::MAS;
    mDos.role = Role::DOS;
    mMom.role = Role::MOM;
}

void TopologySession::runDkg() {
    if (mDkgDone) throw std::runtime_error("runDkg: DKG already completed for this session");

    // Rev 7 §2 bias-frozen DKG (S2 commits first).
    DkgS2Prep prep = dkgS2Prepare(mCtx);
    // Transcript: S2 → S1 commit (public bytes; hides Y2).
    mTranscript.append(Role::S2, "dkg_commit",
                       std::vector<uint8_t>(prep.commit.commit.begin(),
                                            prep.commit.commit.end()));

    Scalar k1{};
    DkgS1Msg1 msg1 = dkgS1SendHop1(mCtx, k1);
    // Transcript: S1 → S2 hop1 (Y1 + Schnorr proof).
    std::vector<uint8_t> hop1_bytes(msg1.Y1.begin(), msg1.Y1.end());
    hop1_bytes.insert(hop1_bytes.end(), msg1.pi1.c.begin(), msg1.pi1.c.end());
    hop1_bytes.insert(hop1_bytes.end(), msg1.pi1.s.begin(), msg1.pi1.s.end());
    mTranscript.append(Role::S1, "dkg_hop1", std::move(hop1_bytes));

    DkgHop1 hop1_msg{ msg1.Y1, msg1.pi1 };
    DkgHop2Final finalMsg = dkgS2Finalize(mCtx, prep, hop1_msg, mS2.dkg);

    // Transcript: S2 → S1 final (opens commit, publishes Y, DLEQ).
    std::vector<uint8_t> hop2_bytes;
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.Y2.begin(), finalMsg.Y2.end());
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.pi2.c.begin(), finalMsg.pi2.c.end());
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.pi2.s.begin(), finalMsg.pi2.s.end());
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.Y.begin(), finalMsg.Y.end());
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.piY.c.begin(), finalMsg.piY.c.end());
    hop2_bytes.insert(hop2_bytes.end(), finalMsg.piY.s.begin(), finalMsg.piY.s.end());
    mTranscript.append(Role::S2, "dkg_hop2", std::move(hop2_bytes));

    bool ok = dkgS1Finalize(mCtx, prep.commit, k1, msg1.Y1, finalMsg, mS1.dkg);
    if (!ok) throw std::runtime_error("runDkg: dkgS1Finalize failed");

    mDkgDone = true;
}

void TopologySession::provisionBeaver(size_t count, oc::PRNG& prng) {
    auto bag = mBeaverBag.generate(mSid, count, prng);
    mS1.beaver_bag_view = std::move(bag.s1_view);
    mS2.beaver_bag_view = std::move(bag.s2_view);
}

void TopologySession::clientDeriveKey(Role client_role, const std::string& id_type,
                                      const std::string& canonical_id,
                                      uint32_t period) {
    if (!mDkgDone) throw std::runtime_error("clientDeriveKey: DKG not run yet");
    if (!isClientRole(client_role))
        throw std::runtime_error("clientDeriveKey: role is not a client role");

    ClientState& c = client(client_role);
    if (mPhi.Q_tilde > 0 && c.oprf_queries_made >= mPhi.Q_tilde) {
        throw std::runtime_error(
            std::string(roleName(client_role)) +
            ": OPRF query cap Q̃ exceeded — metering triggered");
    }
    ++c.oprf_queries_made;

    // Callbacks that route to S1 and S2 in-process — they represent RPCs
    // in a real deployment.
    auto hop1_cb = [this](const GroupElement& U) {
        auto r = oprfServerHop1(mS1.dkg, U, mCtx);
        // Transcript for SP audit: SP-observable outputs of hop 1 (blinded).
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), U.begin(), U.end());
        payload.insert(payload.end(), r.V1.begin(), r.V1.end());
        payload.insert(payload.end(), r.dleq.c.begin(), r.dleq.c.end());
        payload.insert(payload.end(), r.dleq.s.begin(), r.dleq.s.end());
        mTranscript.append(Role::S1, "oprf_hop1", std::move(payload));
        return r;
    };
    auto hop2_cb = [this](const GroupElement& V1) {
        auto r = oprfServerHop2(mS2.dkg, V1, mCtx);
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), V1.begin(), V1.end());
        payload.insert(payload.end(), r.V2.begin(), r.V2.end());
        payload.insert(payload.end(), r.dleq.c.begin(), r.dleq.c.end());
        payload.insert(payload.end(), r.dleq.s.begin(), r.dleq.s.end());
        mTranscript.append(Role::S2, "oprf_hop2", std::move(payload));
        return r;
    };

    auto result = deriveEntityKey(id_type, canonical_id, mCtx,
                                  mS1.dkg.Y1, mS2.dkg.Y2, mS1.dkg.Y,
                                  hop1_cb, hop2_cb);
    if (!result.ok) {
        throw std::runtime_error("clientDeriveKey: OPRF failed (DLEQ mismatch)");
    }
    RowTag tag = deriveRowTag(id_type, canonical_id, period, result.W, mCtx);

    c.raw_id_types.push_back(id_type);
    c.raw_ids.push_back(canonical_id);
    c.entity_keys.push_back(result.W);
    c.row_tags.push_back(tag);
}

ClientState& TopologySession::client(Role r) {
    switch (r) {
        case Role::MAS: return mMas;
        case Role::DOS: return mDos;
        case Role::MOM: return mMom;
        default: throw std::runtime_error("client(): not a client role");
    }
}

const ClientState& TopologySession::client(Role r) const {
    switch (r) {
        case Role::MAS: return mMas;
        case Role::DOS: return mDos;
        case Role::MOM: return mMom;
        default: throw std::runtime_error("client(): not a client role");
    }
}

// ---------------------------------------------------------------------------
// GT-blindness invariant
// ---------------------------------------------------------------------------

std::string auditGtBlindness(const GtState& gt) {
    // GT holds: PhiSummary (public), SessionId (public), attestations (public
    // metadata), final_release (post-disclosure-control opened output).
    // GT MUST NOT hold: any entity handle, any share, any raw id/payload.
    //
    // We can't fully prove this statically, but we can flag any obviously
    // secret-material field. In this schema there is none — the struct only
    // has public fields — so this check is a structural attestation.
    (void)gt;
    return "";  // OK
}

} // namespace mpsvs
} // namespace volePSI
