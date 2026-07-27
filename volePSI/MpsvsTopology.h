#pragma once

// MPSVS Phase 3 — Two-domain (S1+S2) topology, session state, and audit
// transcript for SectorVuln.
//
// Per docs/PROTOCOL.md Phase 3 + docs/PROTOCOL.md §0.
//
// Roles:
//   S1  — MPC compute node (GovTech-operated infra); holds one share of every
//         2-of-2 additive-shared value; runs Phase 2 OPRF server hop 1;
//         orchestrates OSN routing (later phases); never sees plaintext.
//   S2  — MPC compute node (independent operator, organisationally distinct
//         from GovTech); same role as S1, mirrored. {S1, S2} non-collusion.
//   GT  — GovTech workflow orchestrator; publishes ctx + policy Φ; verifies
//         software/version attestations; collects the disclosure-controlled
//         release at protocol end. NEVER holds any share, handle, payload,
//         or match status (per §2 spec constraint on GT).
//   MAS, DOS, MOM — client data-input parties. Each holds its own raw
//         payload; runs Phase 2 party-side OPRF; secret-shares its input
//         table across (S1, S2).
//
// This module provides the session context, role-scoped state, Beaver-bag
// generator (fresh per session; no reuse), and an SP-audit transcript
// accumulator used by later phases.
//
// Threat model this file targets: semi-honest, non-collusion between {S1, S2}.

#include "MpsvsOprf.h"
#include "MpBeaverTriple.h"
#include "MpSecretShare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

enum class Role : uint8_t {
    S1  = 0,
    S2  = 1,
    GT  = 2,
    MAS = 3,
    DOS = 4,
    MOM = 5,
};

inline const char* roleName(Role r) {
    switch (r) {
        case Role::S1:  return "S1";
        case Role::S2:  return "S2";
        case Role::GT:  return "GT";
        case Role::MAS: return "MAS";
        case Role::DOS: return "DOS";
        case Role::MOM: return "MOM";
    }
    return "?";
}

inline bool isClientRole(Role r) {
    return r == Role::MAS || r == Role::DOS || r == Role::MOM;
}

inline bool isServerRole(Role r) {
    return r == Role::S1 || r == Role::S2;
}

// ---------------------------------------------------------------------------
// Session identity + Φ policy summary (public metadata)
// ---------------------------------------------------------------------------

struct SessionId {
    // 128-bit session id (used as component of ctx)
    std::array<uint8_t, 16> bytes{};

    static SessionId random();
    std::string toHex() const;
};

struct PhiSummary {
    // Public policy parameters — required for ctx and audit.
    uint32_t protocol_version = 7;   // Rev 7
    uint32_t epoch_id         = 0;
    uint32_t beta             = 13;  // §9 provisional
    uint32_t tau              = 71;  // β+τ chosen per §9 collision bound
    uint32_t B                = 128; // Rev 7 R27 locked-in default
    bool     radix_enabled    = true; // Locked in at operational scale (B ≤ 128)
    uint32_t Q_tilde          = 0;   // OPRF query cap per party per epoch
    uint32_t cap_P            = 0;   // per-bin capacity
    uint32_t N_hat            = 0;   // union capacity = 2^β · Σ cap_P
    // ... other Φ fields (weights_ver, θ, DP regime, etc.) elided ...
};

// Assemble ctx bytes from public metadata.
Context makeContext(const PhiSummary& phi, const SessionId& sid,
                    const std::array<uint8_t, 16>& nonce);

// ---------------------------------------------------------------------------
// Per-role state (2-domain SectorVuln topology)
// ---------------------------------------------------------------------------

// S1 holds: k1 (DKG secret share), Y1/Y2/Y (public), Beaver bag one share.
struct S1State {
    DkgS1State dkg;                             // populated by DKG in Phase 2
    std::vector<mpstar::BeaverTripleU64> beaver_bag_view;  // this party's view
    // No client plaintext ever appears here.
};

// S2 holds: k2, Y1/Y2/Y, Beaver bag other share.
struct S2State {
    DkgS2State dkg;
    std::vector<mpstar::BeaverTripleU64> beaver_bag_view;
};

// GT holds: only public policy attestations + final disclosure-controlled
// release. No shares, no handles.
struct GtState {
    PhiSummary phi;
    SessionId  session;
    // Received attestations from each role (public software hashes, versions).
    // No secret material.
    struct Attestation { Role role; std::string software_hash; std::string schema_version; };
    std::vector<Attestation> attestations;
    // Final release payload (from Phase 12 output opening). Empty in Phase 3.
    std::vector<uint8_t> final_release;
};

// Client party state (MAS / DOS / MOM). Holds raw payloads + OPRF-derived
// entity keys. Never sees other clients' payloads.
struct ClientState {
    Role role = Role::MAS;
    // Raw local rows (Phase 1 prepared) — kept ONLY at the client.
    // For Phase 3 test, we track a small synthetic set.
    std::vector<std::string> raw_id_types;
    std::vector<std::string> raw_ids;
    // OPRF-derived entity keys, indexed by row.
    std::vector<EntityKey> entity_keys;
    // Row tags derived from entity keys.
    std::vector<RowTag> row_tags;
    // Metering: how many OPRF queries this client has made in this session.
    uint32_t oprf_queries_made = 0;
};

// ---------------------------------------------------------------------------
// Beaver bag — fresh per session, no reuse
// ---------------------------------------------------------------------------

// Wraps generateBeaverTriples; enforces "no reuse across sessions" by keying
// on session_id.

class BeaverBag {
public:
    // Generate `count` fresh triples for a given session. Errors if this
    // session_id has already been served (invariant: fresh triples per run).
    // Returns a pair-of-vectors — one view per server (S1 and S2 shares).
    struct Bag {
        std::vector<mpstar::BeaverTripleU64> s1_view;
        std::vector<mpstar::BeaverTripleU64> s2_view;
    };
    Bag generate(const SessionId& sid, size_t count, oc::PRNG& prng);

    // Query whether a session has been served. For invariant testing.
    bool sessionUsed(const SessionId& sid) const;

private:
    std::unordered_set<std::string> mUsedSessions;   // hex(session_id)
};

// ---------------------------------------------------------------------------
// SP audit transcript — accumulates the S1 (and S2) message log for §24 audit
// ---------------------------------------------------------------------------

// A transcript entry: role, event tag (public), byte payload (fixed shape).
// The transcript is designed so that reading it exhibits NO plaintext of any
// client id, payload, share, or entity-level intermediate. Only public
// metadata + protocol messages that are structurally masked (blinded OPRF
// queries, DLEQ proofs, opened Beaver differences) may appear.

class SpTranscript {
public:
    struct Entry {
        Role     role;
        std::string event;                 // ASCII tag, no secrets
        std::vector<uint8_t> payload;      // MUST be one of the whitelisted shapes below
    };

    // Append; caller MUST ensure payload is whitelisted (see §16 invariant).
    void append(Role r, std::string event, std::vector<uint8_t> payload);

    // Read-only view for audit.
    const std::vector<Entry>& entries() const { return mEntries; }
    size_t size() const { return mEntries.size(); }

    // Structural audit: verify no entry payload exceeds a public size class
    // (per §14′ fixed-shape leakage note). Returns false on any violation.
    bool auditFixedShape(const std::unordered_map<std::string, size_t>& class_max) const;

private:
    std::vector<Entry> mEntries;
};

// ---------------------------------------------------------------------------
// TopologySession — coordinator (in-process; TCP wiring in later phases)
// ---------------------------------------------------------------------------

// Owns the full state of a run: DKG, all party states, Beaver bag, transcript.
// Test/prototype use only — production splits these across processes.

class TopologySession {
public:
    TopologySession(const PhiSummary& phi, const SessionId& sid,
                    const std::array<uint8_t, 16>& nonce);

    // Runs DKG (Phase 2 §2) between S1 and S2. Populates dkg states.
    // Throws on failure.
    void runDkg();

    // Provision Beaver triples for this session (fresh, no reuse).
    void provisionBeaver(size_t count, oc::PRNG& prng);

    // Client-facing helper: given a client Role, drive the OPRF for one id.
    // Records queries against the client's meter; enforces Q̃ cap.
    // Updates client.entity_keys and client.row_tags.
    void clientDeriveKey(Role client_role, const std::string& id_type,
                         const std::string& canonical_id, uint32_t period);

    // Accessors
    const S1State&      s1()  const { return mS1; }
    const S2State&      s2()  const { return mS2; }
    const GtState&      gt()  const { return mGt; }
    ClientState&        client(Role r);
    const ClientState&  client(Role r) const;
    const SpTranscript& transcript() const { return mTranscript; }
    SpTranscript&       transcript()       { return mTranscript; }
    const Context&      ctx()  const { return mCtx; }
    const SessionId&    sid()  const { return mSid; }

private:
    PhiSummary   mPhi;
    SessionId    mSid;
    Context      mCtx;
    S1State      mS1;
    S2State      mS2;
    GtState      mGt;
    ClientState  mMas, mDos, mMom;
    BeaverBag    mBeaverBag;
    SpTranscript mTranscript;
    bool         mDkgDone = false;
};

// ---------------------------------------------------------------------------
// GT-blindness invariant helpers (structural check)
// ---------------------------------------------------------------------------

// Verify that GtState has no share, handle, or payload materialised.
// Returns "" if OK; a description of the violation otherwise.
std::string auditGtBlindness(const GtState& gt);

} // namespace mpsvs
} // namespace volePSI
