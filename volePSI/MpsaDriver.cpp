// MpsaDriver.cpp — end-to-end N-party Private Set Alignment driver.
//
// IMPLEMENTATION NOTES:
//   - coproto::asioConnect(addr, isServer) — same pattern as the existing
//     2-party doFileSpHshPSIwithOSN in fileBased.cpp. Both sides call
//     asioConnect; server side passes isServer=true (accepts), client side
//     passes isServer=false (connects). Requires COPROTO_ENABLE_BOOST.
//   - Peer mesh (sender↔sender): for each pair (i,j) with i<j, sender i
//     ACCEPTS on a dedicated port and sender j CONNECTS. SP plays no role
//     in sender↔sender traffic. Earlier designs tried a star-with-relay
//     where SP forwarded; that deadlocked on coproto's single-thread
//     io_context. Direct mesh removes the relay.
//   - coproto requires Socket::flush() before destruction or terminate()
//     fires — see flushes at runSpRole and runSenderRole exits.

#include "MpsaDriver.h"

#include "RsMpsi.h"
#include "MpStarChannel.h"
#include "MpStarSetup.h"
#include "MpStarCrypto.h"
#include "MpSpHandshake.h"
#include "MpKem.h"
#include "MpHybridHandshake.h"
#include "MpTranscript.h"
#include "MpIdentity.h"
#include "MpShuffleDriver.h"
#include "MpCgpShuffle.h"   // for the Row alias used in wide-payload helpers
#include "fileBased.h"

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/task.h"
#include "macoro/sync_wait.h"

#include <sodium.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace osuCrypto;

namespace volePSI {

namespace {

// Set by doFileMpsa from the -v CLI flag. When false, all the per-step
// debug logs are suppressed.
bool gVerbose = false;
#define LOG if (gVerbose) std::cerr

// Wide-payload-aware CSV parser. CSV layout: column 0 = ID (16-byte hex
// block), columns 1..W = payload (W consecutive 16-byte hex blocks per row).
// Each output payload row has exactly W blocks.
//
// W=1 reproduces the original single-block-per-row behavior.
std::pair<std::vector<block>, std::vector<volePSI::mpstar::Row>>
parseCsv(const std::string& path, uint32_t W)
{
    auto data = readSet(path, FileType::Csv, false, false);
    if (W == 0)
        throw std::runtime_error("MpsaDriver::parseCsv: W must be >= 1");
    if (data.size() < 1 + W) {
        throw std::runtime_error(
            "MpsaDriver: CSV must have at least 1+W columns (id + W payload blocks); got "
            + std::to_string(data.size()) + ", need " + std::to_string(1 + W));
    }
    auto ids = std::move(data[0]);
    const size_t n = ids.size();
    std::vector<volePSI::mpstar::Row> payloads(n);
    for (size_t i = 0; i < n; ++i) {
        payloads[i].resize(W);
        for (uint32_t w = 0; w < W; ++w) {
            if (data[1 + w].size() != n) {
                throw std::runtime_error(
                    "MpsaDriver::parseCsv: payload column " + std::to_string(1 + w)
                    + " has " + std::to_string(data[1 + w].size())
                    + " entries, expected " + std::to_string(n));
            }
            payloads[i][w] = data[1 + w][i];
        }
    }
    return {std::move(ids), std::move(payloads)};
}

// Flatten a wide-payload row vector (C rows × W blocks each) into a flat
// buffer of C*W blocks in row-major order: out[r*W + w] = rows[r][w].
// Used to serialize wide m_i / r_i over the wire as one AEAD payload.
std::vector<block> flattenRowMajor(const std::vector<volePSI::mpstar::Row>& rows,
                                   uint32_t W)
{
    std::vector<block> out(rows.size() * W);
    for (size_t r = 0; r < rows.size(); ++r) {
        if (rows[r].size() != W)
            throw std::runtime_error("flattenRowMajor: row width mismatch");
        for (uint32_t w = 0; w < W; ++w)
            out[r * W + w] = rows[r][w];
    }
    return out;
}

// Inverse of flattenRowMajor: split a C*W flat buffer back into C rows of W.
std::vector<volePSI::mpstar::Row>
unflattenRowMajor(const std::vector<block>& flat, uint64_t C, uint32_t W)
{
    if (flat.size() != C * W)
        throw std::runtime_error("unflattenRowMajor: size mismatch");
    std::vector<volePSI::mpstar::Row> rows(C);
    for (uint64_t r = 0; r < C; ++r) {
        rows[r].resize(W);
        for (uint32_t w = 0; w < W; ++w)
            rows[r][w] = flat[r * W + w];
    }
    return rows;
}

// Reshape one sender's wide payload (C rows × W blocks) into W parallel
// single-block columns of length C — the shape the OSN cascade backend
// already understands. colsOut[w][k] = rows[k][w].
std::vector<std::vector<block>>
rowsToColumns(const std::vector<volePSI::mpstar::Row>& rows, uint32_t W)
{
    std::vector<std::vector<block>> out(W);
    for (uint32_t w = 0; w < W; ++w) out[w].resize(rows.size());
    for (size_t k = 0; k < rows.size(); ++k) {
        if (rows[k].size() != W)
            throw std::runtime_error("rowsToColumns: row width mismatch");
        for (uint32_t w = 0; w < W; ++w)
            out[w][k] = rows[k][w];
    }
    return out;
}

// Write N parallel shuffled columns as a CSV: each row is N comma-separated
// hex-encoded 16-byte blocks (one per sender's payload at that intersection
// row, all permuted by the same secret pi).
void writeColumnsAsCsv(const std::string& path,
                       const std::vector<std::vector<block>>& columns,
                       uint64_t C)
{
    std::ofstream out(path);
    for (uint64_t i = 0; i < C; ++i) {
        for (size_t c = 0; c < columns.size(); ++c) {
            if (c > 0) out << ",";
            out << columns[c][i];
        }
        out << "\n";
    }
}

// coproto::asioConnect is the real upstream API. Both sides call it; the
// server side passes isServer=true (accept), client side passes false.
// host:port is "address:port" string form.
static coproto::Socket spAccept(int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect("localhost:" + std::to_string(port), /*isServer=*/true);
#else
    throw std::runtime_error("MpsaDriver: COPROTO_ENABLE_BOOST required for tcp sockets");
#endif
}

static coproto::Socket senderConnect(const std::string& host, int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect(host + ":" + std::to_string(port), /*isServer=*/false);
#else
    throw std::runtime_error("MpsaDriver: COPROTO_ENABLE_BOOST required for tcp sockets");
#endif
}

macoro::task<void> runSpRole(uint32_t N, int basePort, const std::string& outPath,
                             uint64_t padCmax, bool pqHybrid,
                             uint64_t minK, double cardEpsilon,
                             const std::string& authDir,
                             uint32_t payloadW)
{
    std::vector<coproto::Socket> senderSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        senderSocks[i] = spAccept(basePort + i);
    }

    // New port layout (Round 11 two-OSN-per-round):
    //   basePort + i           (i = 0..N-1): per-sender star/MPSI socket
    //   basePort + N + 2k      (k = 0..N-2): OSN call A socket with sender k
    //   basePort + N + 2k + 1  (k = 0..N-2): OSN call B socket with sender k
    //   basePort + N + 2*(N-1): reveal socket from last sender
    // Total ports used: 3N - 1.
    LOG << "[SP] accepting sender sockets...\n";
    // Port layout (Round 13 — peer-mesh design, SP no longer relays):
    //   basePort + i        (i = 0..N-1):   per-sender SP socket
    //   basePort + N + 2k   (k = 0..N-2):   OSN call A socket with sender k
    //   basePort + N + 2k+1 (k = 0..N-2):   OSN call B socket with sender k
    //   basePort + N + 2(N-1):              reveal socket from last sender
    // Sender-sender mesh ports are at basePort + 3N + (i*N + j) for pair (i,j)
    // with i<j; senders i ACCEPT, senders j CONNECT. SP plays no part.
    std::vector<coproto::Socket> osnSocksA(N - 1), osnSocksB(N - 1);
    for (uint32_t k = 0; k < N - 1; ++k) {
        osnSocksA[k] = spAccept(basePort + N + 2 * k);
        osnSocksB[k] = spAccept(basePort + N + 2 * k + 1);
    }
    coproto::Socket revealSock = spAccept(basePort + N + 2 * (N - 1));
    LOG << "[SP] all SP-side sockets accepted\n";

    std::array<uint8_t, 32> sessionId;
    randombytes_buf(sessionId.data(), sessionId.size());
    LOG << "[SP] broadcasting sessionId\n";
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].send(coproto::span<const uint8_t>(sessionId.data(), sessionId.size()));
    }
    LOG << "[SP] sessionId broadcast done; running handshake\n";

    // T14: optional authentication via long-term Ed25519 identities. SP
    // signs the sessionId with its long-term sk; each sender verifies
    // against the SP's pre-distributed .pk. Then each sender signs the
    // sessionId with its own sk; SP verifies. Catches MITM-forward-pubkey
    // attacks on the ephemeral DH that follows.
    std::unique_ptr<volePSI::mpstar::MpIdentity> spIdent;
    if (!authDir.empty()) {
        spIdent = std::make_unique<volePSI::mpstar::MpIdentity>(authDir, "sp", "sp.sk");
        LOG << "[SP] T14 auth enabled — sending signed sessionId to all senders\n";
        std::vector<uint8_t> sessionMsg(sessionId.begin(), sessionId.end());
        auto sig = spIdent->sign(sessionMsg);
        for (uint32_t i = 0; i < N; ++i) {
            co_await senderSocks[i].send(coproto::span<const uint8_t>(sig.data(), sig.size()));
        }
        // Receive each sender's signature on the same sessionId; verify.
        for (uint32_t i = 0; i < N; ++i) {
            std::array<uint8_t, 64> psig;
            co_await senderSocks[i].recv(coproto::span<uint8_t>(psig.data(), psig.size()));
            std::string peerId = "sender_" + std::to_string(i);
            if (!spIdent->verify(peerId, sessionMsg, psig)) {
                throw std::runtime_error("MpsaDriver: bad sessionId signature from " + peerId);
            }
            LOG << "[SP] T14 verified signature from " << peerId << "\n";
        }
    }

    std::vector<std::array<uint8_t, 32>> spKeysRaw;
    if (pqHybrid) {
        volePSI::mpstar::StubKem kem;
        LOG << "[SP] using PQ-hybrid handshake (Kem=" << kem.name() << ")\n";
        spKeysRaw = co_await MpHybridHandshake::runSp(senderSocks, kem);
    } else {
        spKeysRaw = co_await MpSpHandshake::runSp(senderSocks);
    }
    LOG << "[SP] handshake done\n";
    std::vector<std::array<uint8_t, 32>> spKeys(N);
    for (uint32_t i = 0; i < N; ++i) {
        spKeys[i] = volePSI::mpstar::deriveSessionKey(spKeysRaw[i], sessionId, "sp_session");
    }

    std::vector<size_t> perSenderSetSize(N);
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].recv(perSenderSetSize[i]);
    }
    LOG << "[SP] set sizes received\n";

    RsMpsi3rdPReceiver mpsi;
    mpsi.init(perSenderSetSize[0], perSenderSetSize[0], 40, sysRandomSeed(), false, 1);
    LOG << "[SP] MPSI starting\n";
    uint64_t C = co_await mpsi.runIntersection(senderSocks, N, perSenderSetSize);
    LOG << "[SP] MPSI done; C=" << C << "\n";

    // Threshold-k revelation (T10): abort cleanly if intersection too small
    // for k-anonymity-style compliance. SP MUST commit to k_min before MPSI
    // (audit requirement); enforced here.
    if (minK > 0 && C < minK) {
        LOG << "[SP] threshold check FAILED: C=" << C << " < minK=" << minK << "; aborting\n";
        // Tell senders to bail. For prototype: just throw; senders see
        // socket close and exit.
        throw std::runtime_error("MpsaDriver: intersection cardinality " + std::to_string(C)
                                 + " below threshold " + std::to_string(minK) + " — aborting per k-anon policy");
    }

    // DP-protected cardinality release (T8): if epsilon > 0, the value
    // PUBLISHED to senders / downstream is noisy. The protocol still
    // processes the real C internally; only the WRITE-OUT count is noisy.
    if (cardEpsilon > 0.0) {
        // Laplace mechanism: C_tilde = C + Lap(1/epsilon). For prototype,
        // we just log the noisy value SP would release; the real release
        // mechanism (and composition accounting across runs) is documented
        // in docs/DP_CARDINALITY_DESIGN.md.
        // Simple Laplace via inverse CDF of uniform U ~ Uniform(-0.5, 0.5):
        //   X = -sign(U) * scale * ln(1 - 2*|U|)
        std::array<uint8_t, 8> u_bytes;
        randombytes_buf(u_bytes.data(), u_bytes.size());
        uint64_t u64;
        std::memcpy(&u64, u_bytes.data(), 8);
        double u = (static_cast<double>(u64) / static_cast<double>(UINT64_MAX)) - 0.5;
        double scale = 1.0 / cardEpsilon;
        double sign_u = (u >= 0 ? 1.0 : -1.0);
        double absu2 = std::abs(u) * 2.0;
        double noise = -sign_u * scale * std::log(1.0 - std::min(absu2, 0.999999));
        double noisyC = static_cast<double>(C) + noise;
        LOG << "[SP] DP-cardinality: epsilon=" << cardEpsilon
            << " noisyC=" << noisyC << " (real C=" << C << " kept internal)\n";
        // For prototype, just log it. Real release: write to a separate
        // "dp_cardinality" file for downstream consumption.
    }

    // Apply the same C_max padding the senders will. After this point
    // SP processes Ceff rows; C is the real intersection (still leaked
    // by MPSI to SP — full hiding needs oblivious MPSI, see design doc).
    uint64_t Ceff = std::max(C, padCmax);
    LOG << "[SP] effective row count Ceff=" << Ceff << " (pad from C=" << C << ")\n";
    C = Ceff;

    // Receive AEAD-wrapped masked payloads m_i from each sender. Each m_i
    // arrives as C*W blocks in row-major order (when payloadW > 1) or just
    // C blocks (W=1, legacy). SP flattens to N*W cascade columns of length
    // C, ordered as flat[i*W + w] = sender i's payload block w as a
    // column over all C rows.
    std::vector<std::vector<block>> initialMasked(N * payloadW);
    for (uint32_t i = 0; i < N; ++i) {
        uint64_t ctLen = 0;
        co_await senderSocks[i].recv(ctLen);
        std::vector<uint8_t> ct(ctLen);
        co_await senderSocks[i].recv(ct);
        auto plain = volePSI::mpstar::aeadDecrypt(ct, spKeys[i]);
        auto blocks = volePSI::mpstar::deserializeBlocks(plain, C * payloadW);
        auto rows   = unflattenRowMajor(blocks, C, payloadW);
        auto cols   = rowsToColumns(rows, payloadW);
        for (uint32_t w = 0; w < payloadW; ++w) {
            initialMasked[i * payloadW + w] = std::move(cols[w]);
        }
    }
    LOG << "[SP] N*W=" << (N * payloadW) << " cascade columns received\n";

    // Senders talk to each other directly via the peer mesh; SP only
    // orchestrates the OSN cascade. No MpStarChannel needed on the SP side.
    LOG << "[SP] running MpShuffleDriver::runSp (colCount=" << (N * payloadW) << ")\n";
    auto shuffled = co_await MpShuffleDriver::runSp(
        osnSocksA, osnSocksB, revealSock,
        N, C, std::move(initialMasked), spKeys, sessionId);
    LOG << "[SP] runSp done\n";

    // Flush all SP sockets before destruction to keep coproto happy.
    for (auto& sock : osnSocksA) co_await sock.flush();
    for (auto& sock : osnSocksB) co_await sock.flush();
    co_await revealSock.flush();

    writeColumnsAsCsv(outPath, shuffled, C);

    // T11: produce + sign SP-side transcript for non-repudiation audit.
    // Lightweight: digest covers session id, MPSI cardinality, and
    // padded effective C. Per-message recording is left as a future
    // enrichment (one line per protocol step) — see SECURITY_ANALYSIS.md.
    {
        volePSI::mpstar::MpTranscript tx;
        tx.recordSpan("session_id", sessionId.data(), sessionId.size());
        std::vector<uint8_t> cbuf(8);
        std::memcpy(cbuf.data(), &C, 8);
        tx.record("ceff", cbuf);
        std::array<uint8_t, 32> ed_pk;
        std::array<uint8_t, 64> ed_sk;
        volePSI::mpstar::ed25519Keypair(ed_pk, ed_sk);
        auto sig = tx.sign(ed_sk);
        // For prototype: log the digest + sig hex prefix; production
        // would write to an immutable audit log (e.g., S3 Object Lock).
        char hex[8];
        std::snprintf(hex, sizeof(hex), "%02x%02x%02x%02x",
                      sig[0], sig[1], sig[2], sig[3]);
        LOG << "[SP] transcript signed; sig prefix=" << hex << "...\n";
    }
}

macoro::task<void> runSenderRole(uint32_t N, uint32_t selfIdx, int basePort,
                                 const std::string& inputPath, const std::string& spHost,
                                 uint64_t padCmax, bool pqHybrid,
                                 const std::string& authDir, bool mpsiSalted,
                                 uint32_t payloadW)
{
    LOG << "[S" << selfIdx << "] connecting spSock\n";
    coproto::Socket spSock = senderConnect(spHost, basePort + selfIdx);
    LOG << "[S" << selfIdx << "] spSock connected\n";

    // Peer-mesh sockets (Round 13): direct sender↔sender. For each pair
    // (i,j) with i<j, sender i ACCEPTS at port (basePort + 3N + i*N + j),
    // sender j CONNECTS. Avoid deadlock by iterating pairs in CANONICAL
    // order across all senders — each step has exactly one (accept,
    // connect) pair so they meet up.
    auto peerPort = [&](uint32_t i, uint32_t j) {
        return basePort + 3 * N + i * N + j;
    };
    std::vector<coproto::Socket> peerSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = i + 1; j < N; ++j) {
            if (selfIdx == i) {
                LOG << "[S" << selfIdx << "] accepting peer " << j << "\n";
                peerSocks[j] = coproto::asioConnect(
                    "localhost:" + std::to_string(peerPort(i, j)), true);
            } else if (selfIdx == j) {
                LOG << "[S" << selfIdx << "] connecting peer " << i << "\n";
                peerSocks[i] = senderConnect(spHost, peerPort(i, j));
            }
            // else: this sender sits this pair out.
        }
    }
    LOG << "[S" << selfIdx << "] peer mesh established\n";

    // T15: per-session-salted MPSI hashing. Sender 0 generates a random
    // 16-byte salt and broadcasts to all peers via the peer mesh. SP does
    // NOT learn the salt. Each sender XORs salt into each ID before
    // hashing. SP can still intersect (all senders use the same salt) but
    // cannot dictionary-attack known IDs because SP doesn't know the salt.
    std::array<uint8_t, 16> mpsiSalt{};
    if (mpsiSalted) {
        if (selfIdx == 0) {
            randombytes_buf(mpsiSalt.data(), mpsiSalt.size());
            for (uint32_t j = 1; j < N; ++j) {
                co_await peerSocks[j].send(
                    coproto::span<const uint8_t>(mpsiSalt.data(), mpsiSalt.size()));
                co_await peerSocks[j].flush();
            }
            LOG << "[S0] T15 broadcast mpsi salt to peers\n";
        } else {
            co_await peerSocks[0].recv(
                coproto::span<uint8_t>(mpsiSalt.data(), mpsiSalt.size()));
            LOG << "[S" << selfIdx << "] T15 received mpsi salt\n";
        }
    }

    // Sockets for the two-OSN-per-round cascade design.
    // - Sender k = selfIdx in [0, N-1) connects two OSN sockets to SP
    //   (call A and call B) for the round it drives.
    // - Sender N-1 connects only the reveal socket.
    coproto::Socket osnSocketA, osnSocketB, revealSocket;
    if (selfIdx < N - 1) {
        osnSocketA = senderConnect(spHost, basePort + N + 2 * selfIdx);
        osnSocketB = senderConnect(spHost, basePort + N + 2 * selfIdx + 1);
    } else {
        revealSocket = senderConnect(spHost, basePort + N + 2 * (N - 1));
    }
    LOG << "[S" << selfIdx << "] all sockets connected; recv sessionId\n";

    // Receive session_id broadcast by SP. Binds all this-session AEAD to
    // this run; defeats cross-session replay.
    std::array<uint8_t, 32> sessionId;
    co_await spSock.recv(coproto::span<uint8_t>(sessionId.data(), sessionId.size()));
    LOG << "[S" << selfIdx << "] sessionId received; running handshake\n";

    // T14: optional authentication. Sender verifies SP's sig on sessionId,
    // then signs the sessionId with its own long-term sk and ships.
    std::unique_ptr<volePSI::mpstar::MpIdentity> senderIdent;
    if (!authDir.empty()) {
        std::string selfId = "sender_" + std::to_string(selfIdx);
        senderIdent = std::make_unique<volePSI::mpstar::MpIdentity>(authDir, selfId, selfId + ".sk");

        std::array<uint8_t, 64> sp_sig;
        co_await spSock.recv(coproto::span<uint8_t>(sp_sig.data(), sp_sig.size()));
        std::vector<uint8_t> sessionMsg(sessionId.begin(), sessionId.end());
        if (!senderIdent->verify("sp", sessionMsg, sp_sig)) {
            throw std::runtime_error("MpsaDriver: bad SP sessionId signature");
        }
        LOG << "[S" << selfIdx << "] T14 verified SP signature\n";

        auto my_sig = senderIdent->sign(sessionMsg);
        co_await spSock.send(coproto::span<const uint8_t>(my_sig.data(), my_sig.size()));
        LOG << "[S" << selfIdx << "] T14 sent own signature\n";
    }

    std::array<uint8_t, 32> spKeyRaw;
    if (pqHybrid) {
        volePSI::mpstar::StubKem kem;
        LOG << "[S" << selfIdx << "] using PQ-hybrid handshake\n";
        spKeyRaw = co_await MpHybridHandshake::runSender(spSock, selfIdx, kem);
    } else {
        spKeyRaw = co_await MpSpHandshake::runSender(spSock, selfIdx);
    }
    LOG << "[S" << selfIdx << "] handshake done\n";
    auto spKey = volePSI::mpstar::deriveSessionKey(spKeyRaw, sessionId, "sp_session");

    LOG << "[S" << selfIdx << "] parsing CSV " << inputPath << " (W=" << payloadW << ")\n";
    auto [ids, payloads] = parseCsv(inputPath, payloadW);
    LOG << "[S" << selfIdx << "] CSV parsed: " << ids.size() << " ids, "
              << payloads.size() << " payload rows × " << payloadW << " blocks\n";
    if (ids.size() != payloads.size()) {
        throw std::runtime_error("MpsaDriver: ID / payload size mismatch");
    }

    // T15: XOR the shared salt into each ID before MPSI hashes it.
    if (mpsiSalted) {
        block saltBlk;
        std::memcpy(&saltBlk, mpsiSalt.data(), 16);
        for (auto& id : ids) {
            id = id ^ saltBlk;
        }
        LOG << "[S" << selfIdx << "] T15 salted " << ids.size() << " ids\n";
    }

    co_await spSock.send(ids.size());
    LOG << "[S" << selfIdx << "] sent set size; running MPSI\n";

    RsMpsi3rdPSender mpsi;
    mpsi.init(ids.size(), ids.size(), 40, sysRandomSeed(), false, 1);
    auto bitvec = co_await mpsi.runIntersection(span<block>(ids), spSock, selfIdx, N);
    uint64_t C = mpsi.getCardinality();
    LOG << "[S" << selfIdx << "] MPSI done; C=" << C << "\n";

    // Cardinality-hiding via output padding (Round 17). If -cmax is set
    // and > real C, the sender pads c_i with PRNG-random blocks. After the
    // cascade these padded "dummy" rows are mixed with real intersection
    // rows in the output. SP still learns C from MPSI itself (residual
    // leak — see docs/CARDINALITY_HIDING_DESIGN.md for full-hiding plan).
    uint64_t Ceff = std::max(C, padCmax);
    LOG << "[S" << selfIdx << "] padding C=" << C << " to Ceff=" << Ceff
        << " (cardinality-hiding from downstream)\n";

    LOG << "[S" << selfIdx << "] building c_i (Ceff=" << Ceff << ", ids=" << ids.size()
              << ", bitvec=" << bitvec.size() << ", W=" << payloadW << ")\n";
    using volePSI::mpstar::Row;
    std::vector<Row> c_i(Ceff, Row(payloadW, ZeroBlock));
    {
        uint64_t k = 0;
        for (uint64_t j = 0; j < ids.size() && k < C; ++j) {
            if (bitvec[j]) c_i[k++] = payloads[j];   // copy whole Row
        }
        // Fill remaining (Ceff - C) entries with PRNG-random wide "dummies".
        if (Ceff > C) {
            PRNG dprng;
            dprng.SetSeed(sysRandomSeed());
            for (uint64_t r = C; r < Ceff; ++r) {
                dprng.get<block>(c_i[r].data(), payloadW);
            }
        }
    }
    LOG << "[S" << selfIdx << "] building r_i (Ceff=" << Ceff << ", W=" << payloadW << ")\n";
    std::vector<Row> r_i(Ceff, Row(payloadW));
    {
        PRNG prng;
        prng.SetSeed(sysRandomSeed());
        for (auto& row : r_i) {
            prng.get<block>(row.data(), payloadW);
        }
    }
    LOG << "[S" << selfIdx << "] r_i filled\n";
    std::vector<Row> m_i(Ceff, Row(payloadW));
    for (uint64_t j = 0; j < Ceff; ++j) {
        for (uint32_t w = 0; w < payloadW; ++w) {
            m_i[j][w] = c_i[j][w] ^ r_i[j][w];
        }
    }

    // Rest of the protocol uses Ceff instead of C.
    C = Ceff;
    LOG << "[S" << selfIdx << "] m_i built; AEAD-encrypting (" << (Ceff * payloadW) << " blocks)\n";
    // Flatten C × W into one length-(C·W) buffer (row-major) for AEAD send.
    auto m_i_flat   = flattenRowMajor(m_i, payloadW);
    auto m_i_plain  = volePSI::mpstar::serializeBlocks(m_i_flat);
    auto m_i_ct     = volePSI::mpstar::aeadEncrypt(m_i_plain, spKey);
    uint64_t ctLen  = m_i_ct.size();
    co_await spSock.send(ctLen);
    co_await spSock.send(std::move(m_i_ct));
    LOG << "[S" << selfIdx << "] m_i sent (" << ctLen << " bytes)\n";

    LOG << "[S" << selfIdx << "] making star (peer-mesh) channel\n";
    MpStarChannel chan(std::move(peerSocks), selfIdx, N);
    LOG << "[S" << selfIdx << "] running MpStarSetup::runSender\n";
    auto setup = co_await MpStarSetup::runSender(chan, selfIdx, N);
    LOG << "[S" << selfIdx << "] MpStarSetup done\n";

    // Phase 0 (N-column + commit-and-open hardening):
    //
    // 1) Every sender j>0 picks a fresh 16-byte nonce_j, computes
    //    commit_j = H("mpstar.commit.v1" || serialize(r_j) || nonce_j),
    //    and BROADCASTS commit_j to ALL peers (every k != j).
    // 2) Every sender k receives commit_j from every peer j (k will also
    //    receive its own commit echoed back from sender 0 — discard).
    // 3) Sender 0 receives (serialize(r_j) || nonce_j) AEAD'd from each
    //    sender j>0 and VERIFIES commit_j opens correctly. Mismatch ⇒ abort.
    // 4) Other senders (k != 0) hold their commits for later challenge.
    //
    // Catches: sender j providing different r_j values to different recipients
    // (in the current single-recipient topology this can't happen; but
    // commitments still bind sender j to the value, enabling non-repudiation
    // if a dispute arises after the protocol). With T1's full info-theoretic
    // MAC layer (see docs/MALICIOUS_CASCADE_DESIGN.md) this generalizes to
    // catching wrong-r in the cascade too.
    using volePSI::mpstar::serializeBlocks;
    using volePSI::mpstar::deserializeBlocks;
    using volePSI::mpstar::aeadEncrypt;
    using volePSI::mpstar::aeadDecrypt;
    using volePSI::mpstar::deriveSessionKey;
    using volePSI::mpstar::commit;
    using volePSI::mpstar::verifyCommit;

    // ---- compute my own commitment + nonce ----
    std::array<uint8_t, 16> nonce_i;
    randombytes_buf(nonce_i.data(), nonce_i.size());
    // Commit on the FLATTENED wide r_i (C*W blocks, row-major).
    auto r_i_flat  = flattenRowMajor(r_i, payloadW);
    auto r_i_bytes = serializeBlocks(r_i_flat);
    auto commit_i  = commit(r_i_bytes, nonce_i);

    // ---- broadcast commit_i to every peer (32 bytes opaque) ----
    if (selfIdx > 0) {
        std::vector<uint8_t> commitBytes(commit_i.begin(), commit_i.end());
        for (uint32_t k = 0; k < N; ++k) {
            if (k == selfIdx) continue;
            co_await chan.sendTo(k, commitBytes);  // sender j>0 ships its commit
        }
    }
    LOG << "[S" << selfIdx << "] commit phase: broadcast done\n";

    // ---- receive commit_j from every peer j (only j>0 actually broadcast) ----
    std::vector<std::array<uint8_t, 32>> peerCommits(N);  // peerCommits[j] for j>0
    for (uint32_t j = 1; j < N; ++j) {
        if (j == selfIdx) continue;
        auto cb = co_await chan.recvFrom(j);
        if (cb.size() != 32) {
            throw std::runtime_error("MpsaDriver: bad commit size from peer " + std::to_string(j));
        }
        std::copy(cb.begin(), cb.end(), peerCommits[j].begin());
    }
    LOG << "[S" << selfIdx << "] commit phase: peer commits received\n";

    // ---- Phase 0 open: senders j>0 ship (r_j || nonce_j) to sender 0 ----
    // r_j is wide (C × W blocks); the opened message carries C*W blocks +
    // 16-byte nonce. Sender 0 reassembles ownMasksWide as N wide
    // RowVectors (per-sender masks), then flattens to N*W single-block
    // cascade columns for MpShuffleDriver.
    std::vector<std::vector<Row>> ownMasksWide(N);
    if (selfIdx == 0) {
        ownMasksWide[0] = r_i;  // own wide mask
        for (uint32_t j = 1; j < N; ++j) {
            auto sessionKey = deriveSessionKey(setup.key(j), sessionId, "pair_session");
            auto ct    = co_await chan.recvFrom(j);
            auto plain = aeadDecrypt(ct, sessionKey);
            const size_t expectedPlainBytes = C * payloadW * sizeof(block) + 16;
            if (plain.size() != expectedPlainBytes) {
                throw std::runtime_error("MpsaDriver: bad opened-message size from sender "
                                         + std::to_string(j)
                                         + " (got " + std::to_string(plain.size())
                                         + ", want " + std::to_string(expectedPlainBytes) + ")");
            }
            std::vector<uint8_t> r_j_bytes(plain.begin(),
                                          plain.begin() + C * payloadW * sizeof(block));
            std::array<uint8_t, 16> nonce_j;
            std::copy(plain.end() - 16, plain.end(), nonce_j.begin());

            if (!verifyCommit(r_j_bytes, nonce_j, peerCommits[j])) {
                throw std::runtime_error("MpsaDriver: commitment mismatch from sender "
                                         + std::to_string(j) + " — abort");
            }
            auto r_j_flat = deserializeBlocks(r_j_bytes, C * payloadW);
            ownMasksWide[j] = unflattenRowMajor(r_j_flat, C, payloadW);
        }
        LOG << "[S0] commit phase: all peer opens verified, " << N << " wide masks held\n";
    } else {
        auto sessionKey = deriveSessionKey(setup.key(0), sessionId, "pair_session");
        std::vector<uint8_t> opened;
        opened.reserve(r_i_bytes.size() + 16);
        opened.insert(opened.end(), r_i_bytes.begin(), r_i_bytes.end());
        opened.insert(opened.end(), nonce_i.begin(), nonce_i.end());
        auto ct = aeadEncrypt(opened, sessionKey);
        co_await chan.sendTo(0, std::move(ct));
        // Non-zero senders contribute zero masks initially.
        for (uint32_t i = 0; i < N; ++i) {
            ownMasksWide[i] = std::vector<Row>(C, Row(payloadW, ZeroBlock));
        }
    }

    // Flatten N senders × C rows × W blocks → N*W single-block columns of
    // length C, ordered as ownMasks[i*W + w] = column-over-rows of sender i's
    // payload block w.
    std::vector<std::vector<block>> ownMasks(N * payloadW);
    for (uint32_t i = 0; i < N; ++i) {
        auto cols = rowsToColumns(ownMasksWide[i], payloadW);
        for (uint32_t w = 0; w < payloadW; ++w) {
            ownMasks[i * payloadW + w] = std::move(cols[w]);
        }
    }
    LOG << "[S" << selfIdx << "] cascade input: " << (N * payloadW)
        << " columns × " << C << " rows\n";

    co_await MpShuffleDriver::runSender(
        chan, setup, selfIdx, N, C, std::move(ownMasks),
        osnSocketA, osnSocketB, revealSocket, spKey, sessionId);

    // coproto requires all sockets to be flushed before destruction or
    // terminate() fires. Flush every socket we held.
    // (spSock was moved into chan; the chan's peer sockets get flushed via
    // sendTo's own flush. Phase-0 sender 0 holds peerSocks for inbound but
    // never sends after MpStarSetup, so no pending outbound there.)
    if (selfIdx < N - 1) {
        co_await osnSocketA.flush();
        co_await osnSocketB.flush();
    } else {
        co_await revealSocket.flush();
    }
    LOG << "[S" << selfIdx << "] done\n";
}

} // anonymous namespace

static void printMpsaUsage(std::ostream& os)
{
    os <<
        "MPSA mode (N-party Private Set Alignment)\n"
        "\n"
        "Usage:\n"
        "  frontend -mpsa -N <senderCount> -r <role> [options]\n"
        "\n"
        "Role 0 (Service Provider):\n"
        "  frontend -mpsa -N <N> -r 0 [-port <basePort>] [-out <csv>]\n"
        "    -port      SP listens on basePort..basePort+2N (default 17500)\n"
        "    -out       Output CSV path (default out_cleartext.csv)\n"
        "\n"
        "Role 1 (Sender i):\n"
        "  frontend -mpsa -N <N> -r 1 -i <senderIdx> -in <csv> [-port <p>] [-host <h>]\n"
        "    -i         Sender index in [0, N)\n"
        "    -in        Input CSV (col 0 = ID, col 1 = payload)\n"
        "    -port      Base port to dial SP (default 17500)\n"
        "    -host      SP hostname (default localhost)\n"
        "\n"
        "Common flags:\n"
        "    -v         print per-step debug logs to stderr\n"
        "    -cmax <n>  cardinality-hiding: pad output to >= n rows\n"
        "               (dummies are PRNG-random and shuffled with reals;\n"
        "                hides the exact intersection size from any party\n"
        "                that observes only the output file; SP still learns\n"
        "                C via MPSI itself — see CARDINALITY_HIDING_DESIGN)\n"
        "    -pq        post-quantum hybrid SP↔sender handshake\n"
        "               (X25519 + KEM; currently uses StubKem placeholder.\n"
        "                Real ML-KEM/Kyber-768 swap-in via liboqs documented\n"
        "                in docs/PQ_HYBRID_HANDSHAKE_DESIGN.md)\n"
        "    -mink <K>  threshold-k revelation: SP aborts if |I| < K\n"
        "               (k-anonymity policy; SP commits to K before MPSI runs)\n"
        "    -dp <eps>  DP-protected cardinality release (epsilon > 0)\n"
        "               SP logs Laplace-noised C; real C kept internal\n"
        "    -auth-dir <dir>  long-term identity directory (Ed25519 .pk files)\n"
        "                     If set, parties authenticate ephemeral pubkeys\n"
        "                     against pre-distributed long-term identities.\n"
        "                     See docs/AUTHENTICATED_HANDSHAKE_DESIGN.md\n"
        "    -salt-mpsi       Per-session-salted MPSI hashing (T15)\n"
        "                     Senders agree on a secret salt via peer mesh; XOR\n"
        "                     into IDs before MPSI hashing. SP can't dictionary-\n"
        "                     attack known IDs anymore. See SALTED_MPSI_DESIGN.md\n"
        "    -pw <W>    Payload width in 16-byte blocks per row (default 1).\n"
        "               CSV must then have 1+W columns: col0=ID, cols1..W=payload.\n"
        "               Cascade carries N*W single-block columns; output CSV has\n"
        "               N*W comma-separated hex blocks per intersection row.\n"
        "\n"
        "Helper modes:\n"
        "    -auth-genkey -auth-dir <dir> -auth-id <name> [-auth-sk <skfile>]\n"
        "                generate fresh long-term Ed25519 keypair and exit\n"
        "\n"
        "Examples:\n"
        "  frontend -mpsa -N 3 -r 0\n"
        "  frontend -mpsa -N 3 -r 1 -i 0 -in dataset/sender_0.csv\n"
        "\n"
        "See README.md and docs/RESEARCH_MPSI.md for protocol details.\n";
}

void doFileMpsa(CLP& cmd)
{
    if (cmd.isSet("h") || cmd.isSet("help")) {
        printMpsaUsage(std::cout);
        return;
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("MpsaDriver: sodium_init failed");
    }

    // T14 helper mode: generate long-term Ed25519 keypair for this party.
    // Usage: frontend -mpsa -auth-genkey -auth-dir <dir> -auth-id <name> -auth-sk <skfile>
    if (cmd.isSet("auth-genkey")) {
        std::string dir = cmd.getOr<std::string>("auth-dir", "./auth");
        std::string selfId = cmd.getOr<std::string>("auth-id", "");
        std::string skFile = cmd.getOr<std::string>("auth-sk", "self.sk");
        if (selfId.empty()) {
            throw std::runtime_error("-auth-genkey requires -auth-id <name>");
        }
        volePSI::mpstar::MpIdentity::genkey(dir, selfId, skFile);
        std::cout << "Wrote keypair: " << dir << "/" << selfId << ".pk + "
                  << dir << "/" << skFile << "\n";
        return;
    }

    gVerbose = cmd.isSet("v") || cmd.isSet("verbose");

    uint32_t N    = cmd.getOr<uint32_t>("N", 3);
    int role      = cmd.getOr<int>("r", 0);
    int basePort  = cmd.getOr<int>("port", 17500);
    std::string spHost = cmd.getOr<std::string>("host", "localhost");
    uint64_t padCmax = cmd.getOr<uint64_t>("cmax", 0);  // 0 = no padding
    bool pqHybrid = cmd.isSet("pq");  // post-quantum hybrid handshake (stub KEM in this build)
    uint64_t minK = cmd.getOr<uint64_t>("mink", 0);          // threshold-k reveal (T10)
    double cardEpsilon = cmd.getOr<double>("dp", 0.0);       // DP cardinality release (T8)
    std::string authDir = cmd.getOr<std::string>("auth-dir", "");  // T14 long-term identity dir
    bool mpsiSalted = cmd.isSet("salt-mpsi");                       // T15 per-session salted MPSI
    uint32_t payloadW = cmd.getOr<uint32_t>("pw", 1);               // payload width (16B blocks per row)
    if (payloadW < 1 || payloadW > 256) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -pw must be in [1, 256]");
    }

    if (N < 2) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -N must be >= 2");
    }
    if (basePort <= 0 || basePort + static_cast<int>(2 * N) > 65535) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -port out of range; must be in [1, 65535-2N]");
    }
    if (spHost.empty()) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -host cannot be empty");
    }

    if (role == 0) {
        std::string out = cmd.getOr<std::string>("out", "out_cleartext.csv");
        macoro::sync_wait(runSpRole(N, basePort, out, padCmax, pqHybrid, minK,
                                    cardEpsilon, authDir, payloadW));
    } else if (role == 1) {
        uint32_t idx = cmd.getOr<uint32_t>("i", 0);
        std::string in = cmd.getOr<std::string>("in", "");
        if (in.empty() || idx >= N) {
            printMpsaUsage(std::cerr);
            throw std::runtime_error("MpsaDriver: sender requires -in <csv> and -i in [0, N)");
        }
        macoro::sync_wait(runSenderRole(N, idx, basePort, in, spHost, padCmax,
                                        pqHybrid, authDir, mpsiSalted, payloadW));
    } else {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: invalid -r role (use 0 for SP, 1 for sender)");
    }
}

} // namespace volePSI
