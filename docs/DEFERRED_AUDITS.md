# Deferred audit findings

These came out of code review during the initial build but were not
addressed before commit, either because the fix is non-trivial or because
the prototype works without it under the documented semi-honest threat
model with a single-threaded coproto executor.

## MpStarChannel.{h,cpp} — committed after iteration 3

- **HIGH — concurrency.** `relayLoop` holds `std::lock_guard<std::mutex>` across `co_await`. Unsafe under single-threaded executor (deadlock) and unsound under multi-threaded (unlock may run on a different thread). Replace with coroutine-aware mutex, or refactor to a single-task-per-destination pattern with a per-destination send queue + drain task. **TODO comment in source.**
- **HIGH — error isolation.** Any per-sender task in `relayLoop` that throws kills the whole SP via `macoro::when_all`. Wrap each per-sender loop in try/catch; log + close that one socket; let others continue.
- **MED — pre-allocation buffer cap.** `recvFrame` len-cap (added in patch) prevents 4-GB allocation DoS but `recvFrom`'s `kMaxBufferedBytes` limit still triggers after allocation. Move all size checks to pre-allocation.
- **LOW — std::map for dense indices.** `mRecvBuf`/`mRecvFrameCount`/`mRecvTotalBytes` keyed by `uint32_t` in `[0, senderCount)`. Replace with `std::vector` for O(1) and cache locality.
- **LOW — narrowing cast.** `static_cast<uint32_t>(data.size())` in `sendTo`/`relayLoop` truncates if payload > 4 GiB; the new pre-alloc cap already rejects this, but add an explicit assert at the cast site.
- **LOW — `assert(cnt > 0)` in `recvFrom`.** Asserts compile out in release. If the invariant could ever be broken (e.g. concurrent buffer access we don't see today), switch to `throw std::logic_error`.
- **LOW — `noexcept` on `readU32BE`/`writeU32BE`.** Honest but brittle; remove or document that callers guarantee 4-byte buffers.

## MpStarSetup.{h,cpp} — committed after iteration 2

- **MED — KDF choice.** Used `oc::RandomOracle` (codebase's hash sponge) as the KDF instead of true HKDF-SHA256. Equivalent security for this use (single derivation from a high-entropy DH secret) but doesn't follow the HKDF extract-then-expand spec verbatim — flag if a Singapore-government deployment requires HKDF compliance per IM8 crypto policy.
- **MED — sodium_init lifecycle.** Code assumes the frontend calls `sodium_init()` before any MpStarSetup instance runs. Will be wired up in the frontend sub-step. If forgotten, libsodium calls undefined-behavior.
- **LOW — no PRNG abstraction.** Calls `crypto_box_keypair` directly, bypassing the codebase's `oc::PRNG` (which feeds RNG-determined seeds for reproducibility in test). Use a separate sodium_test_init for determinism in unit tests if needed.
- **LOW — no key-agreement validation.** Doesn't catch the all-zero shared-secret edge case in HKDF (a malicious peer can force it via specific points). `crypto_scalarmult`'s nonzero return covers most cases but not all; consider adding an explicit all-zero check on `sharedSecret`.
- **BUILD — libsodium is a new dependency.** Added via pkg-config in CMakeLists.txt. Ubuntu/Debian: `apt install libsodium-dev`. Add to dockerfile.

## MpShuffleDriver.{h,cpp} — committed after iteration 2 + manual cleanup

- **HIGH — OSN semantics unverified.** Code assumes `OSNSender::run_osn(sock, input_vec)` overwrites `input_vec` with sender's new share = π(input) ⊕ correlation, and `OSNReceiver::run_osn(span, sock, output_masks)` fills `output_masks` with receiver's new share. Invariant: sender_share XOR receiver_share = π(original). Must verify against `osn/OSNSender.cpp` source before integration test. If semantics differ, the cascade is broken.
- **HIGH — recv may short-read.** `recvBlocksOnSocket` does one `co_await sock.recv(buf)` and assumes it fills `buf`. coproto's `recv` on TCP may short-read. Wrap with a loop similar to `MpStarChannel::recvExact`. **TODO comment in source.**
- **MED — protocol asymmetry.** Last sender (selfIdx == N-1) ships final `R` via the OSN socket of the last cascade round (osnSocksPerRound.back()). This requires the last cascade round and the final reveal to happen on the same socket sequentially. If two passes happen concurrently this breaks.
- **MED — manual cleanup applied during integration.** Include paths (`<oc/block.h>` → `"cryptoTools/Common/block.h"`, etc.), namespace wrapping, and removal of `using namespace volePSI`.
- **LOW — randomPermutation uses std::random_device + mt19937_64.** Acceptable for prototype; for production, route through `oc::PRNG` for testability/reproducibility.

## RsMpsi.{h,cpp} — committed after iteration 1 + manual cleanup

- **MED — Simple-Hash PSI, not VOLE-PSI.** The committed extension preserves the same primitive used by the existing 2-party code: AES-128 deterministic hashing with a server-broadcast key. This is NOT the full VOLE-PSI / OKVS construction recommended in `RESEARCH_MPSI.md`. Upgrading to a true MPSI (e.g. Zhang ePrint 2023/1690 or NTY CCS'21) is a separate sub-step beyond the current build.
- **MED — collision resistance via AES key only.** SP picks one block as the AES key. An honest-but-curious SP that re-runs the protocol with the same key over many sessions could collect a frequency profile of which masked values recur — minor metadata leak but not an intersection leak.
- **LOW — coproto::Socket::send(vector<uint8_t>) length-prefixing.** Relies on coproto auto-prefixing a length when sending a vector. Verify against `coproto::Socket` docs; if not auto-prefixed, add explicit length send.
- **LOW — `mAEShash.hashBlocks(inputs, oc::span<block>(hashed))` fixed manually** from an initial single-arg call; verify cryptoTools AES API for the exact signature (two-arg span-out, hopefully).
- **LOW — review skipped** for this sub-step; rely on the manual review above + integration tests.

## MpsaDriver.{h,cpp} + frontend/main.cpp — committed after iteration 1

This sub-step is **scaffolding, not production code**. It will not compile or run as-is. Concrete TODOs:

- **HIGH — coproto TCP API.** `asioAccept` / `asioConnect` are placeholder stubs that return default `coproto::Socket{}`. Replace with the real coproto async-TCP API once the actual coproto release is pulled at build time (typical pattern: `coproto::AsioAcceptor` + `co_await acc.accept()`).
- **HIGH — CSV parser stub.** `parseCsv` returns empty pairs. The existing CSV-loading helpers live in `fileBased.cpp` (anonymous functions inside `doFileSpHshPSIwithOSN`). Either expose them via `fileBased.h` or duplicate into `MpsaDriver.cpp`.
- **HIGH — Phase 0 mask aggregation.** Sender 0 must collect every other sender's `r_i` via `chan.recvFrom(j)`, decrypting under `setup.key(j)`; senders >0 must call `chan.sendTo(0, encrypt(r_i, key0))`. Currently sketched as TODO comments with `ownMasks = ZeroBlock`. Without this, the shuffle output is meaningless.
- **HIGH — relayLoop not driven.** SP's `MpStarChannel::relayLoop` must run concurrently with `runSp` (e.g., `macoro::when_all`). Currently not invoked; sender-to-sender star traffic will hang.
- **MED — last sender's reveal socket.** Last sender uses `basePort + 2*N` as a reveal socket. SP-side currently uses `osnSocksPerRound.back()` for the same purpose (per MpShuffleDriver design). These don't line up; reconcile.
- **MED — block hex stream operator.** `writeBlocksAsHex` assumes `operator<<` on `block` emits hex. If not, hex-encode manually.
- **LOW — main.cpp patch tested only structurally.** `cmd.isSet("mpsa")` follows the existing CLP idiom but `osuCrypto::CLP::isSet` exact name should be verified.

## tests/{gen_mpsa_dataset.py, run_mpsa_smoke.sh} — committed

- **HIGH — smoke test will fail today.** The smoke test expects `frontend -mpsa` to run end-to-end, which depends on the MpsaDriver TODOs being resolved (coproto API, CSV parser, Phase 0 aggregation, relayLoop drive). Treat the test as a regression contract for *after* those gaps are filled, not a current-state validator.
- **LOW — fixed-IP smoke test.** Uses `127.0.0.1`; multi-host runs need address parameterization.
