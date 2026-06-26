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

## Second round of fixes — closed and remaining

### Closed (this commit)
- MpShuffleDriver `recvBlocksOnSocket` short-read: now loops with `recvExact` pattern.
- MpStarCrypto helpers (`serializeBlocks` / `deserializeBlocks` / `aeadEncrypt` / `aeadDecrypt`) extracted into a shared header so MpsaDriver and MpShuffleDriver share them.
- MpStarChannel `relayLoop`: replaced mutex-across-`co_await` with per-destination drain pattern (one producer task per sender socket → per-dest AsyncQueue → one consumer task per dest socket). Per-task try/catch added for error isolation. Removed dead `mSenderSendMutex` member.
- MpsaDriver: `parseCsv` now uses the exported `readSet()` from fileBased.h. Phase 0 mask aggregation wired (sender 0 collects r_j from peers via AEAD, others ship to sender 0). `relayLoop` driven concurrently with shuffle via `macoro::when_any`.

### Still remaining (need a build to verify)
- **HIGH — coproto TCP API names.** `asioAccept` / `asioConnect` are still placeholder stubs returning empty `coproto::Socket{}`. The build will pull coproto; replace with the actual API (likely `coproto::AsioAcceptor` and `coproto::AsioSocket::connect`) once the headers are on disk.
- **HIGH — OSN semantics.** Still unverified — depends on actual `osn/OSNSender.cpp` behavior. See TODO comment in MpShuffleDriver.cpp.
- **MED — `macoro::when_any` return shape.** Code destructures `auto [shuffled, _]` — verify against the macoro release in your build.
- **MED — `macoro::sleep_for` symbol.** Used inside AsyncQueue `pop()` busy-wait in MpStarChannel.cpp. If macoro names it differently, adjust.
- **MED — last-sender reveal port.** `runSenderRole` connects the last sender to `basePort + 2*N` for the final reveal; SP doesn't currently `asioAccept` on that port. Either add the accept OR collapse the final-reveal into `osnSocksPerRound.back()` everywhere.
- **LOW — AsyncQueue busy-wait.** 1ms polling is fine for prototype; replace with coroutine-aware queue for production.

## Third round — Phase 4 fixes

### Closed (this commit)
- New `volePSI/MpSpHandshake.{h,cpp}` — X25519 DH between SP and each sender, derives a per-pair symmetric key. Wired into `MpsaDriver` BEFORE MPSI runs.
- `MpsaDriver`: masked-column transmission now AEAD-wrapped under the SP key (sender `aeadEncrypt(m_i)` → SP `aeadDecrypt`). SP detects tampering / forgery before XOR'ing into M_0.
- New `volePSI/RsMpsiVole.{h,cpp}` — scaffolded API surface for the future swap from Simple-Hash MPSI to upstream 2-party VOLE-PSI (KMPRT-style with SP as common party). Public API drop-in compatible with `RsMpsi3rdP*`. All upstream call sites are TODO stubs that throw at runtime; compiles, doesn't run.

### Still remaining (Phase 4 — implementation, not scaffolding)
- **HIGH — RsMpsiVole upstream wiring.** Needs the actual `volePSI::RsPsiSender` / `RsPsiReceiver` from Visa-Research/volepsi pulled in by the build. Name collision with the local Simple-Hash `RsPsi.h` — see header comment in RsMpsiVole.cpp.
- **HIGH — malicious-secure shuffle.** Cascade-OSN currently semi-honest. Upgrade path per `docs/RESEARCH_MPSI.md` §4: MACs on intermediate shares + RSS-3PC shuffle (N=3) or SSS chain (N≥4).
- **MED — sender↔sender malicious hardening.** Phase 0 AEAD'd already; need commit-and-open on OPRF outputs to prevent equivocation under malicious senders.
- **MED — replay protection on AEAD.** secretbox nonces are random; safe per-session but no sequence number. If sessions are reused, add a session salt to the KDF.

## Fourth round — Concrete residuals from Phase 4

### Closed (this commit)
- **HIGH** coproto TCP API: stubs replaced with real `coproto::asioConnect(addr, isServer)` — mirrors the existing 2-party `doFileSpHshPSIwithOSN` pattern in `fileBased.cpp`. Wrapped in `#ifdef COPROTO_ENABLE_BOOST` like the upstream code. Senders connect to `localhost:<port>`, SP accepts.
- **MED** Last-sender reveal port: SP now `spAccept(basePort + 2*N)` and pushes the resulting socket onto `osnSocksPerRound.back()` so `MpShuffleDriver::runSp`'s existing reveal-recv-on-last-socket logic finds it.
- **MED** `macoro::when_any` not in this build's macoro release. Replaced with `std::thread` for `relayLoop`, with shuffle driving the foreground; thread detaches when shuffle returns and is reaped on process exit.
- **MED** `macoro::sleep_for` not in macoro release. Replaced with `std::this_thread::sleep_for` in AsyncQueue. Acceptable if executor is multi-threaded (each consumer on its own thread); wedges on single-threaded executor — TODO at top of MpStarChannel.cpp.
- **MED** `macoro::when_all(vector<task>)` not in macoro release (only variadic `when_all_ready` is, per RsPsi.cpp:239). Replaced with one `std::thread` per producer/consumer, each calling `macoro::sync_wait` on its own task body. Ugly but correct; relayLoop's outer signature stays `macoro::task<>`.

### Still remaining (research-grade)
- **HIGH** OSN role/semantics verification: this assumes `OSNSender::run_osn` overwrites `input_vec` with sender's new share = π(input) XOR correlation. Verify by in-process unit test after first build.
- **HIGH** RsMpsiVole upstream wiring (Zhang 2023/1690 or KMPRT).
- **HIGH** Malicious-secure shuffle (RSS-3PC or SSS chain).
- **MED** AsyncQueue still busy-waits; replace with proper coroutine-aware queue for production.
- **LOW** Production deployment would `localhost` → real hostnames from a config; trivial.

## Round 5 — small concrete hardening

### Closed (this commit)
- **MED** AsyncQueue: replaced busy-wait with `std::condition_variable`. push() notifies, pop() blocks on cv.wait. No more 1ms tight loops; works under any executor model.
- **MED** Offline unit tests: `tests/unit/test_mpstar_crypto.cpp` covers 9 cases (AEAD round-trip, empty plain, MAC mismatch, nonce mismatch, wrong key, short input, serialize round-trip, wrong-count deserialize, empty blocks). Opt-in via `-DVOLE_PSI_BUILD_TESTS=ON`.
- **MED** Session-id binding: SP picks a random 32-byte session ID at the top of every MPSA run, broadcasts to all senders. All AEAD keys are derived from `(base_key, session_id, purpose)` via RandomOracle KDF. Catches cross-session replay even with long-term DH-key reuse. New function: `volePSI::mpstar::deriveSessionKey`.

### Scope clarification
- The original "commit-and-open on Phase 0 r_i exchange" item was downscoped: in our exact topology r_j has only ONE recipient (sender 0), so the across-recipients-consistency property doesn't apply. Real malicious-sender protection here would need Pedersen-style commitments or a PKI signature scheme; both are research-grade and out of scope for a small fix. The session-id binding above is the substituted small-fix that does provide a real new property (replay protection).

## Round 9 — research-grade items

### Closed (this commit)
- **HIGH** AEAD on cascade `rho_k` and final-reveal `R`. Previously cleartext on the SP socket; now AEAD-wrapped under the session-bound SP key. Tampered `rho_k` is rejected at SP. Closes one half of the cascade-malicious-hardening gap. `MpShuffleDriver::runSender` and `runSp` now take the SP key(s); `MpsaDriver` plumbs them through.
- **HIGH** OSN semantics test scaffold: `tests/unit/test_osn_semantics.cpp` is a compile-ready in-process test that runs the cascade invariant (`newR XOR newM == pi(R XOR M)`) against the real `osn/OSNSender.cpp` + `osn/OSNReceiver.cpp`. The `makeSocketPair()` helper at the top is a stub that returns "skipped" (exit code 77) until the build-time coproto in-process socket-pair API is wired in. CMake target added.
- **DOC** `docs/MALICIOUS_UPGRADE_ROADMAP.md` written. Three paths (RSS-3PC for N=3, CGP chain for N≥4, lightweight Ed25519 signatures + commit-and-open for attribution). Each with paper refs, subtask decomposition, effort estimate.
- **DOC** `docs/RSMPSI_VOLE_INTEGRATION.md` written. Concrete integration plan for the upstream VOLE-PSI swap, including the name-collision resolution (rename local Simple-Hash classes), expected upstream API, parallel-vs-cascade tradeoffs, 6-subtask checklist, effort estimate.

### Genuinely still remaining (cannot finish without external blockers)
- **CRITICAL — OSN shuffles ONE party's input, not the cascade's XOR-shared `(M⊕R)`.** Reverse-engineered from `osn/OSNSender.cpp` and confirmed via `tests/unit/test_osn_semantics`. The actual contract is:
  1. `OSNSender::init_wj(size, ot_type, cache, &i2loc)` picks its OWN destination permutation `dest` via Fisher-Yates and bakes Benes switches for it. The caller cannot pass in a `pi`. `setPi` and `getmyPi` are just metadata — they don't affect routing.
  2. After `init_wj`, the map `i2loc` is populated such that `i2loc[dest[i]] = i` for all `i` (i.e. `i2loc` is `dest^{-1}`).
  3. After `OSNReceiver::run_osn(M, chl, output_masks)` + `OSNSender::run_osn(chl, input_vec)`:
     **`input_vec[j] XOR output_masks[j] == M[dest[j]]`** for all `j`.
     Equivalently, M's input position `i` ends up at output position `i2loc[i]`.
  4. The cascade in `MpShuffleDriver` assumed `newR[j] XOR newM[j] == pi(M[j] XOR R[j])` — which conflates the receiver-only-input shuffle with a shared shuffle. **Wrong by design.** The OSN gives us `pi_k(M_k)` but not `pi_k(R_k)`.

- **CRITICAL #2 — `init_wj`'s PRNG seed is HARDCODED** (`osn/OSNSender.cpp:160`):
  ```cpp
  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // we need to modify this seed
  ```
  The author's own comment acknowledges the deficiency. The Fisher-Yates that produces `dest` always consumes from a fixed seed; therefore **every call to `init_wj(size, ...)` with the same `size` produces the same `dest`**. Confirmed by two back-to-back runs of `test_osn_semantics`: identical i2loc both times. Implications:
  - All N-1 cascade rounds would compose the SAME permutation — defeating the purpose of having N-1 rounds.
  - Even a single shuffle is publicly predictable: anyone with the seed can compute `dest` offline and de-anonymize the output.
  - In the original 2-party PSA, this happens not to be a privacy issue *because* the same dest gets applied once per protocol invocation and the shared output is XOR-secret anyway. But the moment you compose multiple OSN calls, the determinism shows up as broken security.

- **Combined implication:** the existing OSN in this codebase is **unusable as-is** for any multi-round shuffle protocol, including the MpShuffleDriver cascade. Fix paths:
  - **(P)** Fork `osn/OSNSender.cpp` to accept a seed parameter on `init_wj`. **DONE** — added `OSNSender::init_wj_seeded(size, ot_type, cache, &i2loc, seed)`. Verified via `test_osn_semantics`: different seeds → different permutations. The cascade can now derive a per-round seed from the session-bound pairwise key (e.g. `deriveSessionKey(setup.key(k), sessionId, "shuffle_round_k")` repurposed). Still needed: wire it into MpShuffleDriver.
  - **(Q)** Use the OSN only ONCE end-to-end (no cascade). Limits protocol to N=2-party-style alignment; loses the multi-party privacy benefit.
  - **(R)** Switch to Chase-Ghosh-Poburinnaya Secret-Shared Shuffle (Asiacrypt'20). The right primitive for shared inputs; comes with proper per-call randomness. Multi-week, also addresses the malicious-shuffle roadmap. See `docs/MALICIOUS_UPGRADE_ROADMAP.md` Path B.

- **Cascade two-OSN-per-round refactor DONE (commit pending):** MpShuffleDriver rewritten end-to-end. Each round runs two OSN calls (M-side, R-side) sharing the same `init_wj_seeded` per-round seed derived from sender↔SP session key + sessionId + "shuffle_round_k". Both invariants now hold by construction: `(M_{k+1} XOR R_{k+1}) = dest_k(M_k XOR R_k)`. MpsaDriver socket layout extended to 3N-1 ports (per-sender star/MPSI + 2 OSN sockets per round + 1 reveal). All unit tests still pass; build is clean.
- **Round 12 bisection (real bugs found + fixed):** end-to-end run bisected via `std::cerr` at each protocol step. Got past: TCP accept ✓ sessionId broadcast ✓ MpSpHandshake DH ✓ MPSI intersection ✓ masked-column transmission ✓ MpStarSetup initial `sendTo` ✓. **Fixed:**
  - `coproto::Socket::recv(std::vector<uint8_t>&)` does NOT auto-resize; reading into an empty vector reads 0 bytes silently. Bug existed in 2 places (MPSI bitvec recv, masked-column ciphertext recv). Fix: pre-size the vector (for known lengths) or send a length prefix first (for variable lengths like AEAD ciphertext).
  - `PRNG(seed).get(ptr, byteCount)` crashed; the working pattern is `PRNG prng; prng.SetSeed(seed); prng.get<T>(ptr, count)` where `count` is element count, not byte count.
- **Remaining blocker — coproto threading model:** Each sender's `MpStarSetup::runSender` calls `chan.sendTo(j, pk)` (succeeds — bytes reach SP) then `chan.recvFrom(j)` (hangs). SP's relayLoop is spawned in a std::thread and runs its own producer/consumer threads via independent `macoro::sync_wait` calls. Likely failure mode: coproto's `AsioSocket` is built on a single `io_context` that assumes ONE driver thread; multiple `sync_wait`s on different threads either don't drive the io_context or contend for it. The relay reads incoming frames but doesn't deliver them to the destination socket. Fix requires architectural rework — likely `macoro::when_all_ready` over all relay tasks driven by the SAME thread as the main coroutine, or use coproto's intended scheduler integration. Not a quick line fix.

## Round 13 — END-TO-END MPSA WORKING

The threading-model blocker above was resolved by **replacing the star-with-relay design with a direct peer-to-peer mesh**: for each sender pair (i, j) with i < j, sender i accepts a TCP connection and sender j connects. SP no longer touches sender↔sender traffic. MpStarChannel becomes a thin per-peer wrapper. `relayLoop`, `requestStop`, queues, std::threads — all gone.

Canonical pair iteration avoids the obvious deadlock at peer-setup time (every sender iterates pairs in the same canonical order; at each step exactly one sender accepts and one connects). Additional fixes:
- `coproto::Socket::flush()` is required before destruction; without it, `terminate()` fires. Added flush in `MpStarChannel::sendTo` (per send) and at `runSpRole`/`runSenderRole` exits.

**Smoke test result:** `./tests/run_mpsa_smoke.sh` PASSes with N=3, intersection=100, total=1000 records per sender. Output: 100 hex rows representing the per-position XOR of all senders' payloads at intersection rows (this is what the current Phase 0 aggregation produces).

## Round 14 — post-milestone cleanup

- Removed dead `MpStarChannel::runSp` parameter (no longer used after the relay was deleted).
- `-v / -verbose` CLI flag added; gates per-step debug logs (`LOG` macro). Default mode is silent.
- Removed bisection cerrs from `MpStarSetup` and `RsMpsi`.
- Updated `MpsaDriver.cpp` file header to document the peer-mesh design.

## What's still genuinely open (post-Round 14)

- **Output format is XOR-aggregated**, not an N-column joined table. The cryptographic mechanism (intersection + shuffle + AEAD) is correct end-to-end; what's missing is a Phase 0 design that keeps each sender's payload in a separate column. ~1 round of design work: either run the cascade N times in parallel under the same seeded permutations (cost: linear in N), or use a wider payload block layout. Either is straightforward now that the underlying primitives work.
- **RsMpsiVole upstream wiring** — still scaffolded; needs Zhang ePrint 2023/1690 or KMPRT real implementation.
- **Malicious-secure shuffle** — research-grade, see `docs/MALICIOUS_UPGRADE_ROADMAP.md`.
- **HIGH** RsMpsiVole upstream wiring: needs the upstream `volePSI::RsPsiSender`/`RsPsiReceiver` headers (now confirmed available at `out/install/linux/include/volePSI/`) + the name-collision rename in Option 1 of `RSMPSI_VOLE_INTEGRATION.md`. 2-3 days of focused work.
- **HIGH** Malicious-secure shuffle (RSS-3PC for N=3, CGP chain for N≥4): see `MALICIOUS_UPGRADE_ROADMAP.md`. 2-3 weeks (Path A) to 4-6 weeks (Path B) of cryptographer-engineer time with the papers in hand. The OSN-pi finding above strengthens the case for picking up a separate shuffle primitive entirely rather than salvaging the cascade-OSN path.

## Round 10 — build session results

Successful first end-to-end build on Ubuntu 24.04, libsodium 1.0.18 (system) + auto-fetched coproto/libOTe/macoro/Boost 1.86.0/bitpolymul. Real bugs caught + fixed:

### Closed (this commit)
- **build** `co_await sock.recv(span)` returns `void`, not a size; coproto throws on EOF. Replaced multi-iteration `recvExact`/`sendExact` helpers with single-shot calls in MpStarChannel and MpShuffleDriver. **Real bug; my prototype's loop pattern was wrong.**
- **build** `RandomOracle::Final(ptr, size)` doesn't exist; the size is fixed at construction. Use `Final(ptr)`. Fixed in MpStarSetup.
- **build** `oc::block` requires `cryptoTools/Common/Defines.h` (which defines `namespace oc = osuCrypto`); `block.h` alone is not enough. Fixed in MpStarCrypto.h and MpShuffleDriver.h.
- **build** `OSNSender`/`OSNReceiver` are in the global namespace (their headers do `using namespace volePSI;` at file scope — questionable practice but real). My `volePSI::OSNSender` qualified references didn't link. Removed the `volePSI::` qualifier in MpShuffleDriver and test_osn_semantics.
- **build** `OSNSender::init(size, ot_type, ...)` is **declared but not implemented**; only `init_wj(size, ot_type, cache, i2loc_map)` is defined. Switched to `init_wj` with an identity `i2loc` map. Fixed in MpShuffleDriver and test_osn_semantics.
- **build** `OSNReceiver::init` is documented as `init(size, ot_type = 0)` but the existing code always passes `ot_type=1`. Default-zero may or may not work; matched existing convention.
- **wire** `coproto::LocalAsyncSocket::makePair()` confirmed as the in-process socket-pair API. `test_osn_semantics` now uses it for real.

### Test results
- `test_mpstar_crypto`: 9/9 PASS
- `test_kdf`: 6/6 PASS
- `test_osn_semantics`: FAIL — surfaced the CRITICAL OSN-pi finding documented above. This is the test working as designed.
- `frontend -mpsa -h`: prints clean usage; CLI parses correctly.
