# Changelog — multiparty extension

This is the change history of the `elmontu/PSA-for-multiparty` fork relative
to the upstream `DTC-NTU/PSI-DTC.SG` 2-party PSA codebase. The original
upstream commits are not preserved (single-commit fresh-history fork).

## Initial fork commit
Added the N-party Private Set Alignment scaffold:
- `volePSI/MpStarChannel.{h,cpp}` — star-topology relay over coproto::Socket
- `volePSI/MpStarSetup.{h,cpp}` — pairwise sender↔sender X25519 DH via SP relay
- `volePSI/RsMpsi.{h,cpp}` — N-party Simple-Hash MPSI
- `volePSI/MpShuffleDriver.{h,cpp}` — star-cascade OSN reusing existing Benes
- `volePSI/MpsaDriver.{h,cpp}` + `frontend/main.cpp` patch — end-to-end driver
- `tests/gen_mpsa_dataset.py` + `tests/run_mpsa_smoke.sh` — test harness
- `docs/RESEARCH_MPSI.md` — protocol design rationale
- `docs/DEFERRED_AUDITS.md` — audit follow-up list
- New build dep: `libsodium-dev` via pkg-config

## Wiring + hardening
- coproto TCP API stubs replaced with `coproto::asioConnect(addr, isServer)`
- macoro::when_any / sleep_for / when_all(vector) replaced with std::thread
  + std::condition_variable patterns where the corresponding macoro primitives
  weren't available in this build's release
- relayLoop: per-destination drain pattern with per-task try/catch isolation;
  mutex-across-co_await bug removed
- Phase 0 mask aggregation wired; sender 0 collects r_j via AEAD
- Masked-column m_i now AEAD-wrapped under per-sender SP key (new
  `MpSpHandshake` class)
- Session-id binding via `mpstar::deriveSessionKey` (random sid + base key +
  purpose-string KDF) defeats cross-session ciphertext replay
- New shared `MpStarCrypto` helpers (serialize/deserialize blocks, AEAD)
- `volePSI/RsMpsiVole.{h,cpp}` scaffolded as drop-in for the future
  upstream-VOLE-PSI MPSI swap

## Operability
- Clean relayLoop shutdown via `requestStop()` + atomic flag (no more
  detach + die-on-exit)
- Dockerfile: installs `pkg-config libsodium-dev`
- `-host <hostname>` CLI flag (default localhost)
- `-h` / `-help` prints MPSA-specific usage; invalid args print usage + clear error
- Input validation: `-N >= 2`, `-port` in valid range, `-host` non-empty,
  sender `-i in [0, N)`
- README "Multiparty Extension" section with CLI examples + test instructions

## Tests + CI
- `tests/unit/test_mpstar_crypto.cpp` — 9 cases (AEAD roundtrip, MAC/nonce/key
  mismatch, short input, serialize roundtrip, wrong count, empty)
- `tests/unit/test_kdf.cpp` — 6 cases (deriveSessionKey determinism + 3-way
  separation, MpStarSetup min/max symmetry, pair separation)
- `tests/unit/CMakeLists.txt` opt-in via `-DVOLE_PSI_BUILD_TESTS=ON`
- `.github/workflows/ci.yml` — Ubuntu 22.04, build + run unit tests on every
  push and PR to main

## END-TO-END MPSA WORKING (commit 1fd0589)
- Smoke test: `./tests/run_mpsa_smoke.sh` PASSes with N=3, intersection=100, total=1000/sender.
- Replaced star-with-relay design with direct peer-to-peer mesh (sender↔sender
  TCP connections; SP no longer in the data path for inter-sender traffic).
  The star-with-relay path deadlocked on coproto's single-thread io_context.
- Canonical pair iteration (sender i accepts, sender j connects in lockstep)
  avoids peer-setup deadlock.
- coproto's `Socket::flush()` is required before destruction; added flushes
  in `MpStarChannel::sendTo` and at protocol exits.
- Three other build/runtime bugs caught and fixed earlier in the rounds:
  `coproto::Socket::recv(vector)` doesn't auto-resize (pre-size or length-
  prefix); `PRNG(seed).get(ptr, bytes)` segfaults (use `SetSeed` + template
  get); OSN had hardcoded PRNG seed (added `init_wj_seeded`).

## Post-milestone cleanup
- `-v / -verbose` CLI flag gates per-step debug logs (default silent).
- Removed dead `MpShuffleDriver::runSp` spChan parameter.

## Known research-grade items still open
See `docs/DEFERRED_AUDITS.md`. Headline items:
- Output is currently XOR-aggregated; N-column joined-table format needs a
  Phase-0 redesign (linear in N effort).
- RsMpsiVole upstream wiring (Zhang 2023/1690 or KMPRT; needs upstream
  volePSI headers; name collision with local `RsPsi.h` to resolve).
- Malicious-secure cascade shuffle (RSS-3PC for N=3 or SSS chain for N≥4).
