# RsMpsiVole: integration roadmap for real VOLE-PSI MPSI

This doc describes how to take `volePSI/RsMpsiVole.{h,cpp}` from its current
scaffolded state (compiles, throws at every call site) to a working
KMPRT-style or Zhang-style MPSI on top of the upstream
[Visa-Research/volepsi](https://github.com/Visa-Research/volepsi) library
that this build already pulls.

## Why the swap matters

The current `volePSI/RsMpsi.{h,cpp}` is "Simple-Hash" deterministic PSI:
SP broadcasts an AES key, each sender hashes its IDs with that key, SP
intersects the masked hash sets. This has two weaknesses for production:

1. **AES-key reuse risk.** SP issuing the same key across multiple sessions
   leaks frequency information (which masked-hash values recur across
   sessions). Session-id binding (Round 5C) reduces this but doesn't
   eliminate it: a sender's input set's frequency profile leaks to SP
   across many runs.
2. **No malicious security for the intersection step.** A malicious sender
   could submit fake hashes (e.g. constants), corrupting the intersection
   without SP detecting.

A real VOLE-PSI MPSI fixes both: the OPRF gives each sender's hashes
fresh pseudorandomness per session (no cross-session profile), and the
Rindal-Schoppmann construction has a malicious-secure variant.

## Candidate constructions

| Construction | Reference | Star topology? | Primitives | Status |
|---|---|---|---|---|
| **KMPRT** | Kolesnikov, Matania, Pinkas, Rosulek, Trieu. *Practical Multiparty PSI from Symmetric-Key Techniques.* ACM CCS 2017. | Yes (designated leader = SP) | OPRF + OT extension | Most-cited, well-understood |
| **Zhang VOLE-MPSI** | Zhang. *Efficient VOLE based Multi-Party PSI with Lower Communication Cost.* ePrint 2023/1690. | Yes | VOLE + OKVS | Newer, lower comm. ePrint-only, single author — verify proof before deployment. |
| **NTY** | Nevo, Trieu, Yanai. *Simple, Fast Malicious Multiparty PSI.* ACM CCS 2021. | Yes | OKVS + VOLE | Malicious-secure baseline. |
| **CDGOSS** | Chandran et al. *Efficient Linear MPSI in star topology.* PoPETs ~2022. | Yes | OPPRF | Worth comparing if Zhang doesn't pan out. Uncertain exact citation — verify on DBLP. |

**Recommended for first integration:** **KMPRT** (CCS 2017). Reasons:
- Best-documented; reference implementations exist.
- Maps cleanly onto N parallel 2-party PSIs with SP as common party — that
  matches the existing `RsMpsi` SP-broadcasts-key topology.
- Semi-honest only, but matches this prototype's threat model.
- Can be upgraded to NTY's malicious-secure variant later without
  re-architecting the API.

## What the upstream provides

The upstream `Visa-Research/volepsi` (pulled by this build at compile time
via `cmake/findDependancies.cmake`) defines its OWN `volePSI` namespace with:

- `volePSI::RsPsiSender` and `volePSI::RsPsiReceiver` — 2-party VOLE-PSI
  (Rindal-Schoppmann EUROCRYPT 2021). NOT to be confused with this fork's
  local `volePSI::RsPsi3rdPSenderA/B/Receiver` in `volePSI/RsPsi.h`, which
  are Simple-Hash.
- `volePSI::Baxos` — OKVS (Garimella et al. CRYPTO 2021)
- `volePSI::RsCpsi*` — Circuit-PSI

The expected upstream API (verify against the actual headers once the build
runs once and `out/install/.../include/volePSI/RsPsi.h` exists):

```cpp
class RsPsiSender {
public:
    void init(u64 senderSize, u64 recverSize, u64 statSecParam,
              block seed, bool malicious, u64 numThreads);
    task<> run(span<block> inputs, Socket& chl);
    // sender does NOT learn intersection
};

class RsPsiReceiver {
public:
    void init(u64 senderSize, u64 recverSize, u64 statSecParam,
              block seed, bool malicious, u64 numThreads);
    task<> run(span<block> inputs, Socket& chl);
    // receiver learns the intersection: getIntersection() returns indices
    std::vector<u64> mIntersection;
};
```

## Name collision: this codebase's RsPsi.h vs. upstream's

Both live in `namespace volePSI` and both are named `RsPsi*`. They cannot
coexist on the include path without resolution. Two options:

**Option 1 (recommended): rename the local Simple-Hash classes.**
- `volePSI/RsPsi.h` → `volePSI/RsSimpleHashPsi.h`
- `RsPsi3rdPSenderA` → `RsSimpleHashPsi3rdPSenderA` (and same for B, Receiver)
- Update `fileBased.cpp` and `RsMpsi.cpp` accordingly.
- Upstream's `RsPsiSender` / `RsPsiReceiver` are then accessible as their
  canonical names.

Effort: ~30 min mechanical rename + grep-replace. Low risk; existing 2-party
PSA workflow keeps working with the same CLI.

**Option 2 (uglier): namespace-shim.**
- Wrap local Simple-Hash in a sub-namespace: `namespace volePSI::shps`.
- Include upstream `<volePSI/RsPsi.h>` only inside `RsMpsiVole.cpp`.
- This avoids touching existing users but creates per-file include rules
  that future contributors will get wrong.

Pick Option 1. The local `RsPsi*` classes already have a quirky name
("3rdP" for the SP role) that signals their non-standardness.

## Implementation plan for `RsMpsiVole`

**Architecture choice: parallel vs. cascade pairwise PSI.**

| Approach | Topology | Communication | SP knows... |
|---|---|---|---|
| **Parallel** | SP runs N 2-party PSIs in parallel, one per sender. After all, SP has N sets of "intersect-of-{my virtual set, sender_i's set}". | O(N · n · λ) | Each sender's intersection with SP's virtual set, then combines them. |
| **Cascade** | SP runs PSI with sender 0, getting intersection set I_0. Then PSI with sender 1 using I_0 as input, getting I_0 ∩ I_1. Etc. | O(N · n · λ) total, but sequential rounds. | Each intermediate intersection. |

KMPRT (CCS 2017) is actually neither — it uses a clever OPRF-share-combine
that runs all PSIs effectively in parallel without the SP needing a
"virtual set" reference. The simpler parallel/cascade approaches above are
acceptable approximations that don't require implementing the OPRF-combine
trick.

**Recommendation: cascade, for first integration.** Simpler implementation
(N-1 calls of an existing function), correct, and only loses constant-factor
performance vs. KMPRT-proper.

## Subtasks

1. **Rename local Simple-Hash** classes (Option 1 above). ~30 min.
2. **Build the upstream `volePSI::RsPsiSender`/`Receiver` into the link.**
   Should already be linked via `oc::libOTe` (cf. `volePSI/CMakeLists.txt`).
   Verify with `nm` on the built lib. ~15 min.
3. **Wire `RsMpsiVoleSender::runIntersection`.** Sender side calls
   `upstream::RsPsiSender::init + run` with SP socket. Then receives the
   bitvector from SP (existing protocol). ~50 LoC.
4. **Wire `RsMpsiVoleReceiver::runIntersection`.** SP runs N cascade
   PSIs (each producing `mIntersection` indices). Build a virtual-set
   data structure that tracks "which of sender i's input indices are
   in the N-way intersection". This needs each sender to send their
   index→hash mapping in a setup phase OR the upstream API to expose it.
   ~100-150 LoC.
5. **Switch `MpsaDriver` to use `RsMpsiVole*` instead of `RsMpsi*`** behind
   a `-mpsi-backend vole` flag. Keep `RsMpsi*` as the default for now (so
   semi-honest non-VOLE deployments still work). ~10 LoC.
6. **Update `tests/run_mpsa_smoke.sh`** to also exercise the VOLE backend.

## Effort estimate

For an engineer with VOLE-PSI familiarity: **2-3 days**. The bulk is in
subtask 4 (the per-sender bitvector reconstruction). For an engineer
learning VOLE-PSI from scratch: **1-2 weeks** including reading the paper
and confirming the upstream API matches expectations.

## What to verify before merging

- The upstream `RsPsiReceiver` actually exposes `mIntersection` (or
  equivalent) per-input-index, not just a global set membership.
- The build pulls a `volePSI` library version whose `RsPsi*` API matches
  the signature in this doc. If not, adapt.
- Benchmark vs. the existing Simple-Hash MPSI on N=3, n=10⁶. Expected:
  similar wall-clock (network-bound at 1Gbps) but better cross-session
  privacy properties.

## After this lands

The natural next step is upgrading the cascade-PSI to KMPRT-proper for
the bandwidth saving, then upgrading to NTY (CCS 2021) for malicious
security on the intersection step. Both are research-track and would
typically be a paper rather than a feature ticket.
