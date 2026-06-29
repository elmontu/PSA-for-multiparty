# CGP Secret-Shared Shuffle — design, implementation, and N-party cascade (R26)

## Goal

An alternate shuffle backend for the MPSA cascade based on Chase-Ghosh-
Poburinnaya "Secret-Shared Shuffle" (ASIACRYPT 2020). Compared to the
OSN/Benes shuffle currently driving `MpShuffleDriver`:

| Property | OSN/Benes (current) | CGP SSS (R26) |
|---|---|---|
| Per-call online cost | O(n log n) switches | O(n) XOR + 1 permutation |
| Preprocessing cost | none | O(n) OT extension |
| Online rounds | log n (Benes-depth) | 1 (single message m) |
| Hidden permutation | Yes | Yes |
| Per-call bandwidth (online) | n log n × 16 B | n × 16 B |
| Malicious-secure variant | needs OLE + MACs (R25/R28) | needs commit-and-open on (a, α, π, b) — much cheaper |

CGP wins when the same parties shuffle multiple times (amortized
preprocessing) or when shuffle widths are large. The MPSA cascade has
N-1 shuffles per session of width = intersection-cardinality-bound ≈ a
few thousand rows in plausible deployments — comfortably in CGP's
favorable regime.

## The 2-party CGP protocol

Two parties hold an XOR-shared input vector `x = x_A ⊕ x_B` of length n.
Party B holds a permutation `π : [n] → [n]` that B wants to apply
obliviously: output is `y_A ⊕ y_B = π(x)` with A learning nothing about
`π` and B learning nothing about `x`.

### Correlation (preprocessing)

A trusted dealer (or a 2-party OT-based subprotocol) produces:

```
A receives: a, α       (each length n, vectors of GF(2^128) elements)
B receives: π, b       (permutation + vector b of length n)

Invariant: α = π(a) ⊕ b      (componentwise)
```

A learns nothing about `(π, b)`; B learns nothing about `(a, α)`. The
secret correlation `α = π(a) ⊕ b` is what lets the online phase succeed
without further preprocessing exchanges.

### Online phase (one round, n-block message)

```
A computes  m = x_A ⊕ a                       — blinds x_A with a
A sends     m       → B
A's output  y_A = α
B computes  y_B = π(m ⊕ x_B) ⊕ b
```

### Correctness sketch

```
y_A ⊕ y_B = α ⊕ π(m ⊕ x_B) ⊕ b
          = α ⊕ π(x_A ⊕ a ⊕ x_B) ⊕ b
          = α ⊕ π(x_A) ⊕ π(a) ⊕ π(x_B) ⊕ b      [π is linear over XOR]
          = (α ⊕ π(a) ⊕ b) ⊕ π(x_A ⊕ x_B)
          = 0 ⊕ π(x)
          = π(x)                                 [using α = π(a) ⊕ b]
```

`π(x_B)` is xor'd in via `m ⊕ x_B` inside the π application; the linearity
of π-over-XOR is what makes this work (any permutation is linear over
the group action of element-by-element XOR — it's a relabeling, not an
arithmetic operation).

### Privacy sketch

- **B sees only m = x_A ⊕ a**. Because `a` is uniform from B's view, `m`
  is uniform and reveals nothing about `x_A`.
- **A sees only its own outputs (α, a)**. These are independent of `π`,
  `b`, and `x_B` by construction of the dealer correlation.

## How the preprocessing is generated (the work R26 defers to a follow-up)

The trusted dealer must be replaced by a 2-party protocol that gives A
`(a, α)` and B `(π, b)` with `α = π(a) ⊕ b`. Several known approaches:

1. **OT-based switch-network preprocessing** (CGP §4.2). Roughly: for each
   layer of a switching network, use 1-out-of-2 OT to choose the switch
   setting and propagate the correlation. Native fit for `libOTe`'s
   `SilentOtExtSender`/`SilentOtExtReceiver` already in the build.
2. **OLE / VOLE-based** (more efficient with batching). Same `RsMpsiVole`
   substrate that R28 needs.
3. **Spline-PRF based** (Boyle, Couteau, Gilboa, Ishai, et al.). Cheaper
   communication but requires a non-standard pseudorandom primitive.

Approach (1) integrates cleanly with what we already have. Engineering
estimate: ~600 LoC of OT plumbing wrapping libOTe + correctness tests.

## N-party cascade

The 2-party CGP composes into an N-party shuffle by chaining N-1
instances exactly the same way `MpShuffleDriver` already does with OSN:

```
Round k (k = 0..N-2):
  SP plays A-role.
  Sender k plays B-role (owns π_k, b_k).
  Output of round k: SP holds spShare_{k+1}, sender k holds peerShare_{k+1}.
  Sender k AEAD-hands off (peerShare_{k+1}) to sender k+1 over peer mesh.
Final reveal: sender N-1 sends (peerShare_N) to SP.
SP outputs: spShare_N ⊕ peerShare_N = π_total(x_initial)
            where π_total = π_{N-2} ∘ ... ∘ π_1 ∘ π_0.
```

`π_total` is hidden from every party as long as one sender is honest:
each sender k only knows its own `π_k` factor; composition is uniform if
any one factor is uniform.

Cost per round: 1 trusted-dealer correlation generation (or 1 OT-extension
subprotocol) + 1 length-n message. Compared to OSN's log n rounds and
n log n bandwidth per round, the asymptotic win is real for n in the
thousands.

## Malicious-with-abort upgrade

CGP as published is semi-honest. The malicious-secure variant adds **two
commit-and-open checks per round**:

1. **A commits to `(a, α)` at preprocessing**. After the online phase, A
   opens the commitment. B verifies the opened `a` is consistent with the
   `m` that A actually sent.
2. **B commits to `(π, b)` at preprocessing**. After the online phase, B
   opens. The commitment is bound to the correlation B used in computing
   `y_B`.

Both commitments use the same RandomOracle-based scheme as elsewhere in
the codebase (`mpstar::commit` / `verifyCommit`). In the chain composition,
the commitment for round k can be opened to sender k+1 (the recipient of
the peer handoff), giving a chain of accountable transitions.

`MpCgpShuffle::cgpCascadeRound(... MaliciousMode::Malicious ...)` in this
deliverable checks the structural invariant of the dealer correlation
(`α == π(a) ⊕ b`), modelling the post-open verification. A real wire-
protocol implementation does the same check after seeing the opened
values from the counterparty.

### Threat-model attribution

| Attacker | Detection |
|---|---|
| Malicious dealer issues bad correlation | Either party's malicious-mode check fires on opening — round aborts. |
| A submits `m'` not equal to `x_A ⊕ a` | A's opening of `a` and committed `x_A` exposes the inconsistency. |
| B applies `π' ≠ π` or uses `b' ≠ b` | B's opening of `(π, b)` and the verification of `y_B = π(m ⊕ x_B) ⊕ b` exposes it. |
| Network attacker tampers with `m` in transit | AEAD on the message catches it (this is independent of CGP). |

## What this R26 deliverable provides

- `volePSI/MpCgpShuffle.{h,cpp}` — full 2-party CGP simulation with
  trusted-dealer preprocessing, N-party cascade, semi-honest and
  malicious modes.
- `tests/unit/test_cgp_shuffle.cpp` — 6/6 tests covering correlation
  invariant, online correctness, input blinding, 3-round cascade
  composition, malicious-mode tamper detection, and permutation
  randomness.
- This design document.

## What is intentionally deferred

- **OT-based preprocessing.** The simulation uses a trusted dealer. The
  real protocol uses `libOTe` silent OT to generate the same correlation
  obliviously. ~600 LoC follow-up (R26b).
- **Live wire protocol** integrating `MpCgpShuffle` into `MpShuffleDriver`
  as a selectable backend (`-mode cgp` flag in `MpsaDriver`). Mechanical
  port of ~200 LoC once R26b lands.
- **Quantitative bandwidth/latency comparison** vs OSN cascade on real
  network. Bench harness is straightforward once the wire integration
  exists; out of scope for the simulator round.

## References

- Chase, Ghosh, Poburinnaya. "Secret-Shared Shuffle." ASIACRYPT 2020.
- Eskandarian, Boneh. "Clarion: Anonymous Communication from Multiparty
  Shuffling Protocols." NDSS 2022. (Generalizes CGP to N parties.)
- Boyle, Couteau, Gilboa, Ishai. "Compressing Vector OLE." ACM CCS 2018.
  (Tunable preprocessing).
