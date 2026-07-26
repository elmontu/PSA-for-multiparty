# Deployment plan: both-blind XOR-shared control in vendored MPSICS

Session 9 finding + multi-session refactor plan.

## Where the "matcher knows everything" problem actually lives

The row-level cascade shuffle (`volePSI/MpShuffleDriver.cpp`) is fine.
Each round is driven by a different sender who picks a fresh private
routing seed post-A1 fix. SP never learns any round's routing.
Session 4/5's both-blind would not add security here (see session 9 note).

The scalar-output OIRA path (`volePSI/MpOira.cpp`) delegates aggregation
to vendored MPSICS at `volePSI/upstream/mpso/mpso/MPSICS.cpp`. Inside
MPSICS, two `MShuffleParty64` instances (one XOR for indicator, one ADD
for value sum) run an N-party shuffle where **each party i holds a full
permutation `mPi[i]`** loaded from offline files (`getShareCorrelation`).

That IS the "single-server per round" model session 4/5 was designed to
improve: corrupt party i alone leaks its round's `mPi[i]`.

## Proposed refactor: XOR-split each round's permutation

For each MShuffle round i (0 ≤ i < N):
- Currently: party i holds `mPi[i]`, applies `permute64(mPi[i], z)` in
  their turn of the sequential protocol.
- Proposed: `mPi[i] = beta_i ∘ alpha_i` where alpha_i is held by party i
  and beta_i by SP (party 0 in the current mapping, since P_0 is the
  cardinality/sum receiver anyway).
  - Party i applies alpha_i locally to their z.
  - Then SP applies beta_i obliviously (via OSN).
  - Net effect: `permute64(mPi[i], z)` computed as (beta_i ∘ alpha_i)(z),
    no single party holding the composite.

Coalition impact vs current:
- Corrupt party i alone: currently leaks mPi[i]; post-refactor leaks
  only alpha_i (half of mPi[i], one bit per switch decision).
- Corrupt SP alone: currently learns nothing about any mPi[k];
  post-refactor learns beta_k for every k, half of each round's routing.
- Corrupt SP + party i: currently learn mPi[i]; post-refactor also learn
  mPi[i] (they combine alpha_i XOR beta_i).
- All coalitions strictly at least as leaky as before for SP+party pairs;
  strictly less leaky for lone party.

**Verdict:** trade-off. Party-i-alone gets stronger; SP-alone weakens
(from "learns nothing" to "learns half of all rounds"). Whether this is
a net improvement depends on threat model: is corrupt SP or corrupt
individual sender more likely?

For MAS SupTech: SP = MAS, senders = banks. Corrupt bank (single) is
plausibly more likely than corrupt MAS. Refactor helps.

## Multi-session plan

| Session | Deliverable | Files touched | Risk |
|---|---|---|---|
| 10 | Add `betaShare` parameter to `MShuffleParty64::runXOR/runADD`; if provided, apply after party's own mPi | `MShuffle.h`, `MShuffle.cpp` | Low — new parameter, backward-compat with nullptr |
| 11 | Add `betaGen` to `ShareCorrelationGen.cpp` — generate paired alpha/beta permutations whose composition equals the original mPi | `ShareCorrelationGen.cpp` | Medium — offline correlation format changes |
| 12 | Wire OSN-based application of SP's beta in MShuffleParty64 (needs live socket to SP) | `MShuffle.cpp` | High — new inter-party socket, changes flow |
| 13 | Wire the split into `MPSICS.cpp` for both shuffleParty1 (XOR) and shuffleParty2 (ADD) usage | `MPSICS.cpp` | Medium — MPSICS calls change signature |
| 14 | End-to-end test via `oira_probe` — verify aggregate output unchanged, verify SP+party recovery still works but party-alone doesn't | `tests/unit/oira_probe.cpp` | Low — testing |
| 15 | Multi-agent audit (Gemini) of the full change; performance benchmarks (Session 5's ~12 MB projection at m=1024) | test infrastructure | Low — audit |

Total: 6 sessions, mostly medium/high risk in vendored code.

## Alternatives worth reconsidering

1. **Keep MPSICS as-is; apply session 4/5 only to future new protocols.**
   Cost: 0. Value: prevents future single-server designs.

2. **Formalize the CASCADE's coalition properties in the paper instead.**
   The deployed cascade already achieves (N-1)-of-N coalition security.
   That's a stronger result than session 4/5's 2-of-3, worth publishing.
   Cost: 1-2 sessions of writing. Value: paper contribution.

3. **Two-server ρ_2 for top-N tier only, if that tier is deployed.**
   Row-level attribution for "top firms" output. Would need to first
   check whether this tier exists as a separate code path.

## Recommendation (revised session 9)

The heavy MPSICS refactor is technically justified against the threat
model of "corrupt individual bank," but it's 6 sessions of invasive
work into vendored code with modest security gains (SP-alone learns
strictly more, party-alone learns strictly less).

Before starting, worth checking:
- Is there a concrete MAS threat scenario where corrupt-sender-alone
  matters more than corrupt-SP-alone?
- Would MAS accept the added SP knowledge (SP=MAS itself, so MAS learns
  more about routing internals)?
- If the answer is "no strong preference," session 9 recommendation
  becomes alternative 2 (formalize cascade properties in paper).

If yes, proceed with sessions 10-15 as outlined.
