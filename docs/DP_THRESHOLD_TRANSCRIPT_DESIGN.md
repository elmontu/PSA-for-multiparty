# DP-cardinality, Threshold-k, Signed Transcript: Design

Three small but theoretically substantive improvements shipped in the same
round. Each closes a different audit / privacy concern.

## T10: Threshold-k Revelation (`-mink K`)

### What

SP aborts the protocol if `|I| < K`. SP commits to `K` BEFORE running MPSI
(prototype: via the `-mink` CLI arg; production: via an audit-log entry).

### Why

- **k-anonymity-style policy.** If a query returns fewer than `K` matching
  records, the result is too small to be safely released without
  re-identification risk. Standard practice in PDPA-compliant cohort
  selection (e.g., MOH's k=10 default for population health queries; MAS
  segments rarely below k=20).
- **Cheap to add.** ~20 LoC in `MpsaDriver::runSpRole`.

### What it does NOT provide

- Doesn't HIDE `|I|` from SP. SP literally measures `|I|` to enforce the
  threshold. For full hiding, combine with `-cmax` or oblivious MPSI
  (see `CARDINALITY_HIDING_DESIGN.md`).
- Doesn't bind SP to actually enforcing it. Prototype trusts the SP code
  path; production should log the threshold to an audit trail before
  MPSI starts and the audit log should be verifiable.

### CLI

```
frontend -mpsa -N 3 -r 0 -mink 50 ...
```

If `|I| < 50`, SP throws and the protocol aborts.

---

## T8: DP-Protected Cardinality Release (`-dp <epsilon>`)

### What

SP computes the true cardinality `C` internally for the protocol's
own needs (intersection processing, padding), but publishes a noisy
`C̃ = C + Lap(1/ε)` to any external observer. This gives a formal
**(ε, 0)-DP** guarantee on the cardinality output.

The noise is from the Laplace mechanism: sample `U ~ Uniform(-½, ½)`,
output `noise = -sign(U) · (1/ε) · ln(1 - 2|U|)`.

### Why

- **Cardinality is the most useful aggregate** when the joined table
  itself is sensitive. Health-research queries often only need
  "how many patients matched?" — and that count alone is enough to
  re-identify under linkage attacks if released exactly.
- **Composition across runs.** If the same senders run MPSA repeatedly
  (e.g., monthly cohort), `(C_1, ..., C_T)` is a time series. With per-run
  ε, total privacy cost is `T · ε` (basic composition) — bounded and
  trackable.
- **Real provable guarantee.** Laplace mechanism is the textbook DP
  primitive; security argument is two lines and dates to Dwork et al.
  2006.

### What it does NOT provide

- **Doesn't hide C from senders or SP** (they see the real C internally;
  the noise is only on the EXTERNAL release).
- **Doesn't hide the joined table.** The N-column CSV is unchanged. To
  also DP-protect the table, add Laplace noise to each (numeric) cell —
  but our payloads are opaque blocks, so this would require a typed-DP
  variant outside scope.
- **Composition accounting** is in code-comment form only; production
  should track per-organization ε spend in a privacy ledger.

### CLI

```
frontend -mpsa -N 3 -r 0 -dp 0.5 -v ...
```

Logs:
```
[SP] DP-cardinality: epsilon=0.5 noisyC=99.0791 (real C=100 kept internal)
```

### Roadmap

- (½ day) Write `noisyC` to a separate file `out_dp_card.csv` for downstream.
- (½ day) Privacy ledger: persist (timestamp, query_id, ε, organization) to
  a JSON log per run for composition tracking.
- (research) Tight composition via RDP (Mironov ZKP 2017) or
  Gaussian-DP (Dong et al. NeurIPS'19).

---

## T11: Signed Transcript for Non-Repudiation

### What

Each party maintains an append-only hash transcript of every observable
protocol message (send + recv). At protocol end, the party signs the
transcript digest under its long-term Ed25519 keypair. A verifier with
access to the signed digest can:

1. Verify the signature was produced by the claimed party.
2. Replay the protocol against its own transcript and check consistency.
3. Attribute any deviation to a specific party.

### Why

- **CCoP 2.0 audit trail.** Singapore's CSA CCoP 2.0 requires
  demonstrable cyber-event logs for CII operators. A cryptographically
  signed protocol transcript is one form (the other being immutable
  CloudWatch/CloudTrail logs).
- **MAS Notice 644 / 655 cyber-hygiene + outsourcing.** Financial
  institutions outsourcing MPC must demonstrate that they can prove
  what happened in a multi-party computation if a dispute arises.
- **Composes with the malicious-cascade design** (`MALICIOUS_CASCADE_DESIGN.md`):
  per-share MAC tags catch deviations DURING the protocol; the signed
  transcript catches deviations AFTER, with cryptographic attribution.

### Construction

- Library: libsodium's `crypto_sign_*` (Ed25519). Already linked.
- New module: `volePSI/MpTranscript.{h,cpp}` with `record(label, data)`,
  `digest()`, `sign(sk)`, and `verify(digest, sig, pk)`.
- Wire format per record: `u32_be(label_len) | label | u32_be(data_len) | data`.
- Final digest: `RandomOracle("mptranscript.v1" || serialized_records)` → 32 bytes.

### Current scope (prototype)

- SP records `session_id` + final `Ceff`. Signs with a fresh Ed25519
  keypair (logged signature prefix in `-v` mode).
- Production needs:
  - **Long-term Ed25519 identities** distributed out-of-band (PKI,
    cert pinning, or trusted directory).
  - **Per-message recording** (every send/recv) for full deviation
    attribution.
  - **Append to an immutable log** (S3 Object Lock, CloudWatch Logs
    with KMS-encrypted retention).

### Effort to production

- Long-term key management + cert distribution: ~1 day + KMS plumbing.
- Per-message hooks in MpStarChannel / MpSpHandshake / MpStarSetup /
  MpShuffleDriver: ~½ day; LOG-style instrumentation.
- Audit-log sink (S3 Object Lock writer): ~½ day.

### What it does NOT provide

- **Doesn't prevent attacks.** Only post-hoc attribution. Pair with the
  malicious cascade for prevention.
- **Doesn't survive party compromise after the fact.** Once an attacker
  has a party's long-term Ed25519 sk, they can sign anything. Mitigate
  with timestamping (CT-style log) and short-lived sub-keys.

---

## Composition with the protocol

| Round | Layer | Status | When useful |
|---|---|---|---|
| 17 | `-cmax` padding | shipped | external observers see noisy row count |
| **18** | `-pq` hybrid handshake | shipped (StubKem) | HNDL adversary |
| **20** (T10) | `-mink` threshold | shipped | k-anonymity policy |
| **20** (T8) | `-dp` cardinality | shipped | privacy-accounted cardinality release |
| **21** (T11) | Signed transcript | shipped (SP-side, lightweight) | post-hoc audit, CCoP 2.0 |
| (future) | Full per-message transcript hooks | designed | full deviation attribution |
| (future) | Malicious cascade (info-theoretic MACs) | designed | prevent (not just detect) sender misbehavior |

The combined CLI for a deployment-tier run:

```
frontend -mpsa -N 3 -r 0 \
    -pq                  # hybrid handshake (real KEM when liboqs wired)
    -cmax 1024           # hide exact C from output observers
    -mink 50             # abort if <50 matches (k-anon policy)
    -dp 0.5              # release Laplace-noisy C̃ for accounting
    -out result.csv
```

Each flag is orthogonal; composing them doesn't introduce new privacy
loss beyond the per-layer guarantees.

## References

- Dwork, C., McSherry, F., Nissim, K., Smith, A. (2006).
  **Calibrating Noise to Sensitivity in Private Data Analysis.** TCC 2006.
  The Laplace mechanism.
- Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., Yang, B.-Y. (2012).
  **High-speed high-security signatures.** Journal of Cryptographic
  Engineering. Ed25519.
- Mironov, I. (2017). **Rényi Differential Privacy.** IEEE CSF 2017. Tight
  composition for repeated DP releases.
- Dong, J., Roth, A., Su, W. J. (2019). **Gaussian Differential Privacy.**
  NeurIPS 2019. Alternative composition framework.
- Office of the Privacy Commissioner Singapore, **Anonymisation Guide**,
  2nd Edition (2024). k-anonymity guidance.
- CSA Singapore, **Cybersecurity Code of Practice for CII (CCoP 2.0)**,
  Rev 1 (2024). Cyber-event log retention requirements.
