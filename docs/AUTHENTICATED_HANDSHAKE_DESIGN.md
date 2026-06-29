# Authenticated Handshake: Design

T14 of the multi-improvement plan. Closes the MITM-forward-pubkey attack on
the ephemeral handshake by requiring parties to authenticate their session
material with long-term Ed25519 identities.

## The attack T14 defends against

Without T14, the ephemeral DH (X25519 in `MpSpHandshake`, X25519+KEM in
`MpHybridHandshake`) authenticates only the SESSION KEY's confidentiality
— it doesn't authenticate WHO the peer is. An on-path adversary can:

1. Intercept the ephemeral pubkey from SP.
2. Replace it with their own ephemeral pubkey.
3. Establish DH with each sender independently.
4. Decrypt-then-re-encrypt everything in flight.

The senders can't tell because nothing in the protocol commits SP to a
specific long-term identity.

## What T14 ships

### Module: `volePSI/MpIdentity.{h,cpp}`

- Long-term Ed25519 keypairs stored as `<authDir>/<id>.pk` (32B) +
  `<authDir>/<sk-filename>` (64B).
- `MpIdentity` class: load self pk+sk; load + cache peer pks; sign/verify
  detached messages via libsodium's `crypto_sign_*`.

### Helper mode: `-auth-genkey`

```
frontend -mpsa -auth-genkey -auth-dir <dir> -auth-id <name> -auth-sk <skfile>
```

Generates a fresh Ed25519 keypair and writes the .pk (which must be
distributed) and .sk (which the party keeps).

### Protocol mode: `-auth-dir <dir>`

When set on both SP and senders, the protocol runs a sessionId-signing
exchange **before** the ephemeral DH:

```
SP    → senders:  sign_sp(sessionId)     (64 bytes, Ed25519 detached sig)
senders → SP:     sign_i(sessionId)       (64 bytes each)
```

Each sender verifies SP's sig against `sp.pk`; SP verifies each sender's
sig against `sender_<i>.pk`. Mismatch → abort.

After this, the regular DH handshake proceeds. Because the sessionId is
fresh per session and signed by a long-term identity, a MITM cannot
substitute its own DH ephemeral without also signing the sessionId —
which it can't without the long-term sk.

## What this prototype does NOT do

- **Doesn't sign the ephemeral DH pubkey itself.** Currently signs only
  the sessionId. A more careful protocol (TLS 1.3 style) would sign
  `H(transcript_so_far)` after the ephemeral DH messages have been
  exchanged, binding the long-term identity to the specific session DH
  state. Effort to upgrade: ~½ day.
- **Doesn't distribute pubkeys securely.** All parties assume access to a
  pre-populated `<authDir>` containing every other party's .pk. Real
  deployment needs a registry (e.g., Singapore GovTech's CertSG PKI,
  HashiCorp Vault, an internal CA, or DNSSEC TLSA records).
- **Doesn't rotate keys.** Long-term keys are forever (until the .sk
  file is regenerated). Production should support key rotation with
  validity windows and a revocation mechanism.
- **Doesn't sign sender↔sender peer-mesh setup.** Only SP↔sender
  handshake is authenticated. Senders could MITM each other's
  `MpStarSetup` X25519 exchange. Extension: same `sign_i(sessionId)`
  pattern over the peer-mesh sockets. ~½ day.

## What T14 closes vs leaves open

| Attack | Without T14 | With T14 |
|---|---|---|
| Passive eavesdropper on spSock | secure (DH protects content) | secure |
| MITM substitutes ephemeral pubkey | **breaks confidentiality** | **detected: sig fails** |
| MITM compromised a sender's long-term sk | breaks confidentiality | **breaks confidentiality** (limit: rotate keys + revoke) |
| Network drops, reorders packets | AEAD detects on later layers | AEAD detects on later layers |
| Sender lies about its OWN identity (e.g., sender_5 pretends to be sender_0) | undetected | **detected** (sig over wrong .pk) |

## Composition with PQ-hybrid handshake

`-auth-dir` and `-pq` are orthogonal:

- `-pq` defends against future-CRQC adversary on the DH itself
- `-auth-dir` defends against MITM via long-term-identity binding

Together they give **defence in depth**: even if both X25519 AND ML-KEM
are broken in the future, the sessionId sig under Ed25519 still
authenticates (until Ed25519 is also broken — at which point switch to
ML-DSA / SLH-DSA via the same `MpIdentity` interface).

For full PQ-authenticated handshake: extend `MpIdentity` to also hold an
ML-DSA-65 keypair via liboqs; co-sign messages with both Ed25519 (now)
and ML-DSA (HNDL-resistant). Pattern identical to the hybrid KEM in
`PQ_HYBRID_HANDSHAKE_DESIGN.md`. ~½ day.

## Composition with the transcript sig (T11)

T11 signs the protocol TRANSCRIPT at end-of-protocol for non-repudiation.
T14 signs the SESSION ID at start-of-protocol for MITM detection. Both
use the same `MpIdentity` keypair (or could use different ones, e.g.,
session-binding vs audit-trail keys). For a CCoP 2.0 deployment, both
signatures should be archived together as the immutable audit log entry
for the run.

## Effort summary (production-grade)

| Item | Status | Effort |
|---|---|---|
| `MpIdentity` module + `-auth-genkey` | DONE (R22) | shipped |
| `-auth-dir` sessionId sign+verify | DONE (R22) | shipped |
| Sign full transcript hash (not just sessionId) | future | ~½ day |
| Sign peer-mesh MpStarSetup handshake too | future | ~½ day |
| Long-term key rotation + revocation | future | 1-2 days |
| Registry/PKI distribution (CertSG / Vault / DNSSEC) | future | deployment-specific |
| Hybrid ML-DSA + Ed25519 signatures (PQ-resistant) | future | ~½ day |

## References

- Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., Yang, B.-Y. (2012).
  **High-speed high-security signatures.** Ed25519.
- Rescorla, E. (2018). **The Transport Layer Security (TLS) Protocol
  Version 1.3.** RFC 8446. Authenticated handshake pattern (signs the
  full transcript with long-term identity).
- NIST FIPS 204 (2024). **Module-Lattice-Based Digital Signature
  Standard (ML-DSA).** Post-quantum signature scheme; drop-in companion
  to ML-KEM for PQ-authenticated handshake.
- CSA Singapore CertSG (Government Digital Identity / National Digital
  Identity infrastructure) — possible PKI bootstrap for Singapore
  government deployments.
