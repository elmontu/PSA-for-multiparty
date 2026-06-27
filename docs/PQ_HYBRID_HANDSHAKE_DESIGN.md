# Post-Quantum Hybrid Handshake: Design

This doc covers the **hybrid X25519 + post-quantum KEM** handshake used to
derive the per-session sender↔SP keys. Round 18 ships the protocol framework
with a `StubKem` placeholder so the wire format and KDF combiner are
end-to-end testable today; this doc specifies the real ML-KEM-768 swap-in.

## Why hybrid?

Single-primitive options:

| Choice | Confidentiality if X25519 broken | Confidentiality if ML-KEM broken |
|---|---|---|
| X25519 only (current default) | ❌ | ✓ |
| ML-KEM only | ✓ | ❌ |
| **Hybrid X25519 + ML-KEM** | **✓** | **✓** |

Hybrid mode gives **defence in depth**: the session key remains secure as
long as at least ONE of the two primitives is secure. This is the same
rationale TLS 1.3 hybrid PQ deployments use (e.g.
`X25519MLKEM768` in IETF draft-ietf-tls-ecdhe-mlkem).

For our threat model — long-term confidentiality of joined-table outputs
against a "harvest now, decrypt later" adversary — hybrid is the right
default once real KEM is wired in.

## Wire protocol (already shipped)

Per (SP, sender_i) pair on `spSock`, in order:

```
SP    → sender:  x25519_pk_sp        (32 bytes)
SP    → sender:  kem_pk_sp           (KEM publicKeyBytes)
sender → SP:     x25519_pk_sender    (32 bytes)
sender → SP:     kem_ct              (KEM ciphertextBytes; sender's encap to SP's pk)
```

The SP-sends-first ordering matches `MpSpHandshake` and avoids the
classical deadlock at session start.

Both ends then derive:
```
x25519_ss   = X25519(scalarmult)             ← 32 bytes
kem_ss      = KEM.decap (SP) / KEM.encap-output (sender)  ← KEM sharedSecretBytes
session_key = RandomOracle(
    "mphybrid.v1" ‖ x25519_ss ‖ kem_ss ‖ uint32_be(senderIdx)
) → 32 bytes
```

Domain separation via `"mphybrid.v1"` plus `senderIdx` ensures each pair gets
a distinct key even with identical secret material.

## Concrete Kem swap-in (this is what to do)

The `volePSI::mpstar::Kem` interface (in `volePSI/MpKem.h`) is intentionally
minimal:

```cpp
struct Kem {
    virtual size_t publicKeyBytes()    const = 0;
    virtual size_t secretKeyBytes()    const = 0;
    virtual size_t ciphertextBytes()   const = 0;
    virtual size_t sharedSecretBytes() const = 0;
    virtual void keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) const = 0;
    virtual void encap(const std::vector<uint8_t>& peer_pk,
                       std::vector<uint8_t>& ct,
                       std::vector<uint8_t>& ss) const = 0;
    virtual void decap(const std::vector<uint8_t>& ct,
                       const std::vector<uint8_t>& sk,
                       std::vector<uint8_t>& ss) const = 0;
};
```

`MpHybridHandshake::runSp` and `runSender` take any `Kem const&`. Round 18
ships `StubKem` (constant zeros, NOT SECURE — emits a stderr warning).

### Option 1: liboqs (recommended)

[**liboqs**](https://github.com/open-quantum-safe/liboqs) is the
Open-Quantum-Safe project's library — actively maintained, has FIPS-203
ML-KEM-512/768/1024, BSD-3-Clause license.

**Integration steps:**

1. **Install liboqs** (system package on Ubuntu 24.10+:
   `apt install liboqs-dev`; or build from source, ~5 min).
2. **CMake**: add `find_package(liboqs CONFIG REQUIRED)` to `volePSI/CMakeLists.txt`
   and link the volePSI target against `OQS::oqs`.
3. **New file**: `volePSI/MpKemLiboqs.{h,cpp}` implementing `volePSI::mpstar::Kem`
   via `oqs::KeyEncapsulation`:

```cpp
#include <oqs/oqs.h>
class LiboqsMlKem768 : public volePSI::mpstar::Kem {
    OQS_KEM* kem_ = nullptr;
public:
    LiboqsMlKem768()  { kem_ = OQS_KEM_new(OQS_KEM_alg_ml_kem_768); }
    ~LiboqsMlKem768() { OQS_KEM_free(kem_); }
    std::string name() const override { return "ML-KEM-768 (liboqs)"; }
    size_t publicKeyBytes()    const override { return kem_->length_public_key; }
    size_t secretKeyBytes()    const override { return kem_->length_secret_key; }
    size_t ciphertextBytes()   const override { return kem_->length_ciphertext; }
    size_t sharedSecretBytes() const override { return kem_->length_shared_secret; }
    void keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) const override {
        pk.resize(kem_->length_public_key);
        sk.resize(kem_->length_secret_key);
        if (OQS_KEM_keypair(kem_, pk.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("liboqs keypair failed");
    }
    void encap(const std::vector<uint8_t>& peer_pk,
               std::vector<uint8_t>& ct,
               std::vector<uint8_t>& ss) const override {
        ct.resize(kem_->length_ciphertext);
        ss.resize(kem_->length_shared_secret);
        if (OQS_KEM_encaps(kem_, ct.data(), ss.data(), peer_pk.data()) != OQS_SUCCESS)
            throw std::runtime_error("liboqs encap failed");
    }
    void decap(const std::vector<uint8_t>& ct,
               const std::vector<uint8_t>& sk,
               std::vector<uint8_t>& ss) const override {
        ss.resize(kem_->length_shared_secret);
        if (OQS_KEM_decaps(kem_, ss.data(), ct.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("liboqs decap failed");
    }
};
```

4. **Plumb into MpsaDriver**: in `doFileMpsa`, when `-pq` is set, use
   `LiboqsMlKem768` instead of `StubKem`. ~3 LoC change.
5. **Test**: run `tests/run_mpsa_smoke.sh` with `frontend -mpsa -pq ...`.
   With real KEM the warning disappears and shared secrets are genuine.

**Effort: ~½ day** including the new file, CMake change, and smoke test.

### Option 2: pqcrystals/kyber (reference impl)

[**pqcrystals/kyber**](https://github.com/pq-crystals/kyber) is the
reference implementation by the algorithm designers. Smaller surface
(just ML-KEM); CMake integration is via direct add_subdirectory.

Similar steps as liboqs but with `crypto_kem_keypair`, `crypto_kem_enc`,
`crypto_kem_dec` from the reference C API. ~½ day.

### Option 3: BoringSSL or rustls integration

If the deployment already depends on BoringSSL or rustls, both ship
ML-KEM-768 in current versions. Wraps a C++ `Kem` over their APIs. ~½ day.

## Why per-protocol keys are still derived through this combiner

Even with a real ML-KEM in place, the KDF combiner serves three purposes:

1. **Domain separation** via the `"mphybrid.v1"` tag and `senderIdx_BE`
   suffix.
2. **Combiner correctness** — a KDF over `x25519_ss || kem_ss` is secure
   as long as either input has entropy, even if the other is fully
   compromised (standard hybrid KDF argument; see
   [hybrid-design BoringSSL note](https://www.imperialviolet.org/2024/01/15/postquantum.html)).
3. **Output uniformity** — `kem_ss` is already uniform, but the X25519
   shared secret is biased (it's a Curve25519 point coordinate); the KDF
   normalizes both to a uniform 32-byte session key.

## Forward secrecy

Both X25519 and ML-KEM keypairs in this prototype are ephemeral (generated
per protocol invocation in `runSp` / `runSender`). Each session gets fresh
keys; past sessions are forward-secret even if long-term party identities
are later compromised.

For deployments wanting long-term party identities (e.g. authenticated
hybrid), add per-party long-term Ed25519 + ML-DSA signatures over the
ephemeral pubkeys; specified in a future round.

## Threat model coverage matrix

| Adversary capability | Without `-pq` | With `-pq` (StubKem) | With `-pq` (real ML-KEM) |
|---|---|---|---|
| Passive eavesdropper | secure | secure | secure |
| Active MITM on spSock | detected on AEAD | detected on AEAD | detected on AEAD |
| Future X25519 break (post-quantum CRQC) | **broken** | **broken** | **secure** |
| Future ML-KEM break (cryptanalysis) | secure | **broken** | secure |

The middle column (`-pq` with StubKem) gives the wire-protocol structure
but no PQ security. It's a CI smoke-test mode for the framework, NOT a
deployment mode.

## Composition with the rest of the protocol

The session key returned by `MpHybridHandshake::runSender` / `runSp`
plugs into the existing `volePSI::mpstar::deriveSessionKey` step exactly
where `MpSpHandshake`'s key did. All downstream layers (AEAD on masked
columns, AEAD on `rho_k`, AEAD on final reveal, peer-mesh `MpStarSetup`
keys derived from `setup.key(j)`) continue to work unchanged.

`MpStarSetup` (sender↔sender peer-mesh keys) is currently X25519-only.
To make the full handshake hybrid, also add a Kem exchange to
`MpStarSetup`. The pattern is identical to `MpHybridHandshake` and
applies to N(N-1) more keypairs per session. Effort: ~1 day.

## References

- NIST FIPS 203 (2024): **Module-Lattice-Based Key-Encapsulation Mechanism Standard.**
- Schwabe et al. (2024): **CRYSTALS-Kyber.** Original construction.
- Bernstein et al. (2014): **TweetNaCl: A crypto library in 100 tweets.** X25519 reference.
- IETF draft-ietf-tls-ecdhe-mlkem (2025): **Post-quantum hybrid key exchange for TLS 1.3.** The standard wire format for hybrid X25519+ML-KEM.
- Stebila & Mosca (2017): **Post-quantum key exchange for the internet and the open quantum safe project.** Background on the OQS project.
- Bindel et al. (2019): **Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange.** Security proofs for the hybrid KEM combiner.
