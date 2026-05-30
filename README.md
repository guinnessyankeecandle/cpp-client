# SecureMsg C++ Client

A terminal UI secure messaging client implementing the full Signal Protocol with post-quantum cryptography.

## What it does

- **PQXDH session establishment** — hybrid X25519 + ML-KEM-1024 key agreement. Both primitives must be broken to compromise a session. Protects against harvest-now-decrypt-later attacks.
- **Double Ratchet messaging** — per-message forward secrecy (symmetric ratchet) and break-in recovery (DH ratchet). Ratchet headers are encrypted to hide session progression from the server.
- **Group messaging** — Signal Sender Key protocol. O(1) encryptions per group message regardless of group size.
- **SRP-6a authentication** — zero-knowledge password proof (4096-bit group, SHA-256). The server never sees your password. Mutual proofs detect MITM attacks.
- **TOTP 2FA** — required on every login.
- **All crypto via OpenSSL 3.5** — no hand-rolled primitives.

## Build and run

```bash
./start.sh
```

This installs all dependencies, compiles, and launches the app. Requires `sudo` on first run to install packages.

## Dependencies

| Package (Fedora/dnf) | Package (Debian/apt) | Purpose |
|---|---|---|
| `gcc-c++` | `g++` | C++23 compiler |
| `cmake` | `cmake` | Build system |
| `make` | `make` | Build tool |
| `ninja-build` | `ninja-build` | Required generator for C++20 modules |
| `clang` | `clang` | Clang compiler (CI / coverage builds) |
| `openssl-devel` | `libssl-dev` | All crypto: AES-GCM, Ed25519, X25519, ML-KEM-1024, HKDF, PBKDF2, SRP |
| `libcurl-devel` | `libcurl4-openssl-dev` | HTTPS API calls |
| `nlohmann-json-devel` | `nlohmann-json3-dev` | JSON parsing |
| `ftxui-devel` | `libftxui-dev` | Terminal UI framework |
| `catch2-devel` | `catch2-dev` | Unit test framework |
| `qrencode` | `qrencode` | TOTP QR code rendering in terminal |
| `glibc-devel` | `linux-libc-dev` | System headers required by GCC 16 |
| `kernel-headers` | _(included above)_ | Kernel headers required by GCC 16 |

## Cryptographic design

### Key hierarchy

```
Identity Key (IK)     Ed25519  — signs prekeys; proves sender identity
Signed Prekey (SPK)   X25519   — signed by IK; rotated periodically
One-Time Prekeys      X25519   — consumed one per session; replenished when < 10 remain
PQ Prekey             ML-KEM-1024 — signed by IK; post-quantum forward secrecy
```

All keys are stored encrypted in `identity.key` using AES-256-GCM with a key derived from your login password via PBKDF2-HMAC-SHA256 (600,000 iterations, OWASP 2023). **Key generation is fully automatic** — on first login the full bundle (Ed25519 IK, X25519 SPK + 20 OPKs, ML-KEM-1024 PQ prekey) is generated, encrypted, saved, and published to the server without any user interaction.

### PQXDH session establishment

Hybrid key agreement combining X25519 and ML-KEM-1024, following the [Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/).

**Sender side:**
1. Verify recipient's SPK and PQ prekey signatures against their Ed25519 identity key
2. Generate ephemeral X25519 key pair `EK`
3. Compute four X25519 DH values:
   ```
   DH1 = X25519(sender_IK,  recipient_SPK)   — authenticates sender
   DH2 = X25519(sender_EK,  recipient_IK)    — forward secrecy
   DH3 = X25519(sender_EK,  recipient_SPK)   — binds ephemeral to SPK
   DH4 = X25519(sender_EK,  recipient_OPK)   — one-time key (if available)
   ```
4. Encapsulate ML-KEM-1024: `(pq_ciphertext, pq_ss) = ML-KEM.Encap(recipient_pq_pub)`
5. Derive session key:
   ```
   IKM = 0xFF×32 || DH1 || DH2 || DH3 || DH4 || pq_ss
   SK  = HKDF-SHA256(IKM, salt="", info="PQXDH-v1")
   ```

**Why `0xFF×32` prefix?**
The 32-byte `0xFF` binder is prepended to the IKM per the Signal PQXDH spec. It prevents a downgrade attack where an adversary tricks a PQXDH client into completing a classical X3DH exchange instead — the binder makes the two protocols' IKM values structurally incompatible.

**Why `info="PQXDH-v1"`?**
The HKDF `info` parameter provides domain separation. Even if two different protocol versions or key purposes derived keys from the same IKM, the different `info` string guarantees different output keys. This prevents cross-protocol key confusion attacks.

**Why no explicit salt?**
HKDF-SHA256 defaults to a zeroed 32-byte salt when none is provided — an explicit `0x00×32` salt is identical and adds nothing. The security of HKDF comes from the IKM entropy (5 DH/KEM outputs), not the salt.

6. Seed Double Ratchet with `SK`

**Receiver side verification:**

Before deriving the session key, the receiver:
1. Checks the **local identity cache** (`known_identities.json`) for the sender's stored Ed25519 public key — the server is only consulted the very first time a sender is seen (TOFU). A locally cached key is always trusted over the server.
2. Verifies `sender.IK_pub` in the header matches the cached key — rejects and warns if not
3. Verifies the `used_opk_id` corresponds to an OPK they actually generated — rejects if unrecognised
4. Recomputes DH1–DH4 and decapsulates ML-KEM symmetrically
5. Derives `SK` — if the subsequent AEAD decryption succeeds, the sender's identity is implicitly confirmed (a forged `IK_pub` would produce the wrong `SK` and fail authentication)

**Verifying identity out-of-band:**

Press `i` on any conversation to view the contact's Ed25519 identity public key. Compare it with the contact directly (voice call, in person) to confirm no MITM is present. Once verified, mark it as trusted — a checkmark appears next to their name. If a key mismatch is ever detected, a red warning is shown with the old and new keys side by side.

### Double Ratchet

Provides per-message forward secrecy and break-in recovery. Ratchet headers (`ratchet_header_enc`) are encrypted to hide session state from the server.

- **Symmetric ratchet** — chain key advances per message; each message uses a unique key. Compromise of one message key exposes no others.
- **DH ratchet** — root key advances when the remote party sends a new DH ratchet key. Limits the window of exposure after a key compromise.

### Security properties

| Property | Mechanism |
|---|---|
| Password never sent | SRP-6a zero-knowledge proof |
| Server can't read messages | E2E encryption; server stores ciphertext only |
| Post-quantum forward secrecy | ML-KEM-1024 in PQXDH; both X25519 and ML-KEM must be broken |
| Per-message forward secrecy | Double Ratchet symmetric chain |
| Break-in recovery | Double Ratchet DH ratchet |
| Prekey authenticity | Ed25519 signatures on SPK and PQ prekey |
| Timing-safe comparisons | `CRYPTO_memcmp` for all MAC/proof/hash comparisons |
| Secure key zeroing | `OPENSSL_cleanse` on all sensitive buffers |
| Memory safety | No raw owning pointers; RAII for all OpenSSL handles |

### Cryptographic security levels

| Primitive | Classical | Post-quantum |
|---|---|---|
| AES-256-GCM | 256-bit | 128-bit (Grover) |
| X25519 | 128-bit | Broken by Shor |
| ML-KEM-1024 | 256-bit | 128-bit |
| X25519 + ML-KEM-1024 hybrid | 128-bit | 128-bit (both must break) |
| Ed25519 | 128-bit | Broken by Shor |
| SRP-6a (4096-bit) | ~140-bit | Broken by Shor |
| HKDF-SHA256 | 128-bit | 128-bit |

## Code structure

```
src/securemsg/
  crypto/      — random, aead, kdf, ed25519, x25519, mlkem, pqxdh, ratchet, keystore, srp
  network/     — http (CURL), api (all endpoints)
  messaging/   — message model, store, send/receive pipeline
  models/      — user, group
main.cpp       — FTXUI terminal UI only
```

Each module has a co-located `.test.cpp` file. Run tests with:

```bash
cmake --preset ci && cmake --build --preset ci && ctest --test-dir build
```

## Known limitations

See [Backend.md](Backend.md) — Known Limitations section. Key points: no sealed sender (server sees social graph), TOFU trust model, Ed25519 and SRP-6a are not post-quantum resistant.
