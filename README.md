# SecureMsg C++ Client

A command-line secure messaging client for the CS4455 Epic project.

## What it does

- Registers and logs in using **SRP-6a** zero-knowledge password authentication (2048-bit group, SHA-256)
- Encrypts messages end-to-end with **AES-256-GCM** using keys derived via a simplified **HPKE Mode_Auth** key exchange (X25519 static + ephemeral DH → HKDF-SHA256)
- Sends and receives encrypted messages over **HTTPS** using libcurl (TLS certificate verification enabled)
- Stores the local X25519 identity key encrypted at rest (**PBKDF2-HMAC-SHA256**, 600,000 iterations + AES-256-GCM)

## Dependencies

| Library | Purpose |
|---|---|
| OpenSSL ≥ 1.1.0 | AES-GCM, X25519, HKDF, SRP bignum arithmetic, PBKDF2 |
| libcurl | HTTPS API calls |
| nlohmann/json | JSON (fetched automatically by CMake via FetchContent) |

Install system packages (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev libcurl4-openssl-dev git
```

## Build

```bash
cd cpp-client
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The binary is at `build/securemsg`.

## Run

```bash
./build/securemsg
```

By default the client connects to `https://drop-table.theburkenator.com`.
To point at a different backend edit the `BASE_URL` constant in [src/main.cpp](src/main.cpp#L14).

If you are testing locally with a self-signed certificate, set `verifyTls = false` in [src/main.cpp](src/main.cpp#L242).

## Usage

```
=== SecureMsg C++ Client ===
  1) Register
  2) Login
  0) Quit
```

1. **Register** — enter a username and password.  The SRP verifier is computed locally; the plaintext password is never sent.  After registration, scan the TOTP URI in an authenticator app (Google Authenticator, Authy, etc.).

2. **Login** — SRP-6a three-step handshake (init → proof → TOTP).  Both sides verify each other's proofs.  After login, choose a passphrase to protect your local identity key.

3. **Publish my public key** — uploads your X25519 identity public key to the server so others can send you encrypted messages.

4. **Send message** — fetches the recipient's public key, performs X25519 DH, derives a message key via HKDF, and encrypts with AES-256-GCM.  The ephemeral public key is sent alongside the ciphertext so the recipient can reproduce the shared secret.

5. **Fetch & decrypt messages** — downloads ciphertexts, recovers the message key using your private key and the sender's public key, and decrypts each message.

6. **Acknowledge receipt** — sends a receipt to the server, which deletes the server-side copy of the message.

7. **Revoke a sent message** — uses the single-use revocation token to delete a message before it is read.

## Code structure

```
include/
  User.hpp          — user model (id, username, tokens)
  Message.hpp       — message model (ciphertext, direction, plaintext after decrypt)
  MessageStore.hpp  — local message cache (std::vector + std::unordered_map for O(1) lookup)
  ApiClient.hpp     — HTTP client (libcurl, all API endpoints)
  CryptoManager.hpp — all crypto: AES-GCM, X25519, HKDF, SRP-6a, PBKDF2

src/
  main.cpp          — interactive CLI
  User.cpp
  Message.cpp
  MessageStore.cpp
  ApiClient.cpp
  CryptoManager.cpp
```

## Key design decisions

**AES-256-GCM** — standard AEAD; IV is 12 random bytes per message generated via `RAND_bytes`.  The packed wire format is `IV[12] | TAG[16] | CIPHERTEXT`.

**X25519 + HKDF-SHA256 key exchange** — simplified HPKE Mode_Auth.  Per-message IKM = `DH(senderStatic, recipientStatic) || DH(senderEphemeral, recipientStatic)`.  The static component authenticates the sender; the ephemeral component provides per-message forward secrecy.

**SRP-6a** — 2048-bit RFC 5054 group, SHA-256.  Client computes `v = g^x mod N` locally during registration.  During login both parties exchange mutual proofs; a wrong proof terminates the session.

**PBKDF2-HMAC-SHA256 / 600,000 iterations** — protects the local X25519 private key at rest.  Follows OWASP 2023 recommendation for PBKDF2-SHA256.
