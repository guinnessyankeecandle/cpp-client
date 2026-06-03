# Cryptographic Design Document — SecureMsg C++ Client

## 1. Threat Model

### 1.1 Passive Network Attacker

An attacker who can read all traffic between clients and server — for example, an ISP, a compromised router, or a surveillance system with visibility over the network path.

**What this attacker can observe:**

- The source and destination IP addresses of every connection — they know a client at IP X is communicating with the server at `BobbyTables.theburkenator.com`.
- TLS handshake metadata: the server's hostname (SNI field), certificate, and cipher suite negotiated.
- The size and timing of every request and response: how many bytes were exchanged, when, and how often. A passive observer who cannot read content can still infer that a user is actively messaging (frequent small bursts), or sent a large file (single large request). Message length leaks information about plaintext length even through encryption, since ciphertext size is plaintext size + a small fixed overhead.
- If monitoring traffic to/from the server for all users: the attacker can correlate connection timing to infer who is talking to whom — Alice connects and sends 400 bytes, Bob connects one second later and receives 400 bytes, suggesting a message from Alice to Bob.

**Properties that hold:**

- All transport traffic is TLS 1.2+, so the attacker observes only encrypted bytes. Certificate verification is enforced in `ApiClient` (`verifyTls = true`); connections to an unverified host are rejected.
- Even if TLS were stripped, message payloads are end-to-end encrypted under the Double Ratchet. The server only receives base64-encoded AES-256-GCM ciphertext and an encrypted ratchet header — plaintext is never present on the wire.
- Forward secrecy: each Double Ratchet step derives a fresh chain key and message key via HKDF. A passive observer who records traffic today gains nothing if they later obtain a session's root key, because prior message keys are already deleted.

### 1.2 Active Network Attacker

An attacker who can additionally modify, drop, replay, or inject traffic — for example, a rogue Wi-Fi hotspot operator, a compromised gateway, or a state-level MITM. This attacker has all the capabilities of §1.1.

**What this attacker can do, beyond §1.1:**

- Intercept and modify packets in transit, including attempting to strip TLS (SSL stripping attacks).
- Attempt to impersonate the server by presenting a forged TLS certificate.
- Drop specific messages to deny delivery to selected users.
- Replay previously captured encrypted requests to the server.
- Inject fabricated API responses to trick the client into accepting bad data — for example, serving a malicious key bundle in place of a real one.

**Properties that hold:**

- TLS with certificate verification prevents a MITM from substituting a fake server certificate. `SSL_CTX_set_verify(SSL_VERIFY_PEER)` enforces certificate chain validation and `SSL_set1_host` enforces hostname verification against the certificate's CN/SAN fields.
- SRP-6a authentication never sends the password over the wire, even to a fake server. The password contributes only to computing the verifier locally. A MITM who intercepts the SRP exchange learns only the public ephemeral values A and B, from which recovering the password is equivalent to solving a discrete logarithm in a 4096-bit group.
- Replay attacks on messages are detected by the Double Ratchet's `m_processed` set, which records every successfully decrypted `(dhPub, messageIndex)` pair. Any replayed ciphertext will match an existing entry and be rejected with "Replayed message detected".
- Injected ciphertexts fail AES-256-GCM authentication. The 128-bit GCM tag provides a 2⁻¹²⁸ per-attempt forgery probability, rendering injection without the message key computationally infeasible.
- Key substitution on first contact: when sending to a known contact, the sender compares the server-provided identity key against the locally cached `identityPub` using `CRYPTO_memcmp` (constant-time). A mismatch throws "Identity key mismatch" and aborts the session.

### 1.3 Honest-but-Curious Server

A server that correctly executes the protocol — delivers messages, stores data, responds to API calls — but logs and inspects everything it receives and stores. For example, a legitimate service provider under a legal subpoena, an employee with database read access, or a partial breach that exposes the server. This attacker has all the capabilities of §1.1.

**What this attacker can observe, beyond §1.1:**

- Everything stored in the database: usernames, SRP verifiers, all ciphertext blobs, ratchet header ciphertext, group membership, SKDM payloads, timestamps, and message IDs.
- The full social graph: `sender_id` and `recipient_id` are stored for every message. The server knows exactly who communicates with whom, when, and how often.
- Group membership: the server stores and manages group member lists and epochs.
- TOTP provisioning URIs: the server generates and delivers these at registration. If logged, a curious server knows each user's TOTP secret.

**Properties that hold:**

- The server never sees plaintext. PQXDH session keys are derived entirely from DH and ML-KEM operations performed locally; the session key is never transmitted. Message bodies are AES-256-GCM ciphertext opaque to the server.
- Ratchet headers are also encrypted (under separate header keys), so the server cannot read the X25519 ratchet public keys embedded in headers — it sees only an additional AES-256-GCM blob.
- Passwords are never stored on the server. SRP-6a ensures the server holds only a verifier `v = g^x mod N` (where `x = SHA-256(salt || SHA-256(username || ":" || password))`). Even with full database access, recovering the password from `v` requires solving a 4096-bit DLP.
- Local private keys are never transmitted. The keystore file stored on disk is encrypted with PBKDF2-derived AES-256-GCM; the plaintext private key material never leaves the device.

### 1.4 Fully Compromised Server

An attacker with full read/write access to the server's database, logs, and process memory — for example, a malicious insider, a remote code execution exploit, or physical access to the server. This attacker has all the capabilities of §1.2 and §1.3.

**What this attacker can do, beyond §1.2 and §1.3:**

- Modify or delete any stored data: ciphertext blobs, key bundles, group membership records, message history.
- Access all SRP verifiers in the database (but cannot use these to authenticate).
- Serve malicious key bundles to clients initiating new sessions.

**Properties that hold:**

- Message confidentiality: the server never holds message keys at any point. Session keys are derived entirely from client-side DH and ML-KEM operations and are never transmitted; message keys are derived locally from the Double Ratchet chain.
- Integrity in established conversations: AES-256-GCM authentication means a compromised server cannot alter ciphertext without the receiver detecting it. Additionally, PQXDH verifies all three Ed25519 signatures on the recipient's key bundle before performing any DH operations — a compromised server cannot silently substitute signed prekeys for an established contact without the signature check failing. One-time prekeys (OPKs) are unsigned, so a compromised server can omit or substitute an OPK; however, OPK use only adds an optional fourth DH contribution to the session key — removing it weakens but does not break the session key derivation, which still relies on the three signed DH operations and the ML-KEM shared secret.
- Password confidentiality: the SRP verifier in the database does not reveal the password.

**Properties NOT held:**

- **Key substitution for new contacts (TOFU window):** On the very first message to a new contact, the client fetches their key bundle from the server. A compromised server can serve a malicious bundle at this point. After the first exchange, any subsequent identity key changes are detected via `CRYPTO_memcmp`. This can be mitigated by meeting and comparing the keys.
- **Message delivery:** A compromised server can drop, delay, or reorder messages. The Double Ratchet handles gaps gracefully, so out-of-order or delayed messages still decrypt when they arrive and are displayed in creation order using the `timestampMs` field encrypted inside each message header. Dropped messages are detectable: the sequential `messageIndex` and monotonically increasing `totalSentCount` in the decrypted header reveal gaps, so the receiver can tell messages are missing — but cannot force the server to deliver them.
- **Sender Key group messages post-compromise:** The Sender Key Ratchet has no DH ratchet component. If a group sender key is obtained (e.g., via a compromised SKDM in transit), all future messages from that sender in the current epoch are compromised until the next membership change triggers a new sender key.
- **Group membership manipulation:** Group membership is managed server-side. A compromised server can add attacker-controlled members to a group — those members will receive new SKDMs and can decrypt future group messages from that epoch onwards. The server can also silently remove legitimate members or pretend to delete users. Client-side Ed25519 signature verification prevents the server from substituting the keys of existing known members, it cannot prevent the server from adding entirely new malicious identities to the group whose keys it controls — however, legitimate group members will be notified of the membership change and can observe the unexpected addition.

---

## 2. Construction Walkthrough

### 2.1 Registration

```
Client                                          Server
  |                                               |
  |  1. Compute SRP verifier locally:             |
  |     x   = SHA256(salt || SHA256(user:pass))   |
  |     verifier = g^x mod N  (NG_4096, g=5)      |
  |                                               |
  |  2. Generate key bundle:                      |
  |     ik  = Ed25519 keypair  (identity signing) |
  |     ikX = X25519 keypair   (long-term DH)     |
  |     spk = X25519 keypair   (signed prekey)    |
  |     pq  = ML-KEM-1024 keypair                 |
  |     opks= 20 × X25519 one-time prekeys        |
  |     Sign ikX.pub, spk.pub, pq.pub with ik     |
  |                                               |
  |  POST /register {username, salt, verifier,    |
  |    ik.pub, ikX.pub, ikX.sig,                  |
  |    spk.pub, spk.sig,                          |
  |    pq.pub, pq.sig, opks.pubs}  ─────────────> |
  |                                               |  Store verifier, key bundle,
  |                                               |  generate & store TOTP secret
  |  <─────────── {totp_provisioning_uri} ──────  |
  |                                               |
  |  3. Render TOTP QR code (qrencode)            |
  |     User scans and saves to authenticator app |
  |  4. Encrypt key bundle to disk:               |
  |     salt = random(16 bytes)                   |
  |     key  = PBKDF2-HMAC-SHA256(passphrase,     |
  |              salt, 600000, 32)                |
  |     file = salt || AES-256-GCM(key, bundle)   |
```

### 2.2 Login (SRP-6a + TOTP)

```
Client                                          Server
  |                                               |
  |  1. a = random scalar (ephemeral)             |
  |     A = g^a mod N                             |
  |  POST /srp/init {username, A} ───────────────>|
  |                                               |  b = random, B = kv + g^b mod N
  |  <──────────── {B, srpSalt} ───────────────   |
  |                                               |
  |  2. u   = SHA256(A || B)                      |
  |     x   = SHA256(srpSalt || SHA256(user:pass))|
  |     S   = (B - k·g^x)^(a + u·x) mod N        |
  |     K   = SHA256(S)                           |
  |     M1  = SHA256(A || B || K)                 |
  |  POST /srp/verify {M1} ──────────────────────>|
  |                                               |  Verify M1, compute M2
  |  <──────── {M2, pre_auth_token} ────────────  |
  |                                               |
  |  3. Verify M2 — ABORT if wrong (MITM check)   |
  |  POST /2fa/verify {totp_code,                 |
  |    pre_auth_token} ──────────────────────────>|
  |                                               |
  |  <──── {access_token, refresh_token} ──────── |
```

### 2.3 Key Publication and Bundle Retrieval

After login, the client uploads any depleted one-time prekeys. When Alice wants to send to Bob for the first time, she fetches Bob's key bundle:

```
GET /users/{bob_id}/keys  ──────────────────────>|
<── {ikEdPub, ikXPub, ikXSig, spkPub, spkSig,    |
     pqPub, pqSig, opkPub (optional)} ────────── |
```

Alice verifies all three Ed25519 signatures (`ikXSig`, `spkSig`, `pqSig`) over Bob's published keys before using them. If any signature fails, the key bundle is rejected.

### 2.4 Sending a Direct Message (PQXDH + Double Ratchet)

**First message to a new recipient — PQXDH key establishment:**

```
Alice computes:
  ek        = X25519 ephemeral keypair
  dh1       = X25519-DH(aliceIkX.priv, bobSpkPub)
  dh2       = X25519-DH(ek.priv, bobIkXPub)
  dh3       = X25519-DH(ek.priv, bobSpkPub)
  [dh4      = X25519-DH(ek.priv, bobOpkPub)]  (if OPK present)
  [pqCt,ss] = ML-KEM-1024-Encap(bobPqPub)

  IKM = 0xFF×32 || dh1 || dh2 || dh3 [|| dh4] || ss
  SK  = HKDF-SHA256(IKM, salt="", info="PQXDH-v1", 32)

  All intermediate DH outputs and IKM are cleansed with OPENSSL_cleanse()

Alice initialises Double Ratchet as sender:
  RatchetState::initSender(SK, bobSpkPub)

Wire format for first message:
  header = 0x01 (PQXDH_FLAG_INITIAL)
         || aliceIkXPub (32 bytes)
         || ek.pub      (32 bytes)
         || pqCt        (1568 bytes, ML-KEM-1024 ciphertext)
         || opkPub      (32 bytes, or 0×32 if none)
         || AES-256-GCM(sendHeaderKey, ratchetHeader)
  body   = AES-256-GCM(messageKey, plaintext)
```

**Subsequent messages — Double Ratchet only:**

```
header = 0x00 (PQXDH_FLAG_REGULAR)
       || AES-256-GCM(sendHeaderKey, ratchetHeader)
body   = AES-256-GCM(messageKey, plaintext)

ratchetHeader contains: dhPub, prevChainLen, messageIndex, totalSentCount, timestampMs
```

Each message key is derived by advancing the chain:

```
newChainKey = HKDF-SHA256(chainKey, salt="", info="ratchet-chain-key", 32)
messageKey  = HKDF-SHA256(chainKey, salt="", info="ratchet-message-key", 32)
```

A DH ratchet step occurs when the receiver's new DH public key appears in the decrypted header, deriving a new root key, chain key, and next header key:

```
newRootKey, newChainKey, nextHK = HKDF-SHA256(DH(mySendPriv, theirPub), rootKey, info=..., 32)
```

### 2.5 Receiving a Direct Message

```
1. Decode base64 ciphertext and ratchet_header_enc
2. Check flag byte:
   - 0x01: parse PQXDH prefix, run pqxdhReceive(), initialise RatchetState as receiver
   - 0x00: look up existing RatchetState for sender
3. Decrypt header: try recvHeaderKey, then nextRecvHeaderKey
   (encrypted headers prevent the ratchet public key from being visible to the server)
4. If dhPub in header differs from known remote key → DH ratchet step
5. Advance chain to messageIndex, stashing skipped keys (up to RATCHET_MAX_SKIP=1000)
6. Decrypt body with derived messageKey using AES-256-GCM
7. Check (dhPub, messageIndex) against m_processed — reject if already seen
8. Record in m_processed; cleanse messageKey with OPENSSL_cleanse()
9. Acknowledge receipt to server
```

### 2.6 Group Messaging (Sender Key Ratchet)

```
Key distribution (group creation or epoch change):
  senderKey = random(32 bytes)          # per-sender, per-epoch
  For each member m:
    Run PQXDH(myIkX, m.keyBundle) → sessionKey
    skdm = AES-256-GCM(sessionKey, senderKey)
    POST /groups/{id}/skdm [encrypted per member]
  OPENSSL_cleanse(senderKey)

Sending:
  chainKey = HKDF(senderKey, info="sender-key-chain-init", 32)
  newCk    = HKDF(chainKey,  info="sender-key-chain",   32)
  mk       = HKDF(chainKey,  info="sender-key-message", 32)
  wire     = iteration(4 bytes) || AES-256-GCM(mk, plaintext)

Epoch rotation: triggered by addMember/removeMember — new senderKey generated,
  new SKDMs distributed to current members only.
  Removed members do not receive the new sender key (forward secrecy for the group).
  New members do not receive old sender keys (past message confidentiality).
```

### 2.7 Storage at Rest

```
File: ~/.config/securemsg/identity.key

Layout: PBKDF2_SALT[16] || IV[12] || TAG[16] || ENC_PAYLOAD[n]

Payload (plaintext, inside AEAD envelope):
  Ed25519 private key  (32 bytes)
  Ed25519 public key   (32 bytes)
  X25519 IK priv       (32 bytes)
  X25519 IK pub        (32 bytes)
  ikXSig               (64 bytes)
  SPK priv             (32 bytes)
  SPK pub              (32 bytes)
  spkSig               (64 bytes)
  PQ priv              (3168 bytes, ML-KEM-1024)
  PQ pub               (1568 bytes)
  pqSig                (64 bytes)
  OPK count (1 byte) + OPK pairs (64 bytes each)

Derivation:
  key = PBKDF2-HMAC-SHA256(passphrase, PBKDF2_SALT, 600000, 32)
  Encrypt with AES-256-GCM, random 12-byte IV
  key is cleansed with OPENSSL_cleanse() after use

Write is atomic: file written to identity.key.tmp first, then
  std::filesystem::rename() replaces the original (POSIX-atomic).
```

---

## 3. Primitive Justifications

### 3.1 AES-256-GCM (AEAD)

**Algorithm:** AES in Galois/Counter Mode. NIST SP 800-38D.

**Why 256-bit key:** AES-256 provides 256 bits of key entropy and 128 bits of security against exhaustive search under Grover's algorithm on a quantum computer.

**Why GCM specifically:** GCM is an Authenticated Encryption with Associated Data (AEAD) construction that provides confidentiality and integrity in a single pass. It is standardised in NIST SP 800-38D and has no known practical vulnerabilities. The alternative constructions (CBC + separate HMAC, CTR + HMAC) require correct ordering.

**Why 96-bit random IV:** NIST SP 800-38D, §8.2 specifies that 96-bit IVs are preferred for GCM because they allow the counter block to be constructed by direct concatenation with a 32-bit counter, avoiding the variable-length GHASH padding step required for other IV lengths. IVs are generated with `RAND_bytes` never reused. In this protocol, each message key is used for exactly one encryption, so even in the theoretical event of an IV collision the key will be different, preserving security.

**Why 128-bit tag:** Full 128-bit GCM tag. A 128-bit tag provides 2⁻¹²⁸ forgery probability per attempt, which is negligible. Truncating the tag (e.g. to 96 or 64 bits) would weaken integrity guarantees without any protocol benefit.

### 3.2 HKDF-SHA256 (Key Derivation)

**Standard:** RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function.

**Why HKDF and not just SHA256:** HKDF is designed for the case where the input keying material (IKM) is already pseudorandom (e.g., a DH output or an existing key). It provides a formal PRF security proof under the random oracle model. A bare SHA-256 hash does not provide the domain-separation or expansion properties needed here.

**Why SHA-256 as the underlying hash:** SHA-256 provides 128-bit collision resistance (birthday bound). The Double Ratchet specification (Marlinspike & Perrin, "The Double Ratchet Algorithm", 2016, §7.2) specifies HMAC-SHA-256 as the HKDF hash. Using SHA-512 would provide no meaningful benefit for 256-bit output lengths and would increase computational cost.

**Domain separation via `info`:** Every call to `hkdf()` uses a distinct `info` string (e.g., `"ratchet-chain-key"`, `"ratchet-message-key"`, `"ratchet-root-key"`, `"ratchet-hks"`, `"PQXDH-v1"`). This is RFC 5869's mechanism for binding derived keys to their intended use context. Two calls with the same IKM but different `info` strings produce computationally independent outputs, preventing key confusion across protocol layers.

**Why not PBKDF2 here:** PBKDF2 is designed for low-entropy inputs (passwords). DH outputs and session keys already have 256 bits of entropy; adding iteration cost provides no security benefit and would harm performance.

### 3.3 PBKDF2-HMAC-SHA256 (Keystore Encryption)

**Standard:** RFC 8018 (PKCS #5 v2.1), §5.2.

**Why PBKDF2 for local key storage:** Passphrases have low entropy. PBKDF2 artificially increases the cost of brute-force attacks by iterating the hash function, making an offline dictionary attack against a stolen keystore file expensive in proportion to the iteration count.

**Why 600,000 iterations:** OWASP Password Storage Cheat Sheet (2026) recommends 600,000 iterations of PBKDF2-HMAC-SHA256 as the minimum for protecting sensitive credentials. This dramatically increases the cost and time of brute force attacks, while not being too expensive for each legitimate hashing operations.

**Why 16-byte random salt:** A 128-bit random salt, generated with `RAND_bytes`, prevents precomputed rainbow table attacks. Because the salt is unique per user per device, identical passphrases produce different keys. The salt is stored in plaintext alongside the ciphertext; this is secure because salt alone is useless.

### 3.4 SRP-6a, NG_4096, SHA-256

**Standard:** RFC 5054 — Appendix A (group parameters).

**Why SRP:** Standard password-over-TLS sends the password (or a hash) to the server, exposing it to a compromised server or a MITM. SRP is a password-authenticated key exchange (PAKE): the server stores only a verifier `v = g^x mod N`, and the password is never transmitted in any form. A full database breach leaks only `v`, from which recovering the password is guarded by the discrete logarithm problem.

**Why 4096-bit group (NG_4096):** RFC 5054 Appendix A defines several DLP groups. The 1024-bit group provides approximately 80-bit security (no longer adequate); 2048-bit provides ~112 bits (adequate but narrow margin). The 4096-bit group provides approximately 140 bits of classical security, it also shows where the number comes from in "nothing up my sleve", avoiding a backdoor simlar to Dual EC DRBG.

**Why SHA-256:** SHA-256 is used to compute `x`, `u`, `M1`, `M2`, and `K`. This matches pysrp's `NG_4096` + `SHA256` configuration on the server. SHA-1 is cryptographically broken for collision-resistance and must not be used. SHA-512 (SHA-2 family) would provide a larger output but the security of SRP is bounded by the hardness of the discrete logarithm problem in the group, not by the hash output size — SHA-256's 256-bit output is sufficient. SHA-3 would introduce a server/client mismatch with no security benefit.

**Mutual authentication:** The client verifies the server's proof `M2 = SHA256(A || M1 || K)` before proceeding to TOTP. If `M2` fails, the session is immediately aborted — this prevents the client from accepting a session key that the legitimate server does not hold, closing a class of MITM attacks even within the SRP exchange.

### 3.5 ML-KEM-1024 (Post-Quantum KEM)

**Standard:** NIST FIPS 203 (Kyber) — Module-Lattice-Based Key-Encapsulation Mechanism Standard.

**Why a post-quantum KEM:** RSA and Diffie-Hellman (including X25519) are broken by Shor's algorithm on a sufficiently large quantum computer. While large-scale quantum computers do not yet exist, messages recorded today under a classical-only key exchange could be decrypted in the future ("harvest now, decrypt later"). ML-KEM provides security based on the Module-Learning With Errors (MLWE) problem, which has no known efficient quantum algorithm.

**Why the 1024 variant:** FIPS 203 defines three parameter sets:
- ML-KEM-512: NIST Category 1 (~AES-128 security, 128-bit classical)
- ML-KEM-768: NIST Category 3 (~AES-192)
- ML-KEM-1024: NIST Category 5 (~AES-256, ~256-bit classical / 128-bit quantum)

ML-KEM-1024 is chosen to match the AES-256-GCM symmetric security level. Using ML-KEM-512 would create a bottleneck where the post-quantum security is weaker than the symmetric layer.

**Hybrid construction (PQXDH):** ML-KEM-1024 is not used alone. The PQXDH construction ("The PQXDH Key Agreement Protocol", Signal whitepaper 2023) combines three X25519 DH operations with one ML-KEM encapsulation. The shared key is:

```
SK = HKDF(0xFF×32 || DH1 || DH2 || DH3 [|| DH4] || MLKEM_SS, info="PQXDH-v1")
```

The 32-byte `0xFF` binder prevents confusion with a legacy X3DH session that does not include the ML-KEM component. Security degrades gracefully: if ML-KEM is broken, security falls back to classical X3DH; if X25519 is broken by a quantum computer, the ML-KEM component preserves post-quantum confidentiality.

### 3.6 X25519 (Elliptic-Curve Diffie-Hellman)

**Standard:** RFC 7748 — Elliptic Curves for Security, §5 (X25519).

**Why Curve25519 / X25519:** X25519 provides ~128-bit classical security with a 32-byte key. The Montgomery-ladder scalar multiplication used in Curve25519 runs in constant time regardless of the scalar value, eliminating timing side-channels. It also has a much smaller key when compared to RSA or DH

### 3.7 Ed25519 (Digital Signatures)

**Standard:** RFC 8032 — Edwards-Curve Digital Signature Algorithm, §5.1.

**Why Ed25519:** Ed25519 is a Schnorr-type signature on the Edwards25519 curve. Unlike ECDSA (which requires a random nonce and is vulnerable to nonce reuse — the PS3 signing key was recovered due to a weak RNG), Ed25519 is deterministic: the nonce is derived from the private key and the message via a hash, so there is no random nonce to be weak or reused. The signature is 64 bytes; verification is fast and constant-time.

### 3.8 Double Ratchet with Encrypted Headers

**Standard:** The Double Ratchet Algorithm - Signal Foundation, 2025.

**Why the Double Ratchet:** A static HPKE construction provides forward secrecy only for sessions where a new ephemeral key is generated per message. The Double Ratchet's DH ratchet step additionally provides *break-in recovery*: after each ratchet step, an attacker who compromises the current chain key cannot decrypt future messages, because a new root key is derived from a fresh DH exchange.

**Why encrypted headers:** Standard Double Ratchet transmits the ratchet DH public key in the clear. Encrypting headers under separate key material (derived from the session key, `hkdf(SK, info="ratchet-hks")`) prevents a network observer from tracking ratchet epochs, which would otherwise reveal something about the message pattern even if message bodies are encrypted.

**Skip limit (RATCHET_MAX_SKIP = 1000):** Without a limit, an adversary could induce the receiver to pre-generate and store an unbounded number of skipped message keys, consuming memory. The limit of 1000 skipped keys is consistent with Signal's reference implementation.

---

## 4. Known Limitations


1. **No sealed sender** — the server can observe who messages whom (social graph visible).

2. **TOFU trust model** — the first published key bundle is trusted unconditionally; no key transparency log. A transparency log would not fully solve this anyway: the server controls the log and could show Alice and Bob two different versions (a split-view attack), each internally consistent. The standard mitigation is gossip — clients exchange the root hash they've seen so discrepancies are detected — but the server could simply drop gossip packets, silently preventing detection without either client knowing.

3. **Ed25519 not post-quantum** — unlike encryption, signatures are not vulnerable to store-now-decrypt-later attacks. Post-quantum signature schemes (ML-DSA, SLH-DSA) produce signatures 10–50× larger than Ed25519's 64 bytes, adding significant overhead per message. They are also recent NIST standards with far less real-world scrutiny than Ed25519.

4. **SRP-6a not post-quantum** — Shor's algorithm breaks discrete log, so a quantum attacker with a stolen verifier database could recover passwords. The post quantum replacement is OPAQUE, but no pip-installable Python implementation exists yet, and as a relatively new protocol it has had less real-world scrutiny than SRP.

5. **No Device Bound Service Credentials** — access tokens are not device-bound. Device binding is straightforward in browsers via the Web Authentication API (WebAuthn), but we've to build our own client; adding device-binding scheme would add significant complexity.

6. **Unsigned one-time prekeys** — OPKs are not signed by the identity key. A malicious server could substitute an attacker's OPK, compromising the forward secrecy of that one session establishment. This is a deliberate tradeoff inherited from Signal's X3DH design: signing every OPK would double their upload size (a 64-byte Ed25519 signature per 32-byte key) for marginal security gain, given that a substituted OPK only affects a single session rather than all future sessions as a substituted signed prekey would. The signed prekey and ML-KEM prekey are both signed precisely because they are long-lived and high-value targets.
