#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <array>

// Holds the state needed during a single SRP-6a login attempt.
class SrpSession {
public:
    // Call once per login attempt.  Returns A (hex) to send to the server.
    std::string begin(const std::string& username, const std::string& password);

    // Call after the server replies with (salt_hex, B_hex).
    // Returns M1 (hex) to send as client_proof.
    std::string computeProof(const std::string& srpSaltHex,
                             const std::string& serverPublicHex);

    // Verify the server's proof (M2 hex) to confirm the server knows the verifier.
    bool verifyServerProof(const std::string& serverProofHex) const;

private:
    std::string m_username;
    std::string m_password;

    // BN state kept as raw bytes between calls
    std::vector<uint8_t> m_a_bytes;   // client private ephemeral
    std::vector<uint8_t> m_A_bytes;   // client public  ephemeral (256 bytes, big-endian)
    std::vector<uint8_t> m_K;         // session key (SHA-256 of S)
    std::vector<uint8_t> m_M1;        // client proof
};

class CryptoManager {
public:
    static constexpr int KEY_BYTES = 32;  // AES-256
    static constexpr int IV_BYTES  = 12;  // GCM recommended
    static constexpr int TAG_BYTES = 16;  // GCM auth tag

    // Packed on-wire layout: IV[12] | TAG[16] | CIPHERTEXT[n]
    struct AeadPacket {
        std::vector<uint8_t> iv;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> ciphertext;
    };

    // AES-256-GCM
    static AeadPacket   aeadEncrypt(const std::string& plaintext,
                                    const std::vector<uint8_t>& key);
    static std::string  aeadDecrypt(const AeadPacket& pkt,
                                    const std::vector<uint8_t>& key);

    // Serialise / deserialise the packed wire format (IV || TAG || CIPHERTEXT).
    static std::vector<uint8_t> packAead(const AeadPacket& pkt);
    static AeadPacket           unpackAead(const std::vector<uint8_t>& raw);

    // X25519 key pair — returns (private_bytes, public_bytes) each 32 bytes.
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateX25519KeyPair();

    // X25519 DH — returns 32-byte shared secret.
    static std::vector<uint8_t> x25519DH(const std::vector<uint8_t>& privKey,
                                          const std::vector<uint8_t>& peerPub);

    // HKDF-SHA256 — returns `outLen` bytes.
    static std::vector<uint8_t> hkdf(const std::vector<uint8_t>& ikm,
                                      const std::vector<uint8_t>& salt,
                                      const std::string&           info,
                                      std::size_t                  outLen);

    // Derive a message key from Alice's private key, Bob's public key, and an
    // ephemeral key pair (generated fresh for each message).
    // Returns {messageKey[32], ephemeralPub[32]}.
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    deriveMessageKey(const std::vector<uint8_t>& senderPriv,
                     const std::vector<uint8_t>& senderPub,
                     const std::vector<uint8_t>& recipientPub);

    // Recover the message key on the receiver side.
    static std::vector<uint8_t>
    recoverMessageKey(const std::vector<uint8_t>& recipientPriv,
                      const std::vector<uint8_t>& recipientPub,
                      const std::vector<uint8_t>& senderPub,
                      const std::vector<uint8_t>& ephemeralPub);

    // SRP-6a (2048-bit group, SHA-256) — registration side.
    // Fills saltHex with the freshly generated salt.
    static std::string computeSrpVerifier(const std::string& username,
                                           const std::string& password,
                                           std::string&       saltHex);

    // Local key store: encrypt/decrypt 32-byte private key with a passphrase.
    // File layout: PBKDF2_SALT[16] | IV[12] | TAG[16] | ENC_KEY[32]
    static void savePrivateKey(const std::string&           path,
                               const std::vector<uint8_t>&  privKey,
                               const std::string&           passphrase);
    static std::vector<uint8_t> loadPrivateKey(const std::string& path,
                                               const std::string& passphrase);

    // Utilities
    static std::vector<uint8_t> randomBytes(std::size_t n);
    static std::string          base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& encoded);
    static std::string          toHex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fromHex(const std::string& hex);
};
