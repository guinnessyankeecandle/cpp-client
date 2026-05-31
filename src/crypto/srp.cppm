module;
#include <cstdint>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <botan/srp6.h>
#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/symkey.h>
export module securemsg.crypto.srp;
import securemsg.crypto.random;

static constexpr auto SRP_GROUP = "modp/srp/4096";
static constexpr auto SRP_HASH  = "SHA-256";

static std::vector<uint8_t> sha256(std::initializer_list<std::pair<const uint8_t *, std::size_t>> parts) {
  const auto h = Botan::HashFunction::create_or_throw(SRP_HASH);
  for (const auto &[data, len] : parts)
    h->update(data, len);
  return h->final_stdvec();
}

// Verifier generation — fully delegated to Botan.
export std::string srpComputeVerifier(const std::string &username,
                                      const std::string &password,
                                      std::string &saltHexOut) {
  const auto saltBytes = randomBytes(32);

  // Pad salt to 64 bytes to match the server's expected format
  std::vector<uint8_t> saltPadded(64, 0);
  std::copy(saltBytes.begin(), saltBytes.end(), saltPadded.begin());

  const Botan::BigInt verifier = Botan::srp6_generate_verifier(
      username, password, saltPadded, SRP_GROUP, SRP_HASH);

  saltHexOut = Botan::BigInt(saltPadded).to_hex_string();
  return verifier.to_hex_string();
}

export struct SrpProof {
  std::string clientPublicHex; // A — send to srpVerify
  std::string clientProofHex;  // M1 — send to srpVerify
};

// SRP-6a client session — core key agreement delegated to Botan.
// New two-step protocol flow:
//   1. srpInit(username)                    → {session_id, srp_salt, server_public (B)}
//   2. computeProof(username, password, salt, B) → SrpProof{A, M1}
//   3. srpVerify(session_id, A, M1)         → {server_proof (M2)}
//   4. verifyServerProof(M2)                → confirms server holds correct verifier
export class SrpSession {
public:
  // Derives (A, K) via Botan, then computes M1. Returns A and M1 for srpVerify.
  SrpProof computeProof(const std::string &username,
                        const std::string &password,
                        const std::string &srpSaltHex,
                        const std::string &serverPublicHex) {
    Botan::AutoSeeded_RNG rng;

    const Botan::BigInt B   = Botan::BigInt::from_string("0x" + serverPublicHex);
    const auto saltBytes    = Botan::hex_decode(srpSaltHex);

    // Botan performs the full constant-time SRP-6a client computation
    auto [A, sessionKey]    = Botan::srp6_client_agree(
        username, password, SRP_GROUP, SRP_HASH, saltBytes, B, rng);

    m_A = A;
    const auto keyBits = sessionKey.bits_of();
    m_K.assign(keyBits.begin(), keyBits.end());

    // M1 = SHA256(SHA256(N) XOR SHA256(g) || SHA256(username) || salt || A || B || K)
    // Matches pysrp's non-RFC5054 M1 formula used by the server.
    const Botan::DL_Group group(SRP_GROUP);
    const auto nBytes   = group.get_p().serialize(512);
    const auto gByte    = static_cast<uint8_t>(group.get_g().word_at(0));
    const auto ABytes   = m_A.serialize(512);
    const auto BBytes   = B.serialize(512);

    const auto hashN    = sha256({{nBytes.data(), nBytes.size()}});
    const auto hashG    = sha256({{&gByte, 1}});
    std::vector<uint8_t> xorNG(32);
    for (std::size_t i = 0; i < 32; ++i)
      xorNG[i] = hashN[i] ^ hashG[i];

    const auto hashUser = sha256({{reinterpret_cast<const uint8_t *>(username.data()),
                                   username.size()}});

    m_M1 = sha256({
        {xorNG.data(),     xorNG.size()},
        {hashUser.data(),  hashUser.size()},
        {saltBytes.data(), saltBytes.size()},
        {ABytes.data(),    ABytes.size()},
        {BBytes.data(),    BBytes.size()},
        {m_K.data(),       m_K.size()},
    });

    return {m_A.to_hex_string(), Botan::BigInt(m_M1).to_hex_string()};
  }

  // M2 = SHA256(A || M1 || K) — verifies the server also holds the correct verifier.
  bool verifyServerProof(const std::string &serverProofHex) const {
    if (m_K.empty() || m_M1.empty())
      throw std::runtime_error("SRP: cannot verify server proof before completing handshake");

    const auto ABytes   = m_A.serialize(512);
    const auto expected = sha256({
        {ABytes.data(), ABytes.size()},
        {m_M1.data(),   m_M1.size()},
        {m_K.data(),    m_K.size()},
    });

    const auto serverM2 = Botan::BigInt::from_string("0x" + serverProofHex).serialize(32);
    return CRYPTO_memcmp(expected.data(), serverM2.data(), 32) == 0;
  }

  ~SrpSession() {
    if (!m_K.empty())
      OPENSSL_cleanse(m_K.data(), m_K.size());
    if (!m_M1.empty())
      OPENSSL_cleanse(m_M1.data(), m_M1.size());
  }

private:
  Botan::BigInt m_A;
  mutable std::vector<uint8_t> m_K;
  mutable std::vector<uint8_t> m_M1;
};
