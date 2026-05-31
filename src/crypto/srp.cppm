module;
#include <algorithm>
#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/hex.h>
#include <botan/srp6.h>
#include <botan/symkey.h>
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.srp;
import securemsg.crypto.random;
import securemsg.crypto.aead;

using MdCtxPtr = OssPtr<EVP_MD_CTX, EVP_MD_CTX_free>;

export struct SrpProof {
  std::string clientPublicHex;
  std::string clientProofHex;
};

export class SrpSession {
public:
  static std::string computeVerifier(const std::string &username,
                                     const std::string &password,
                                     std::string &saltHexOut) {
    const auto saltBytes = randomBytes(KEY_BYTES);

    const Botan::BigInt verifier = Botan::srp6_generate_verifier(
        username, password, saltBytes, SRP_GROUP, SRP_HASH);

    saltHexOut = Botan::BigInt(saltBytes).to_hex_string();
    return verifier.to_hex_string();
  }

  SrpProof computeProof(const std::string &username,
                        const std::string &password,
                        const std::string &srpSaltHex,
                        const std::string &serverPublicHex) {
    Botan::AutoSeeded_RNG rng;

    const Botan::BigInt serverPublic =
        Botan::BigInt::from_string("0x" + serverPublicHex);
    const auto saltBytes = Botan::hex_decode(srpSaltHex);

    auto [clientPublic, sessionKey] = Botan::srp6_client_agree(
        username, password, SRP_GROUP, SRP_HASH, saltBytes, serverPublic, rng);

    m_clientPublic = clientPublic;
    auto keyBits = sessionKey.bits_of();
    m_sessionKey.assign(keyBits.begin(), keyBits.end());
    OPENSSL_cleanse(keyBits.data(), keyBits.size());

    // Conversions to big endian
    const Botan::DL_Group group = Botan::DL_Group::from_name(SRP_GROUP);
    const auto modulusBytes = group.get_p().serialize(SRP_FIELD_BYTES);
    const auto generatorByte = static_cast<uint8_t>(group.get_g().word_at(0));
    const auto clientPublicBytes = m_clientPublic.serialize(SRP_FIELD_BYTES);
    const auto serverPublicBytes = serverPublic.serialize(SRP_FIELD_BYTES);

    const auto hashModulus =
        sha256({{modulusBytes.data(), modulusBytes.size()}});
    const auto hashGenerator =
        sha256({{&generatorByte, sizeof(generatorByte)}});
    std::vector<uint8_t> xorNG(KEY_BYTES);
    for (std::size_t i = 0; i < KEY_BYTES; ++i)
      xorNG[i] = hashModulus[i] ^ hashGenerator[i];

    const auto hashUser =
        sha256({{reinterpret_cast<const uint8_t *>(username.data()),
                 username.size()}});

    m_clientProof = sha256({
        {xorNG.data(), xorNG.size()},
        {hashUser.data(), hashUser.size()},
        {saltBytes.data(), saltBytes.size()},
        {clientPublicBytes.data(), clientPublicBytes.size()},
        {serverPublicBytes.data(), serverPublicBytes.size()},
        {m_sessionKey.data(), m_sessionKey.size()},
    });

    return {m_clientPublic.to_hex_string(), Botan::hex_encode(m_clientProof)};
  }

  bool verifyServerProof(const std::string &serverProofHex) const {
    if (m_sessionKey.empty() || m_clientProof.empty())
      throw std::runtime_error(
          "SRP: cannot verify server proof before completing handshake");

    const auto clientPublicBytes = m_clientPublic.serialize(SRP_FIELD_BYTES);
    const auto expected = sha256({
        {clientPublicBytes.data(), clientPublicBytes.size()},
        {m_clientProof.data(), m_clientProof.size()},
        {m_sessionKey.data(), m_sessionKey.size()},
    });

    const auto serverProofBytes =
        Botan::BigInt::from_string("0x" + serverProofHex).serialize(KEY_BYTES);
    return CRYPTO_memcmp(expected.data(), serverProofBytes.data(), KEY_BYTES) ==
           0;
  }

  ~SrpSession() {
    if (!m_sessionKey.empty())
      OPENSSL_cleanse(m_sessionKey.data(), m_sessionKey.size());
    if (!m_clientProof.empty())
      OPENSSL_cleanse(m_clientProof.data(), m_clientProof.size());
  }

private:
  static constexpr auto SRP_GROUP = "modp/srp/4096";
  static constexpr auto SRP_HASH = "SHA-256";
  static constexpr std::size_t SRP_FIELD_BYTES =
      512; // 4096-bit group → 512 bytes

  // Avoids allocating a concatenated buffer.
  static std::vector<uint8_t>
  sha256(std::initializer_list<std::pair<const uint8_t *, std::size_t>> parts) {
    const MdCtxPtr ctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);

    for (const auto &[data, len] : parts)
      EVP_DigestUpdate(ctx.get(), data, len);

    std::vector<uint8_t> out(KEY_BYTES);
    EVP_DigestFinal_ex(ctx.get(), out.data(), nullptr);
    return out;
  }

  Botan::BigInt m_clientPublic;
  mutable std::vector<uint8_t> m_sessionKey;
  mutable std::vector<uint8_t> m_clientProof;
};
