module;
#include <algorithm>
#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/hex.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/srp6.h>
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

static std::string stripHexPrefix(const std::string &s) {
  return s.substr(0, 2) == "0x" ? s.substr(2) : s;
}

static std::string toLower(std::string s) {
  std::ranges::transform(s, s.begin(),
                         [](const unsigned char c) { return std::tolower(c); });
  return s;
}

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

    saltHexOut = toLower(Botan::hex_encode(saltBytes));
    return toLower(stripHexPrefix(verifier.to_hex_string()));
  }

  SrpProof computeProof(const std::string &username,
                        const std::string &password,
                        const std::string &srpSaltHex,
                        const std::string &serverPublicHex) {
    Botan::AutoSeeded_RNG rng;

    const Botan::BigInt serverPublic =
        Botan::BigInt::from_string("0x" + serverPublicHex);
    const auto saltBytes = Botan::hex_decode(srpSaltHex);

    const Botan::DL_Group group = Botan::DL_Group::from_name(SRP_GROUP);
    const Botan::BigInt &N = group.get_p();
    const Botan::BigInt &g = group.get_g();

    // k = H(N_padded || g_padded) — RFC 5054
    const auto N_bytes = N.serialize(SRP_FIELD_BYTES);
    const auto g_bytes_padded_k = g.serialize(SRP_FIELD_BYTES);
    const auto k_hash = sha256({{N_bytes.data(), N_bytes.size()},
                                {g_bytes_padded_k.data(), g_bytes_padded_k.size()}});
    const Botan::BigInt k(k_hash.data(), k_hash.size());

    // Ephemeral a, A = g^a mod N
    const Botan::BigInt a(rng, 256);
    m_clientPublic = group.power_g_p(a, N.bits());

    // u = H(pad(A) || pad(B))
    const auto A_bytes = m_clientPublic.serialize(SRP_FIELD_BYTES);
    const auto B_bytes = serverPublic.serialize(SRP_FIELD_BYTES);
    const auto u_hash = sha256({{A_bytes.data(), A_bytes.size()},
                                {B_bytes.data(), B_bytes.size()}});
    const Botan::BigInt u(u_hash.data(), u_hash.size());

    // x = H(salt || H(username:password))
    const std::string cred = username + ":" + password;
    const auto h_cred = sha256(
        {{reinterpret_cast<const uint8_t *>(cred.data()), cred.size()}});
    const auto x_bytes = sha256({{saltBytes.data(), saltBytes.size()},
                                 {h_cred.data(), h_cred.size()}});
    const Botan::BigInt x(x_bytes.data(), x_bytes.size());

    // S = (B - k*g^x mod N)^(a + u*x) mod N
    const Botan::Modular_Reducer mod_N(N);
    const Botan::BigInt gx   = group.power_g_p(x, N.bits());
    const Botan::BigInt kgx  = mod_N.reduce(k * gx);
    const Botan::BigInt base = mod_N.reduce(serverPublic - kgx + N);
    const Botan::BigInt S    = Botan::power_mod(base, a + u * x, N);

    // K = H(minimal S bytes) — pysrp uses long_to_bytes(S) without padding
    const auto S_min = S.serialize();
    m_sessionKey = sha256({{S_min.data(), S_min.size()}});

    // Conversions to big endian
    const auto modulusBytes = N.serialize(SRP_FIELD_BYTES);
    const auto clientPublicBytes = m_clientPublic.serialize(SRP_FIELD_BYTES);
    const auto serverPublicBytes = serverPublic.serialize(SRP_FIELD_BYTES);

    const auto hashModulus =
        sha256({{modulusBytes.data(), modulusBytes.size()}});
    const auto hashGenerator =
        sha256({{g_bytes_padded_k.data(), g_bytes_padded_k.size()}});
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


    return {toLower(stripHexPrefix(m_clientPublic.to_hex_string())),
            toLower(Botan::hex_encode(m_clientProof))};
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
