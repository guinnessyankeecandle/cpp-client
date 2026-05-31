module;
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.srp;
import securemsg.crypto.random;

static constexpr const char *SRP_N_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
    "FFFFFFFFFFFFFFFF";

static constexpr uint8_t SRP_G = 5;

using BnPtr = OssPtr<BIGNUM, BN_free>;
using BnCtxPtr = OssPtr<BN_CTX, BN_CTX_free>;

static std::vector<uint8_t> sha256Multi(
    std::initializer_list<std::pair<const uint8_t *, std::size_t>> parts) {
  using MdCtxPtr = OssPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
  auto ctx = MdCtxPtr(EVP_MD_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");
  sslAssert(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr), "DigestInit");
  for (auto &[data, len] : parts)
    sslAssert(EVP_DigestUpdate(ctx.get(), data, len), "DigestUpdate");
  std::vector<uint8_t> out(32);
  unsigned int outLen = 32;
  sslAssert(EVP_DigestFinal_ex(ctx.get(), out.data(), &outLen), "DigestFinal");
  return out;
}

export std::string srpComputeVerifier(const std::string &username,
                                      const std::string &password,
                                      std::string &saltHexOut) {
  auto saltBytes = randomBytes(32);
  auto bnCtx = BnCtxPtr(BN_CTX_new());
  BIGNUM *Nraw = nullptr;
  BN_hex2bn(&Nraw, SRP_N_HEX);
  auto N = BnPtr(Nraw);
  auto g = BnPtr(BN_new());
  BN_set_word(g.get(), SRP_G);

  std::string credentials = username + ":" + password;
  auto innerHash =
      sha256Multi({{reinterpret_cast<const uint8_t *>(credentials.data()),
                    credentials.size()}});
  auto x_bytes = sha256Multi({{saltBytes.data(), saltBytes.size()},
                              {innerHash.data(), innerHash.size()}});
  auto x = BnPtr(BN_new());
  BN_bin2bn(x_bytes.data(), static_cast<int>(x_bytes.size()), x.get());

  auto v = BnPtr(BN_new());
  BN_mod_exp(v.get(), g.get(), x.get(), N.get(), bnCtx.get());

  std::vector<uint8_t> saltPadded(64, 0);
  std::copy(saltBytes.begin(), saltBytes.end(), saltPadded.begin());

  BIGNUM *saltBnRaw = nullptr;
  BN_bin2bn(saltPadded.data(), static_cast<int>(saltPadded.size()), saltBnRaw);
  // Use saltPadded directly for hex conversion
  char *saltHex = BN_bn2hex(BN_bin2bn(
      saltPadded.data(), static_cast<int>(saltPadded.size()), nullptr));
  char *vHex = BN_bn2hex(v.get());
  saltHexOut = saltHex;
  std::string verifierHex = vHex;
  OPENSSL_free(saltHex);
  OPENSSL_free(vHex);
  OPENSSL_cleanse(x_bytes.data(), x_bytes.size());
  return verifierHex;
}

export class SrpSession {
public:
  std::string begin(const std::string &username, const std::string &password) {
    m_username = username;
    m_password = password;
    BIGNUM *Nraw = nullptr;
    BN_hex2bn(&Nraw, SRP_N_HEX);
    auto N = BnPtr(Nraw);
    auto aBytes = randomBytes(32);
    auto a = BnPtr(BN_new());
    BN_bin2bn(aBytes.data(), static_cast<int>(aBytes.size()), a.get());
    auto g = BnPtr(BN_new());
    BN_set_word(g.get(), SRP_G);
    auto A = BnPtr(BN_new());
    auto ctx = BnCtxPtr(BN_CTX_new());
    BN_mod_exp(A.get(), g.get(), a.get(), N.get(), ctx.get());
    m_a_bytes.resize(static_cast<std::size_t>(BN_num_bytes(a.get())));
    BN_bn2bin(a.get(), m_a_bytes.data());
    m_A_bytes.resize(512);
    BN_bn2binpad(A.get(), m_A_bytes.data(), 512);
    char *hex = BN_bn2hex(A.get());
    std::string result = hex;
    OPENSSL_free(hex);
    return result;
  }

  std::string computeProof(const std::string &srpSaltHex,
                           const std::string &serverPublicHex) {
    BIGNUM *Nraw = nullptr;
    BN_hex2bn(&Nraw, SRP_N_HEX);
    auto N = BnPtr(Nraw);
    auto g = BnPtr(BN_new());
    BN_set_word(g.get(), SRP_G);
    auto ctx = BnCtxPtr(BN_CTX_new());

    std::vector<uint8_t> nBytes(512);
    BN_bn2binpad(N.get(), nBytes.data(), 512);
    uint8_t gByte = SRP_G;
    auto kBytes = sha256Multi({{nBytes.data(), nBytes.size()}, {&gByte, 1}});
    auto k = BnPtr(BN_new());
    BN_bin2bn(kBytes.data(), static_cast<int>(kBytes.size()), k.get());

    BIGNUM *Braw = nullptr;
    BN_hex2bn(&Braw, serverPublicHex.c_str());
    auto B = BnPtr(Braw);
    BIGNUM *saltRaw = nullptr;
    BN_hex2bn(&saltRaw, srpSaltHex.c_str());
    auto salt = BnPtr(saltRaw);
    std::vector<uint8_t> saltBytes(
        static_cast<std::size_t>(BN_num_bytes(salt.get())));
    BN_bn2bin(salt.get(), saltBytes.data());

    std::vector<uint8_t> BPad(512);
    BN_bn2binpad(B.get(), BPad.data(), 512);
    auto uBytes = sha256Multi(
        {{m_A_bytes.data(), m_A_bytes.size()}, {BPad.data(), BPad.size()}});
    auto u = BnPtr(BN_new());
    BN_bin2bn(uBytes.data(), static_cast<int>(uBytes.size()), u.get());

    std::string cred = m_username + ":" + m_password;
    auto inner = sha256Multi(
        {{reinterpret_cast<const uint8_t *>(cred.data()), cred.size()}});
    auto xBytes = sha256Multi(
        {{saltBytes.data(), saltBytes.size()}, {inner.data(), inner.size()}});
    auto x = BnPtr(BN_new());
    BN_bin2bn(xBytes.data(), static_cast<int>(xBytes.size()), x.get());

    auto gx = BnPtr(BN_new());
    BN_mod_exp(gx.get(), g.get(), x.get(), N.get(), ctx.get());
    auto kgx = BnPtr(BN_new());
    BN_mod_mul(kgx.get(), k.get(), gx.get(), N.get(), ctx.get());
    auto base = BnPtr(BN_new());
    BN_mod_sub(base.get(), B.get(), kgx.get(), N.get(), ctx.get());
    auto a = BnPtr(BN_new());
    BN_bin2bn(m_a_bytes.data(), static_cast<int>(m_a_bytes.size()), a.get());
    auto ux = BnPtr(BN_new());
    BN_mul(ux.get(), u.get(), x.get(), ctx.get());
    auto exp = BnPtr(BN_new());
    BN_add(exp.get(), a.get(), ux.get());
    auto S = BnPtr(BN_new());
    BN_mod_exp(S.get(), base.get(), exp.get(), N.get(), ctx.get());

    std::vector<uint8_t> SBytes(512);
    BN_bn2binpad(S.get(), SBytes.data(), 512);
    m_K = sha256Multi({{SBytes.data(), SBytes.size()}});

    auto hashN = sha256Multi({{nBytes.data(), nBytes.size()}});
    auto hashG = sha256Multi({{&gByte, 1}});
    std::vector<uint8_t> xorNG(32);
    for (int i = 0; i < 32; ++i)
      xorNG[i] = hashN[i] ^ hashG[i];
    auto hashUser =
        sha256Multi({{reinterpret_cast<const uint8_t *>(m_username.data()),
                      m_username.size()}});
    m_M1 = sha256Multi({{xorNG.data(), xorNG.size()},
                        {hashUser.data(), hashUser.size()},
                        {saltBytes.data(), saltBytes.size()},
                        {m_A_bytes.data(), m_A_bytes.size()},
                        {BPad.data(), BPad.size()},
                        {m_K.data(), m_K.size()}});

    OPENSSL_cleanse(xBytes.data(), xBytes.size());
    BIGNUM *m1Bn =
        BN_bin2bn(m_M1.data(), static_cast<int>(m_M1.size()), nullptr);
    char *hex = BN_bn2hex(m1Bn);
    BN_free(m1Bn);
    std::string result = hex;
    OPENSSL_free(hex);
    return result;
  }

  bool verifyServerProof(const std::string &serverProofHex) const {
    auto expected = sha256Multi({{m_A_bytes.data(), m_A_bytes.size()},
                                 {m_M1.data(), m_M1.size()},
                                 {m_K.data(), m_K.size()}});
    BIGNUM *serverM2Bn = nullptr;
    BN_hex2bn(&serverM2Bn, serverProofHex.c_str());
    std::vector<uint8_t> serverM2(32);
    BN_bn2binpad(serverM2Bn, serverM2.data(), 32);
    BN_free(serverM2Bn);
    return CRYPTO_memcmp(expected.data(), serverM2.data(), 32) == 0;
  }

  ~SrpSession() {
    if (!m_a_bytes.empty())
      OPENSSL_cleanse(m_a_bytes.data(), m_a_bytes.size());
    if (!m_K.empty())
      OPENSSL_cleanse(m_K.data(), m_K.size());
    if (!m_M1.empty())
      OPENSSL_cleanse(m_M1.data(), m_M1.size());
  }

private:
  std::string m_username;
  std::string m_password;
  std::vector<uint8_t> m_a_bytes;
  std::vector<uint8_t> m_A_bytes;
  std::vector<uint8_t> m_K;
  std::vector<uint8_t> m_M1;
};
