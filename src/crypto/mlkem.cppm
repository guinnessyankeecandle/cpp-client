module;
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.mlkem;
import securemsg.crypto.random;

export constexpr int MLKEM1024_PUB_BYTES = 1568;  // FIPS 203 encapsulation key
export constexpr int MLKEM1024_PRIV_BYTES = 3168; // FIPS 203 decapsulation key
export constexpr int MLKEM1024_CT_BYTES = 1568;
export constexpr int MLKEM1024_SS_BYTES = 32;

export struct MlKemKeyPair {
  std::vector<uint8_t> priv;
  std::vector<uint8_t> pub;
};

export struct MlKemEncapResult {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> sharedSecret;
};

using PkeyCtxPtr =
    OsslHandle<EVP_PKEY_CTX,
               EVP_PKEY_CTX_free>; // public-private key operation context
using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>; // public-private key

export MlKemKeyPair mlkemGenerate() {
  const auto ctx =
      PkeyCtxPtr(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
  if (!ctx)
    throw std::runtime_error("ML-KEM-1024 CTX_new failed");

  sslAssert(EVP_PKEY_keygen_init(ctx.get()), "ML-KEM-1024 keygen_init");

  const auto pkey = [&] {
    EVP_PKEY *tmp = nullptr;
    sslAssert(EVP_PKEY_keygen(ctx.get(), &tmp), "ML-KEM-1024 keygen");
    return PkeyPtr(tmp);
  }();

  MlKemKeyPair kp;
  std::size_t privLen = 0, pubLen = 0;

  EVP_PKEY_get_raw_private_key(pkey.get(), nullptr, &privLen);
  EVP_PKEY_get_raw_public_key(pkey.get(), nullptr, &pubLen);

  kp.priv.resize(privLen);
  kp.pub.resize(pubLen);

  sslAssert(EVP_PKEY_get_raw_private_key(pkey.get(), kp.priv.data(), &privLen),
            "ML-KEM-1024 get_raw_private_key");

  sslAssert(EVP_PKEY_get_raw_public_key(pkey.get(), kp.pub.data(), &pubLen),
            "ML-KEM-1024 get_raw_public_key");
  return kp;
}

export MlKemEncapResult mlkemEncap(const std::vector<uint8_t> &pubKey) {
  const auto pub = PkeyPtr(EVP_PKEY_new_raw_public_key_ex(
      nullptr, "ML-KEM-1024", nullptr, pubKey.data(), pubKey.size()));
  if (!pub)
    throw std::runtime_error("ML-KEM-1024 new_raw_public_key failed");
  const auto ctx =
      PkeyCtxPtr(EVP_PKEY_CTX_new_from_pkey(nullptr, pub.get(), nullptr));
  if (!ctx)
    throw std::runtime_error("ML-KEM-1024 CTX_new_from_pkey failed");
  sslAssert(EVP_PKEY_encapsulate_init(ctx.get(), nullptr),
            "ML-KEM-1024 encap_init");
  std::size_t ctLen = 0, ssLen = 0;
  sslAssert(EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctLen, nullptr, &ssLen),
            "ML-KEM-1024 encap size");
  MlKemEncapResult res;
  res.ciphertext.resize(ctLen);
  res.sharedSecret.resize(ssLen);
  sslAssert(EVP_PKEY_encapsulate(ctx.get(), res.ciphertext.data(), &ctLen,
                                 res.sharedSecret.data(), &ssLen),
            "ML-KEM-1024 encap");
  return res;
}

export std::vector<uint8_t> mlkemDecap(const std::vector<uint8_t> &privKey,
                                       const std::vector<uint8_t> &ciphertext) {
  const auto priv = PkeyPtr(EVP_PKEY_new_raw_private_key_ex(
      nullptr, "ML-KEM-1024", nullptr, privKey.data(), privKey.size()));
  if (!priv)
    throw std::runtime_error("ML-KEM-1024 new_raw_private_key failed");
  const auto ctx =
      PkeyCtxPtr(EVP_PKEY_CTX_new_from_pkey(nullptr, priv.get(), nullptr));
  if (!ctx)
    throw std::runtime_error("ML-KEM-1024 CTX_new_from_pkey failed");
  sslAssert(EVP_PKEY_decapsulate_init(ctx.get(), nullptr),
            "ML-KEM-1024 decap_init");
  std::size_t ssLen = 0;
  sslAssert(EVP_PKEY_decapsulate(ctx.get(), nullptr, &ssLen, ciphertext.data(),
                                 ciphertext.size()),
            "ML-KEM-1024 decap size");
  std::vector<uint8_t> ss(ssLen);
  sslAssert(EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ssLen,
                                 ciphertext.data(), ciphertext.size()),
            "ML-KEM-1024 decap");
  return ss;
}
