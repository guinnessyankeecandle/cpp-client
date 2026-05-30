module;
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.ed25519;
import securemsg.crypto.random;

export constexpr int ED25519_PRIV_BYTES = 32;
export constexpr int ED25519_PUB_BYTES = 32;
export constexpr int ED25519_SIG_BYTES = 64;

export struct Ed25519KeyPair {
  std::vector<uint8_t> priv;
  std::vector<uint8_t> pub;
};

export Ed25519KeyPair ed25519Generate() {
  using PkeyCtxPtr = OsslHandle<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;

  auto ctx = PkeyCtxPtr(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new_id Ed25519 failed");
  sslAssert(EVP_PKEY_keygen_init(ctx.get()), "Ed25519 keygen_init");

  EVP_PKEY *raw = nullptr;
  sslAssert(EVP_PKEY_keygen(ctx.get(), &raw), "Ed25519 keygen");
  auto pkey = PkeyPtr(raw);

  Ed25519KeyPair kp;
  kp.priv.resize(ED25519_PRIV_BYTES);
  kp.pub.resize(ED25519_PUB_BYTES);
  std::size_t privLen = ED25519_PRIV_BYTES, pubLen = ED25519_PUB_BYTES;
  sslAssert(EVP_PKEY_get_raw_private_key(pkey.get(), kp.priv.data(), &privLen),
            "Ed25519 get_raw_private_key");
  sslAssert(EVP_PKEY_get_raw_public_key(pkey.get(), kp.pub.data(), &pubLen),
            "Ed25519 get_raw_public_key");
  return kp;
}

export std::vector<uint8_t> ed25519Sign(const std::vector<uint8_t> &privKey,
                                        const std::vector<uint8_t> &message) {
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;
  using MdCtxPtr = OsslHandle<EVP_MD_CTX, EVP_MD_CTX_free>;

  auto pkey = PkeyPtr(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, privKey.data(), privKey.size()));
  if (!pkey)
    throw std::runtime_error("Ed25519 new_raw_private_key failed");

  auto ctx = MdCtxPtr(EVP_MD_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");
  sslAssert(
      EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()),
      "Ed25519 DigestSignInit");

  std::size_t sigLen = ED25519_SIG_BYTES;
  std::vector<uint8_t> sig(sigLen);
  sslAssert(EVP_DigestSign(ctx.get(), sig.data(), &sigLen, message.data(),
                           message.size()),
            "Ed25519 DigestSign");
  sig.resize(sigLen);
  return sig;
}

export bool ed25519Verify(const std::vector<uint8_t> &pubKey,
                          const std::vector<uint8_t> &message,
                          const std::vector<uint8_t> &signature) {
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;
  using MdCtxPtr = OsslHandle<EVP_MD_CTX, EVP_MD_CTX_free>;

  auto pkey = PkeyPtr(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, pubKey.data(), pubKey.size()));
  if (!pkey)
    throw std::runtime_error("Ed25519 new_raw_public_key failed");

  auto ctx = MdCtxPtr(EVP_MD_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");
  sslAssert(
      EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()),
      "Ed25519 DigestVerifyInit");

  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                          message.data(), message.size()) == 1;
}
