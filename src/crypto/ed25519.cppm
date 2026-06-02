module;
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.ed25519;
import securemsg.crypto.random;

using PkeyCtxPtr =
    OssPtr<EVP_PKEY_CTX,
           EVP_PKEY_CTX_free>; // public-private key operation context
using PkeyPtr = OssPtr<EVP_PKEY, EVP_PKEY_free>;      // public-private key
using MdCtxPtr = OssPtr<EVP_MD_CTX, EVP_MD_CTX_free>; // message digest

export constexpr int ED25519_PRIV_BYTES = 32;
export constexpr int ED25519_PUB_BYTES = 32;
export constexpr int ED25519_SIG_BYTES = 64;

export RawKeyPair ed25519Generate() {
  auto [priv, pub] = generateRawKeyPair(EVP_PKEY_ED25519, "Ed25519");
  return {std::move(priv), std::move(pub)};
}

export std::vector<uint8_t> ed25519Sign(const std::vector<uint8_t> &privKey,
                                        const std::vector<uint8_t> &message) {
  const auto private_key_object = PkeyPtr(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, privKey.data(), privKey.size()));
  if (!private_key_object)
    throw std::runtime_error("Ed25519 new_raw_private_key failed");

  const auto ctx = MdCtxPtr(EVP_MD_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");

  // initilize the signing
  sslAssert(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr,
                               private_key_object.get()),
            "Ed25519 DigestSignInit");

  std::size_t sigLen = 0;
  EVP_DigestSign(ctx.get(), nullptr, &sigLen, message.data(), message.size());
  std::vector<uint8_t> sig(sigLen);

  sslAssert(EVP_DigestSign(ctx.get(), sig.data(), &sigLen, message.data(),
                           message.size()),
            "Ed25519 DigestSign");
  return sig;
}

export bool ed25519Verify(const std::vector<uint8_t> &pubKey,
                          const std::vector<uint8_t> &message,
                          const std::vector<uint8_t> &signature) {
  const auto public_key = PkeyPtr(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, pubKey.data(), pubKey.size()));
  if (!public_key)
    throw std::runtime_error("Ed25519 new_raw_public_key failed");

  const auto ctx = MdCtxPtr(EVP_MD_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");
  sslAssert(EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr,
                                 public_key.get()),
            "Ed25519 DigestVerifyInit");

  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                          message.data(), message.size()) == 1;
}
