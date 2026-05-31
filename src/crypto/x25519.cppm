module;
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.x25519;
import securemsg.crypto.random;

export constexpr std::size_t X25519_KEY_BYTES = 32;

using PkeyPtr = OssPtr<EVP_PKEY, EVP_PKEY_free>;
using PkeyCtxPtr = OssPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

export RawKeyPair x25519Generate() {
  auto [priv, pub] = generateRawKeyPair(EVP_PKEY_X25519, "X25519");
  return {std::move(priv), std::move(pub)};
}

export std::vector<uint8_t> x25519DH(const std::vector<uint8_t> &privKey,
                                     const std::vector<uint8_t> &peerPub) {

  const auto priv_key = PkeyPtr(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, privKey.data(), privKey.size()));
  if (!priv_key)
    throw std::runtime_error("X25519 new_raw_private_key failed");

  const auto peer_key = PkeyPtr(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peerPub.data(), peerPub.size()));
  if (!peer_key)
    throw std::runtime_error("X25519 new_raw_public_key failed");

  const auto ctx = PkeyCtxPtr(EVP_PKEY_CTX_new(priv_key.get(), nullptr));
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new failed");

  sslAssert(EVP_PKEY_derive_init(ctx.get()), "X25519 derive_init");
  sslAssert(EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()),
            "X25519 derive_set_peer");

  std::size_t sharedLen = 0;
  EVP_PKEY_derive(ctx.get(), nullptr, &sharedLen);
  std::vector<uint8_t> shared(sharedLen);
  sslAssert(EVP_PKEY_derive(ctx.get(), shared.data(), &sharedLen),
            "X25519 derive");
  return shared;
}

export std::vector<uint8_t>
x25519PublicFromPrivate(const std::vector<uint8_t> &priv) {
  const auto key_private_ptr = PkeyPtr(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, priv.data(), priv.size()));
  if (!key_private_ptr)
    throw std::runtime_error("X25519 new_raw_private_key failed");
  std::size_t pubLen = 0;
  EVP_PKEY_get_raw_public_key(key_private_ptr.get(), nullptr, &pubLen);
  std::vector<uint8_t> pub(pubLen);
  sslAssert(EVP_PKEY_get_raw_public_key(key_private_ptr.get(), pub.data(), &pubLen),
            "X25519 get_raw_public_key");
  return pub;
}
