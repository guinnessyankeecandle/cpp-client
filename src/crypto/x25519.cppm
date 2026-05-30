module;
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.x25519;
import securemsg.crypto.random;

export constexpr int X25519_KEY_BYTES = 32;

export struct X25519KeyPair {
  std::vector<uint8_t> priv;
  std::vector<uint8_t> pub;
};

export X25519KeyPair x25519Generate() {
  using PkeyCtxPtr = OsslHandle<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;

  auto ctx = PkeyCtxPtr(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new_id X25519 failed");
  sslAssert(EVP_PKEY_keygen_init(ctx.get()), "X25519 keygen_init");

  const auto pkey = [&] {
    EVP_PKEY *tmp = nullptr;
    sslAssert(EVP_PKEY_keygen(ctx.get(), &tmp), "X25519 keygen");
    return PkeyPtr(tmp);
  }();

  X25519KeyPair kp;
  kp.priv.resize(X25519_KEY_BYTES);
  kp.pub.resize(X25519_KEY_BYTES);
  std::size_t privLen = X25519_KEY_BYTES, pubLen = X25519_KEY_BYTES;
  sslAssert(EVP_PKEY_get_raw_private_key(pkey.get(), kp.priv.data(), &privLen),
            "X25519 get_raw_private_key");
  sslAssert(EVP_PKEY_get_raw_public_key(pkey.get(), kp.pub.data(), &pubLen),
            "X25519 get_raw_public_key");
  return kp;
}

export std::vector<uint8_t> x25519DH(const std::vector<uint8_t> &privKey,
                                     const std::vector<uint8_t> &peerPub) {
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;
  using PkeyCtxPtr = OsslHandle<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

  auto priv = PkeyPtr(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, privKey.data(), privKey.size()));
  if (!priv)
    throw std::runtime_error("X25519 new_raw_private_key failed");

  auto peer = PkeyPtr(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peerPub.data(), peerPub.size()));
  if (!peer)
    throw std::runtime_error("X25519 new_raw_public_key failed");

  auto ctx = PkeyCtxPtr(EVP_PKEY_CTX_new(priv.get(), nullptr));
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new failed");
  sslAssert(EVP_PKEY_derive_init(ctx.get()), "X25519 derive_init");
  sslAssert(EVP_PKEY_derive_set_peer(ctx.get(), peer.get()),
            "X25519 derive_set_peer");

  std::size_t sharedLen = X25519_KEY_BYTES;
  std::vector<uint8_t> shared(sharedLen);
  sslAssert(EVP_PKEY_derive(ctx.get(), shared.data(), &sharedLen),
            "X25519 derive");
  return shared;
}

export std::vector<uint8_t>
x25519PublicFromPrivate(const std::vector<uint8_t> &priv) {
  using PkeyPtr = OsslHandle<EVP_PKEY, EVP_PKEY_free>;
  auto pkey = PkeyPtr(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                   priv.data(), priv.size()));
  if (!pkey)
    throw std::runtime_error("X25519 new_raw_private_key failed");
  std::vector<uint8_t> pub(X25519_KEY_BYTES);
  std::size_t pubLen = X25519_KEY_BYTES;
  sslAssert(EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pubLen),
            "X25519 get_raw_public_key");
  return pub;
}
