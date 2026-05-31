module;
#include <algorithm>
#include <cstdint>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.random;

export {
  template <typename T, auto DelFn>
  using OssPtr =
      std::unique_ptr<T, std::integral_constant<decltype(DelFn), DelFn>>;
}

using PkeyCtxPtr = OssPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using PkeyPtr = OssPtr<EVP_PKEY, EVP_PKEY_free>;

export inline void sslAssert(const int return_code, const char *op) {
  if (return_code != 1)
    throw std::runtime_error(std::string(op) + " failed");
}

export std::vector<uint8_t> randomBytes(const std::size_t numBytes) {
  std::vector<uint8_t> buf(numBytes);
  if (numBytes > 0)
    sslAssert(RAND_bytes(buf.data(), static_cast<int>(numBytes)), "RAND_bytes");
  return buf;
}

export struct RawKeyPair {
  std::vector<uint8_t> priv;
  std::vector<uint8_t> pub;
};

export RawKeyPair generateRawKeyPair(const int evpKeyType, const char *name) {
  const auto ctx = PkeyCtxPtr(EVP_PKEY_CTX_new_id(evpKeyType, nullptr));
  if (!ctx)
    throw std::runtime_error(std::string(name) + " CTX_new_id failed");
  sslAssert(EVP_PKEY_keygen_init(ctx.get()),
            (std::string(name) + " keygen_init").c_str());

  const auto key_pair_ptr = [&] {
    EVP_PKEY *tmp = nullptr;
    sslAssert(EVP_PKEY_keygen(ctx.get(), &tmp),
              (std::string(name) + " keygen").c_str());
    return PkeyPtr(tmp);
  }();

  std::size_t privLen = 0, pubLen = 0;
  EVP_PKEY_get_raw_private_key(key_pair_ptr.get(), nullptr, &privLen);
  EVP_PKEY_get_raw_public_key(key_pair_ptr.get(), nullptr, &pubLen);

  RawKeyPair kp;
  kp.priv.resize(privLen);
  kp.pub.resize(pubLen);
  sslAssert(EVP_PKEY_get_raw_private_key(key_pair_ptr.get(), kp.priv.data(),
                                         &privLen),
            (std::string(name) + " get_raw_private_key").c_str());
  sslAssert(
      EVP_PKEY_get_raw_public_key(key_pair_ptr.get(), kp.pub.data(), &pubLen),
      (std::string(name) + " get_raw_public_key").c_str());
  return kp;
}

export std::string base64Encode(const std::span<const uint8_t> data) {
  if (data.empty())
    return {};

  std::string out;
  out.resize(EVP_ENCODE_LENGTH(data.size()));
  const int len = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(out.data()),
                                  data.data(), static_cast<int>(data.size()));

  out.resize(static_cast<std::size_t>(len));
  return out;
}

export std::vector<uint8_t> base64Decode(const std::string &encoded) {
  if (encoded.empty())
    return {};

  std::vector<uint8_t> out;
  out.resize(EVP_DECODE_LENGTH(encoded.size()));

  const int len = EVP_DecodeBlock(
      out.data(), reinterpret_cast<const uint8_t *>(encoded.data()),
      static_cast<int>(encoded.size()));

  if (len < 0)
    throw std::runtime_error("base64Decode failed");

  // Strip padding bytes that EVP_DecodeBlock counts in its output length
  const std::size_t padding = std::ranges::count(encoded, '=');
  out.resize(static_cast<std::size_t>(len) - padding);
  return out;
}
