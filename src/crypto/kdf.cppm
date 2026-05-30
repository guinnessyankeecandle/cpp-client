module;
#include <cstdint>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.kdf;
import securemsg.crypto.random;

using KdfCtxPtr = OsslHandle<EVP_KDF_CTX, EVP_KDF_CTX_free>;

export std::vector<uint8_t> hkdf(const std::vector<uint8_t> &ikm,
                                 const std::vector<uint8_t> &salt,
                                 const std::string &info,
                                 const std::size_t outLen) {

  EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (!kdf)
    throw std::runtime_error("EVP_KDF_fetch HKDF failed");

  // convert to a smart pointer
  const auto ctx = KdfCtxPtr(EVP_KDF_CTX_new(kdf));
  EVP_KDF_free(kdf);
  if (!ctx)
    throw std::runtime_error("EVP_KDF_CTX_new failed");

  // Build params array conditionally to handle empty salt correctly
  OSSL_PARAM params[5];
  int pi = 0;

  params[pi++] = OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, const_cast<char *>("SHA256"), 0);

  params[pi++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());

  if (!salt.empty())
    params[pi++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt.data()), salt.size());

  params[pi++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, const_cast<char *>(info.data()), info.size());

  params[pi] = OSSL_PARAM_END;

  std::vector<uint8_t> out(outLen);
  sslAssert(EVP_KDF_derive(ctx.get(), out.data(), outLen, params),
            "HKDF derive");
  return out;
}

// 600,000 iterations — OWASP 2023 recommendation for PBKDF2-SHA256
static constexpr int PBKDF2_ITERATIONS = 600'000;

export std::vector<uint8_t> pbkdf2(const std::string &password,
                                   const std::vector<uint8_t> &salt,
                                   const std::size_t outLen) {
  std::vector<uint8_t> out(outLen);
  sslAssert(PKCS5_PBKDF2_HMAC(
                password.data(), static_cast<int>(password.size()), salt.data(),
                static_cast<int>(salt.size()), PBKDF2_ITERATIONS, EVP_sha256(),
                static_cast<int>(outLen), out.data()),
            "PBKDF2");
  return out;
}
