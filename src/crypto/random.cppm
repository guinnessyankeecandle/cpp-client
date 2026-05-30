module;
#include <cstdint>
#include <memory>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
export module securemsg.crypto.random;

export {
  template <typename T, auto DelFn>
  using OsslHandle =
      std::unique_ptr<T, std::integral_constant<decltype(DelFn), DelFn>>;
}

export inline void sslAssert(int rc, std::string_view op) {
  if (rc != 1)
    throw std::runtime_error(std::string(op) + " failed");
}

export std::vector<uint8_t> randomBytes(std::size_t n) {
  std::vector<uint8_t> buf(n);
  if (n > 0)
    sslAssert(RAND_bytes(buf.data(), static_cast<int>(n)), "RAND_bytes");
  return buf;
}

export std::string base64Encode(std::span<const uint8_t> data) {
  BIO *b64raw = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new(BIO_s_mem());
  BIO_set_flags(b64raw, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64raw, mem);
  if (!data.empty())
    BIO_write(b64raw, data.data(), static_cast<int>(data.size()));
  BIO_flush(b64raw);
  const char *ptr = nullptr;
  long len = BIO_get_mem_data(mem, &ptr);
  std::string result(ptr, static_cast<std::size_t>(len));
  BIO_free_all(b64raw);
  return result;
}

export std::vector<uint8_t> base64Decode(const std::string &encoded) {
  if (encoded.empty())
    return {};
  BIO *b64raw = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
  BIO_set_flags(b64raw, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64raw, mem);
  std::vector<uint8_t> out(encoded.size());
  int len = BIO_read(b64raw, out.data(), static_cast<int>(out.size()));
  BIO_free_all(b64raw);
  if (len < 0)
    throw std::runtime_error("base64Decode failed");
  out.resize(static_cast<std::size_t>(len));
  return out;
}
