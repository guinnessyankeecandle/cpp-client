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
#include <vector>
export module securemsg.crypto.random;

export {
  template <typename T, auto DelFn>
  using OssPtr =
      std::unique_ptr<T, std::integral_constant<decltype(DelFn), DelFn>>;
}

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

using BioChainPtr = OssPtr<BIO, BIO_free_all>;

export std::string base64Encode(const std::span<const uint8_t> data) {
  const auto b64 = BioChainPtr(BIO_new(BIO_f_base64()));
  if (!b64)
    throw std::runtime_error("BIO_new failed");

  BIO *mem = BIO_new(BIO_s_mem());
  if (!mem)
    throw std::runtime_error("BIO_new failed");

  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

  BIO_push(b64.get(), mem); // b64 chain now owns mem
  if (!data.empty())
    BIO_write(b64.get(), data.data(), static_cast<int>(data.size()));

  BIO_flush(b64.get()); // flush all buffered data
  const char *ptr = nullptr;
  const long len = BIO_get_mem_data(mem, &ptr);
  return {ptr, static_cast<std::size_t>(len)};
}

export std::vector<uint8_t> base64Decode(const std::string &encoded) {
  if (encoded.empty())
    return {};

  const auto b64 = BioChainPtr(BIO_new(BIO_f_base64()));
  if (!b64)
    throw std::runtime_error("BIO_new failed");

  BIO *mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
  if (!mem)
    throw std::runtime_error("BIO_new_mem_buf failed");

  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

  BIO_push(b64.get(), mem); // b64 chain now owns mem
  std::vector<uint8_t> out(encoded.size());
  const int len = BIO_read(b64.get(), out.data(), static_cast<int>(out.size()));

  if (len < 0)
    throw std::runtime_error("base64Decode failed");

  out.resize(static_cast<std::size_t>(len));
  return out;
}
