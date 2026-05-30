module;
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.aead;
import securemsg.crypto.random;

export struct AeadPacket {
  std::vector<uint8_t> iv;
  std::vector<uint8_t> tag;
  std::vector<uint8_t> ciphertext;
};

export constexpr int IV_BYTES = 12;
export constexpr int TAG_BYTES = 16;
export constexpr int KEY_BYTES = 32;

export AeadPacket aeadEncrypt(const std::vector<uint8_t> &plaintext,
                              const std::vector<uint8_t> &key) {
  using CipherCtxPtr = OsslHandle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

  AeadPacket packet;
  // Random defensive in case 2 messages share the same key (shouldn't happen with double rachet)
  packet.iv = randomBytes(IV_BYTES);
  packet.tag.resize(TAG_BYTES);
  packet.ciphertext.resize(plaintext.size());

  const auto ctx = CipherCtxPtr(EVP_CIPHER_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  sslAssert(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr),
            "EncryptInit");
  sslAssert(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                               packet.iv.data()),
            "EncryptInit key/iv");

  int outLen = 0;
  if (!plaintext.empty())
    sslAssert(EVP_EncryptUpdate(ctx.get(), packet.ciphertext.data(), &outLen,
                                plaintext.data(),
                                static_cast<int>(plaintext.size())),
              "EncryptUpdate");

  sslAssert(
      EVP_EncryptFinal_ex(ctx.get(), packet.ciphertext.data() + outLen, &outLen),
      "EncryptFinal");
  sslAssert(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_BYTES,
                                packet.tag.data()),
            "GetTag");
  return packet;
}

export std::vector<uint8_t> aeadDecrypt(const AeadPacket &pkt,
                                        const std::vector<uint8_t> &key) {
  using CipherCtxPtr = OsslHandle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

  if (static_cast<int>(pkt.iv.size()) != IV_BYTES ||
      static_cast<int>(pkt.tag.size()) != TAG_BYTES)
    throw std::runtime_error("Invalid AEAD packet");

  const auto ctx = CipherCtxPtr(EVP_CIPHER_CTX_new());
  if (!ctx)
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  sslAssert(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr),
            "DecryptInit");
  sslAssert(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                               pkt.iv.data()),
            "DecryptInit key/iv");

  std::vector<uint8_t> plain(pkt.ciphertext.size());
  int outLen = 0;
  if (!pkt.ciphertext.empty())
    sslAssert(EVP_DecryptUpdate(ctx.get(), plain.data(), &outLen,
                                pkt.ciphertext.data(),
                                static_cast<int>(pkt.ciphertext.size())),
              "DecryptUpdate");

  sslAssert(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_BYTES,
                                const_cast<uint8_t *>(pkt.tag.data())),
            "SetTag");

  if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + outLen, &outLen) != 1)
    throw std::runtime_error("AEAD authentication failed");

  return plain;
}

export std::vector<uint8_t> packAead(const AeadPacket &pkt) {
  std::vector<uint8_t> out;
  out.reserve(IV_BYTES + TAG_BYTES + pkt.ciphertext.size());
  out.insert(out.end(), pkt.iv.begin(), pkt.iv.end());
  out.insert(out.end(), pkt.tag.begin(), pkt.tag.end());
  out.insert(out.end(), pkt.ciphertext.begin(), pkt.ciphertext.end());
  return out;
}

export AeadPacket unpackAead(const std::vector<uint8_t> &raw) {
  if (raw.size() < static_cast<size_t>(IV_BYTES + TAG_BYTES))
    throw std::runtime_error("AEAD packet too short");
  AeadPacket pkt;
  pkt.iv.assign(raw.begin(), raw.begin() + IV_BYTES);
  pkt.tag.assign(raw.begin() + IV_BYTES, raw.begin() + IV_BYTES + TAG_BYTES);
  pkt.ciphertext.assign(raw.begin() + IV_BYTES + TAG_BYTES, raw.end());
  return pkt;
}
