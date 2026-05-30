module;
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.keystore;
import securemsg.crypto.random;
import securemsg.crypto.aead;
import securemsg.crypto.kdf;
import securemsg.crypto.ed25519;
import securemsg.crypto.x25519;
import securemsg.crypto.mlkem;

export struct KeyBundle {
  Ed25519KeyPair ik;
  X25519KeyPair spk;
  std::vector<uint8_t> spkSig;
  MlKemKeyPair pq;
  std::vector<uint8_t> pqSig;
  std::vector<X25519KeyPair> opks;
};

static constexpr int PBKDF2_SALT_BYTES = 16;
static constexpr int OPK_BATCH_SIZE = 20;

export KeyBundle keystoreGenerate() {
  KeyBundle kb;
  kb.ik = ed25519Generate();
  kb.spk = x25519Generate();
  kb.spkSig = ed25519Sign(kb.ik.priv, kb.spk.pub);
  kb.pq = mlkemGenerate();
  kb.pqSig = ed25519Sign(kb.ik.priv, kb.pq.pub);
  kb.opks.reserve(OPK_BATCH_SIZE);
  for (int i = 0; i < OPK_BATCH_SIZE; ++i)
    kb.opks.push_back(x25519Generate());
  return kb;
}

export void keystoreSave(const std::string &path, const KeyBundle &kb,
                         const std::string &password) {
  std::vector<uint8_t> payload;
  const auto append = [&](const std::vector<uint8_t> &v) {
    std::ranges::copy(v, std::back_inserter(payload));
  };
  append(kb.ik.priv);
  append(kb.ik.pub);
  append(kb.spk.priv);
  append(kb.spk.pub);
  append(kb.spkSig);
  append(kb.pq.priv);
  append(kb.pq.pub);
  append(kb.pqSig);

  payload.push_back(static_cast<uint8_t>(kb.opks.size()));
  for (const auto &opk : kb.opks) {
    append(opk.priv);
    append(opk.pub);
  }

  auto salt = randomBytes(PBKDF2_SALT_BYTES);
  auto encKey = pbkdf2(password, salt, KEY_BYTES);
  auto pkt = aeadEncrypt(payload, encKey);

  // Clear sensitive data from memory
  OPENSSL_cleanse(encKey.data(), encKey.size());
  OPENSSL_cleanse(payload.data(), payload.size());

  // Write to a temp file first — if anything fails the original is untouched
  const std::string tmpPath = path + ".tmp";
  {
    std::ofstream key_file(tmpPath, std::ios::binary | std::ios::trunc);
    if (!key_file)
      throw std::runtime_error("Cannot open key file for writing: " + tmpPath);
    const auto packed = packAead(pkt);
    key_file.write(reinterpret_cast<const char *>(salt.data()),
                   PBKDF2_SALT_BYTES);
    key_file.write(reinterpret_cast<const char *>(packed.data()),
                   static_cast<std::streamsize>(packed.size()));
  }
  // Atomic replace — rename is atomic on POSIX when src/dst are on same fs
  std::filesystem::rename(tmpPath, path);
}

export KeyBundle keystoreLoad(const std::string &path,
                              const std::string &password) {
  std::ifstream key_file(path, std::ios::binary);
  if (!key_file)
    throw std::runtime_error("Key file not found: " + path);

  std::array<uint8_t, PBKDF2_SALT_BYTES> salt{};
  key_file.read(reinterpret_cast<char *>(salt.data()), PBKDF2_SALT_BYTES);

  std::vector<uint8_t> rest((std::istreambuf_iterator(key_file)),
                            std::istreambuf_iterator<char>());

  auto encKey = pbkdf2(password, {salt.begin(), salt.end()}, KEY_BYTES);
  auto pkt = unpackAead(rest);
  auto payload = aeadDecrypt(pkt, encKey);

  // clean memory
  OPENSSL_cleanse(encKey.data(), encKey.size());

  std::size_t off = 0;
  auto read = [&](const std::size_t numBytes) {
    if (off + numBytes > payload.size())
      throw std::runtime_error("Key file truncated");
    std::vector v(payload.begin() + off, payload.begin() + off + numBytes);
    off += numBytes;
    return v;
  };

  KeyBundle kb;
  kb.ik.priv = read(ED25519_PRIV_BYTES);
  kb.ik.pub = read(ED25519_PUB_BYTES);
  kb.spk.priv = read(X25519_KEY_BYTES);
  kb.spk.pub = read(X25519_KEY_BYTES);
  kb.spkSig = read(ED25519_SIG_BYTES);
  kb.pq.priv = read(MLKEM1024_PRIV_BYTES);
  kb.pq.pub = read(MLKEM1024_PUB_BYTES);
  kb.pqSig = read(ED25519_SIG_BYTES);

  const uint8_t opkCount = read(1)[0];
  kb.opks.reserve(opkCount);
  for (uint8_t i = 0; i < opkCount; ++i) {
    X25519KeyPair opk;
    opk.priv = read(X25519_KEY_BYTES);
    opk.pub = read(X25519_KEY_BYTES);
    kb.opks.push_back(std::move(opk));
  }

  // clear sensitive memory
  OPENSSL_cleanse(payload.data(), payload.size());
  return kb;
}
