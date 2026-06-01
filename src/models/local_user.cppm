module;
#include <filesystem>
#include <openssl/crypto.h>
#include <optional>
#include <string>
#include <vector>
export module securemsg.models.local_user;
import securemsg.models.user;
import securemsg.crypto.keystore;
import securemsg.crypto.x25519;
import securemsg.crypto.ed25519;

export class LocalUser : public User {
public:
  LocalUser(const int32_t id, std::string username, std::string accessToken,
            std::string refreshToken, std::string keyPath,
            const std::string &passphrase)
      : User(id, std::move(username)), m_accessToken(std::move(accessToken)),
        m_refreshToken(std::move(refreshToken)), m_keyPath(std::move(keyPath)) {

    if (std::filesystem::exists(m_keyPath)) {
      m_keyBundle = keystoreLoad(m_keyPath, passphrase);
    } else {
      m_keyBundle = keystoreGenerate();
      keystoreSave(m_keyPath, *m_keyBundle, passphrase);
    }
  }

  [[nodiscard]] const std::string &getAccessToken() const {
    return m_accessToken;
  }
  [[nodiscard]] const std::string &getRefreshToken() const {
    return m_refreshToken;
  }
  void setAccessToken(std::string token) { m_accessToken = std::move(token); }
  void setRefreshToken(std::string token) { m_refreshToken = std::move(token); }

  [[nodiscard]] const KeyBundle &getKeyBundle() const { return *m_keyBundle; }

  // Removes the OPK with the given public key
  void consumeOneTimePrekey(const std::vector<uint8_t> &opkPub,
                            const std::string &passphrase) {
    auto &opks = m_keyBundle->opks;
    const auto it = std::ranges::find_if(
        opks, [&](const auto &kp) { return kp.pub == opkPub; });
    if (it == opks.end())
      return;
    OPENSSL_cleanse(it->priv.data(), it->priv.size());
    opks.erase(it);
    keystoreSave(m_keyPath, *m_keyBundle, passphrase);
  }

  // Generates new OPKs, persists the bundle, and returns the public keys
  std::vector<std::vector<uint8_t>>
  replenishOneTimePrekeys(const std::size_t count,
                          const std::string &passphrase) {

    std::vector<std::vector<uint8_t>> pubs;
    pubs.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
      auto kp = x25519Generate();
      pubs.push_back(kp.pub);
      m_keyBundle->opks.push_back(std::move(kp));
    }
    keystoreSave(m_keyPath, *m_keyBundle, passphrase);
    return pubs;
  }

  // Generates a new SPK, signs it with the Ed25519 IK
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  rotateSPK(const std::string &passphrase) {
    m_keyBundle->spk = x25519Generate();
    m_keyBundle->spkSig =
        ed25519Sign(m_keyBundle->ik.priv, m_keyBundle->spk.pub);
    keystoreSave(m_keyPath, *m_keyBundle, passphrase);
    return {m_keyBundle->spk.pub, m_keyBundle->spkSig};
  }

private:
  std::string m_accessToken, m_refreshToken, m_keyPath;
  std::optional<KeyBundle> m_keyBundle;
};
