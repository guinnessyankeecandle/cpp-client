module;
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
export module securemsg.models.local_user;
import securemsg.models.user;
import securemsg.crypto.keystore;

export class LocalUser : public User {
public:
  LocalUser(const int32_t id, std::string username, std::string accessToken,
            std::string refreshToken)
      : User(id, std::move(username)), m_accessToken(std::move(accessToken)),
        m_refreshToken(std::move(refreshToken)) {}

  [[nodiscard]] const std::string &getAccessToken() const {
    return m_accessToken;
  }
  [[nodiscard]] const std::string &getRefreshToken() const {
    return m_refreshToken;
  }
  void setAccessToken(std::string token) { m_accessToken = std::move(token); }
  void setRefreshToken(std::string token) { m_refreshToken = std::move(token); }

  void generateKeys() { m_keyBundle = keystoreGenerate(); }

  void saveKeys(const std::string &path, const std::string &passphrase) {
    if (!m_keyBundle)
      throw std::runtime_error("No keys to save");
    keystoreSave(path, *m_keyBundle, passphrase);
  }

  void loadKeys(const std::string &path, const std::string &passphrase) {
    m_keyBundle = keystoreLoad(path, passphrase);
  }

  [[nodiscard]] bool hasKeys() const { return m_keyBundle.has_value(); }

  [[nodiscard]] const KeyBundle &getKeyBundle() const {
    if (!m_keyBundle)
      throw std::runtime_error("Keys not loaded");
    return *m_keyBundle;
  }

  [[nodiscard]] KeyBundle &getKeyBundle() {
    if (!m_keyBundle)
      throw std::runtime_error("Keys not loaded");
    return *m_keyBundle;
  }

private:
  std::string m_accessToken, m_refreshToken;
  std::optional<KeyBundle> m_keyBundle;
};
