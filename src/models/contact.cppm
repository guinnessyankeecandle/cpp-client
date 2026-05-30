module;
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>
export module securemsg.models.contact;
import securemsg.models.user;
import securemsg.crypto.random; // for base64Encode/Decode

export class Contact : public User {
public:
  Contact(const int32_t id, std::string username,
          std::vector<uint8_t> identityPub, const bool verified = false)
      : User(id, std::move(username)), m_identityPub(std::move(identityPub)),
        m_verified(verified) {}

  [[nodiscard]] const std::vector<uint8_t> &getIdentityPub() const {
    return m_identityPub;
  }
  [[nodiscard]] bool isVerified() const { return m_verified; }
  void markVerified() { m_verified = true; }

private:
  std::vector<uint8_t> m_identityPub;
  bool m_verified;
};

export void
contactCacheSave(const std::string &path,
                 const std::unordered_map<int32_t, Contact> &contacts) {
  nlohmann::json j;
  for (const auto &[id, c] : contacts) {
    j[std::to_string(id)] = {{"username", c.getUsername()},
                             {"identity_pub", base64Encode(c.getIdentityPub())},
                             {"verified", c.isVerified()}};
  }
  std::ofstream f(path);
  if (!f)
    throw std::runtime_error("Cannot write contact cache: " + path);
  f << j.dump(2);
}

export std::unordered_map<int32_t, Contact>
contactCacheLoad(const std::string &path) {
  std::unordered_map<int32_t, Contact> contacts;
  if (!std::filesystem::exists(path))
    return contacts;
  std::ifstream f(path);
  const auto j = nlohmann::json::parse(f);
  for (const auto &[key, val] : j.items()) {
    const int32_t id = std::stoi(key);
    contacts.emplace(id, Contact{id, val.value("username", ""),
                                 base64Decode(val.value("identity_pub", "")),
                                 val.value("verified", false)});
  }
  return contacts;
}
