module;
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
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

export void contactCacheSave(const std::string &path,
                             const std::vector<Contact> &contacts) {
  nlohmann::json root;
  for (const auto &contact : contacts) {
    // JSON object keys must be strings
    root[std::to_string(contact.getId())] = {
        {"username", contact.getUsername()},
        {"identity_pub", base64Encode(contact.getIdentityPub())},
        {"verified", contact.isVerified()}};
  }
  std::ofstream file(path);
  if (!file)
    throw std::runtime_error("Cannot write contact cache: " + path);
  file << root.dump(2); // pretty pring
}

export std::vector<Contact> contactCacheLoad(const std::string &path) {
  std::vector<Contact> contacts;
  if (!std::filesystem::exists(path))
    return contacts;
  std::ifstream file(path);
  const auto root = nlohmann::json::parse(file);
  for (const auto &[key, entry] : root.items()) {
    const int32_t id = std::stoi(key);
    contacts.emplace_back(
        id, entry.at("username").get<std::string>(),
        base64Decode(entry.at("identity_pub").get<std::string>()),
        entry.at("verified").get<bool>());
  }
  return contacts;
}
