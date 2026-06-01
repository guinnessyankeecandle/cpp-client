module;
#include <cstdint>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
export module securemsg.network.api;
import securemsg.network.http;

export class ApiClient {
public:
  explicit ApiClient(std::string baseUrl) : m_http(std::move(baseUrl)) {}

  // ── Auth ─────────────────────────────────────────────────────────────────
  [[nodiscard]] nlohmann::json
  registerUser(const std::string &username, const std::string &srpSaltHex,
               const std::string &srpVerifierHex) const {
    return m_http.post("/auth/register", {{"username", username},
                                          {"srp_salt", srpSaltHex},
                                          {"srp_verifier", srpVerifierHex}});
  }

  [[nodiscard]] nlohmann::json srpInit(const std::string &username) const {
    return m_http.post("/auth/srp-init", {{"username", username}});
  }

  [[nodiscard]] nlohmann::json
  srpVerify(const std::string &sessionId, const std::string &clientPublicHex,
            const std::string &clientProofHex) const {
    return m_http.post("/auth/srp-verify", {{"session_id", sessionId},
                                            {"client_public", clientPublicHex},
                                            {"client_proof", clientProofHex}});
  }

  [[nodiscard]] nlohmann::json verify2FA(const std::string &preAuthToken,
                                         const std::string &totpCode) const {
    return m_http.post("/auth/verify-2fa", {{"totp_code", totpCode},
                                            {"pre_auth_token", preAuthToken}});
  }

  [[nodiscard]] nlohmann::json
  refreshTokens(const std::string &refreshToken) const {
    return m_http.post("/auth/refresh", {{"refresh_token", refreshToken}});
  }

  void logout(const std::string &refreshToken) const {
    (void)m_http.post("/auth/logout", {{"refresh_token", refreshToken}});
  }

  void deleteAccount(const std::string &accessToken) const {
    (void)m_http.del("/auth/me", nullptr, accessToken);
  }

  // ── Keys ─────────────────────────────────────────────────────────────────
  void publishKeyBundle(
      const std::string &accessToken, const std::string &identityPubB64,
      const std::string &identityXPubB64, const std::string &identityXSigB64,
      const std::string &spkPubB64, const std::string &spkSigB64,
      const std::vector<std::string> &opkPubsB64, const std::string &pqPubB64,
      const std::string &pqSigB64) const {
    (void)m_http.post("/keys/bundle",
                      {{"identity_pub", identityPubB64},
                       {"identity_x_pub", identityXPubB64},
                       {"identity_x_sig", identityXSigB64},
                       {"signed_prekey_pub", spkPubB64},
                       {"signed_prekey_sig", spkSigB64},
                       {"one_time_prekeys", opkPubsB64},
                       {"pq_prekey_pub", pqPubB64},
                       {"pq_prekey_sig", pqSigB64}},
                      accessToken);
  }

  void uploadPrekeys(const std::string &accessToken,
                     const std::vector<std::string> &opkPubsB64) const {
    (void)m_http.post("/keys/prekeys", {{"one_time_prekeys", opkPubsB64}},
                      accessToken);
  }

  [[nodiscard]] nlohmann::json
  getPrekeysCount(const std::string &accessToken) const {
    return m_http.get("/keys/prekeys/count", accessToken);
  }

  [[nodiscard]] nlohmann::json
  lookupByUsername(const std::string &accessToken,
                   const std::string &username) const {
    return m_http.get("/keys/lookup/by-username?username=" + username,
                      accessToken);
  }

  [[nodiscard]] nlohmann::json getKeyBundle(const std::string &accessToken,
                                            const int32_t userId) const {
    return m_http.get("/keys/" + std::to_string(userId), accessToken);
  }

  // ── Messages ─────────────────────────────────────────────────────────────
  [[nodiscard]] nlohmann::json
  sendMessage(const std::string &accessToken, const int32_t recipientId,
              const std::string &ciphertextB64,
              const std::string &ratchetHeaderEncB64) const {
    return m_http.post("/messages/",
                       {{"recipient_id", recipientId},
                        {"ciphertext", ciphertextB64},
                        {"ratchet_header_enc", ratchetHeaderEncB64}},
                       accessToken);
  }

  [[nodiscard]] nlohmann::json
  listMessages(const std::string &accessToken) const {
    return m_http.get("/messages/", accessToken);
  }

  void acknowledgeReceipt(const std::string &accessToken,
                          const int32_t messageId) const {
    (void)m_http.postEmpty(
        "/messages/" + std::to_string(messageId) + "/receipt", accessToken);
  }

  void revokeMessage(const std::string &accessToken,
                     const int32_t messageId) const {
    (void)m_http.del("/messages/" + std::to_string(messageId), nullptr,
                     accessToken);
  }

  // ── Groups ────────────────────────────────────────────────────────────────
  [[nodiscard]] nlohmann::json
  listGroups(const std::string &accessToken) const {
    return m_http.get("/groups/", accessToken);
  }

  [[nodiscard]] nlohmann::json
  createGroup(const std::string &accessToken, const std::string &name,
              const std::map<int32_t, std::string> &initialMembers) const {
    nlohmann::json members;
    for (const auto &[uid, ct] : initialMembers)
      members[std::to_string(uid)] = ct;
    return m_http.post("/groups/",
                       {{"name", name}, {"initial_members", members}},
                       accessToken);
  }

  [[nodiscard]] nlohmann::json getGroup(const std::string &accessToken,
                                        const int32_t groupId) const {
    return m_http.get("/groups/" + std::to_string(groupId), accessToken);
  }

  void addGroupMember(const std::string &accessToken, const int32_t groupId,
                      const int32_t userId,
                      const std::string &skdmCiphertextB64) const {
    (void)m_http.post(
        "/groups/" + std::to_string(groupId) + "/members",
        {{"user_id", userId}, {"skdm_ciphertext", skdmCiphertextB64}},
        accessToken);
  }

  void removeGroupMember(
      const std::string &accessToken, const int32_t groupId,
      const int32_t userId,
      const std::map<int32_t, std::string> &freshSkdms = {}) const {
    nlohmann::json body;
    if (!freshSkdms.empty()) {
      nlohmann::json cts;
      for (const auto &[uid, ct] : freshSkdms)
        cts[std::to_string(uid)] = ct;
      body["skdm_ciphertexts"] = cts;
    }
    (void)m_http.del("/groups/" + std::to_string(groupId) + "/members/" +
                         std::to_string(userId),
                     body, accessToken);
  }

  [[nodiscard]] nlohmann::json
  sendGroupMessage(const std::string &accessToken, const int32_t groupId,
                   const int32_t epoch,
                   const std::string &ciphertextB64) const {
    return m_http.post("/groups/" + std::to_string(groupId) + "/messages",
                       {{"epoch", epoch}, {"ciphertext", ciphertextB64}},
                       accessToken);
  }

  [[nodiscard]] nlohmann::json listGroupMessages(const std::string &accessToken,
                                                 const int32_t groupId) const {
    return m_http.get("/groups/" + std::to_string(groupId) + "/messages",
                      accessToken);
  }

  void acknowledgeGroupReceipt(const std::string &accessToken,
                               const int32_t groupId,
                               const int32_t messageId) const {
    (void)m_http.postEmpty("/groups/" + std::to_string(groupId) + "/messages/" +
                               std::to_string(messageId) + "/receipt",
                           accessToken);
  }

  void revokeGroupMessage(const std::string &accessToken, const int32_t groupId,
                          const int32_t messageId) const {
    (void)m_http.del("/groups/" + std::to_string(groupId) + "/messages/" +
                         std::to_string(messageId),
                     nullptr, accessToken);
  }

  void postSkdm(const std::string &accessToken, const int32_t groupId,
                const std::map<int32_t, std::string> &skdmCiphertexts) const {
    nlohmann::json cts;
    for (const auto &[uid, ct] : skdmCiphertexts)
      cts[std::to_string(uid)] = ct;
    (void)m_http.post("/groups/" + std::to_string(groupId) + "/skdm",
                      {{"skdm_ciphertexts", cts}}, accessToken);
  }

  [[nodiscard]] nlohmann::json fetchSkdm(const std::string &accessToken,
                                         const int32_t groupId) const {
    return m_http.get("/groups/" + std::to_string(groupId) + "/skdm",
                      accessToken);
  }

private:
  HttpClient m_http;
};
