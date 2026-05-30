module;
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <map>
export module securemsg.network.api;
import securemsg.network.http;

export class ApiClient {
public:
    explicit ApiClient(std::string baseUrl, bool verifyTls = true)
        : m_http(std::move(baseUrl), verifyTls) {}

    // ── Auth ─────────────────────────────────────────────────────────────────
    nlohmann::json registerUser(const std::string& username,
                                 const std::string& srpSaltHex,
                                 const std::string& srpVerifierHex) {
        return m_http.post("/auth/register", {
            {"username",     username},
            {"srp_salt",     srpSaltHex},
            {"srp_verifier", srpVerifierHex}
        });
    }

    nlohmann::json srpInit(const std::string& username,
                            const std::string& clientPublicHex) {
        return m_http.post("/auth/srp-init", {
            {"username",      username},
            {"client_public", clientPublicHex}
        });
    }

    nlohmann::json srpVerify(const std::string& sessionId,
                              const std::string& clientProofHex) {
        return m_http.post("/auth/srp-verify", {
            {"session_id",   sessionId},
            {"client_proof", clientProofHex}
        });
    }

    nlohmann::json verify2FA(const std::string& preAuthToken,
                              const std::string& totpCode) {
        return m_http.post("/auth/verify-2fa", {
            {"totp_code",      totpCode},
            {"pre_auth_token", preAuthToken}
        });
    }

    nlohmann::json refreshTokens(const std::string& refreshToken) {
        return m_http.post("/auth/refresh", {{"refresh_token", refreshToken}});
    }

    void logout(const std::string& refreshToken) {
        m_http.post("/auth/logout", {{"refresh_token", refreshToken}});
    }

    void deleteAccount(const std::string& accessToken) {
        m_http.del("/auth/me", nullptr, accessToken);
    }

    // ── Keys ─────────────────────────────────────────────────────────────────
    void publishKeyBundle(const std::string&              accessToken,
                           const std::string&              identityPubB64,
                           const std::string&              spkPubB64,
                           const std::string&              spkSigB64,
                           const std::vector<std::string>& opkPubsB64,
                           const std::string&              pqPubB64,
                           const std::string&              pqSigB64) {
        m_http.post("/keys/bundle", {
            {"identity_pub",      identityPubB64},
            {"signed_prekey_pub", spkPubB64},
            {"signed_prekey_sig", spkSigB64},
            {"one_time_prekeys",  opkPubsB64},
            {"pq_prekey_pub",     pqPubB64},
            {"pq_prekey_sig",     pqSigB64}
        }, accessToken);
    }

    void uploadPrekeys(const std::string&              accessToken,
                        const std::vector<std::string>& opkPubsB64) {
        m_http.post("/keys/prekeys",
                    {{"one_time_prekeys", opkPubsB64}}, accessToken);
    }

    nlohmann::json getPrekeysCount(const std::string& accessToken) {
        return m_http.get("/keys/prekeys/count", accessToken);
    }

    nlohmann::json lookupByUsername(const std::string& accessToken,
                                     const std::string& username) {
        return m_http.get("/keys/lookup/by-username?username=" + username,
                          accessToken);
    }

    nlohmann::json getKeyBundle(const std::string& accessToken, int32_t userId) {
        return m_http.get("/keys/" + std::to_string(userId), accessToken);
    }

    // ── Messages ─────────────────────────────────────────────────────────────
    nlohmann::json sendMessage(const std::string& accessToken,
                                int32_t            recipientId,
                                const std::string& ciphertextB64,
                                const std::string& ratchetHeaderEncB64) {
        return m_http.post("/messages/", {
            {"recipient_id",       recipientId},
            {"ciphertext",         ciphertextB64},
            {"ratchet_header_enc", ratchetHeaderEncB64}
        }, accessToken);
    }

    nlohmann::json listMessages(const std::string& accessToken) {
        return m_http.get("/messages/", accessToken);
    }

    void acknowledgeReceipt(const std::string& accessToken, int32_t messageId) {
        m_http.postEmpty("/messages/" + std::to_string(messageId) + "/receipt",
                          accessToken);
    }

    void revokeMessage(const std::string& accessToken, int32_t messageId) {
        m_http.del("/messages/" + std::to_string(messageId), nullptr, accessToken);
    }

    // ── Groups ────────────────────────────────────────────────────────────────
    nlohmann::json listGroups(const std::string& accessToken) {
        return m_http.get("/groups/", accessToken);
    }

    nlohmann::json createGroup(const std::string& accessToken,
                                const std::string& name,
                                const std::map<int32_t, std::string>& initialMembers) {
        nlohmann::json members;
        for (const auto& [uid, ct] : initialMembers)
            members[std::to_string(uid)] = ct;
        return m_http.post("/groups/",
                           {{"name", name}, {"initial_members", members}}, accessToken);
    }

    nlohmann::json getGroup(const std::string& accessToken, int32_t groupId) {
        return m_http.get("/groups/" + std::to_string(groupId), accessToken);
    }

    void addGroupMember(const std::string& accessToken, int32_t groupId,
                         int32_t userId, const std::string& skdmCiphertextB64) {
        m_http.post("/groups/" + std::to_string(groupId) + "/members",
                    {{"user_id", userId}, {"skdm_ciphertext", skdmCiphertextB64}},
                    accessToken);
    }

    void removeGroupMember(const std::string& accessToken, int32_t groupId,
                            int32_t userId,
                            const std::map<int32_t, std::string>& freshSkdms = {}) {
        nlohmann::json body;
        if (!freshSkdms.empty()) {
            nlohmann::json cts;
            for (const auto& [uid, ct] : freshSkdms)
                cts[std::to_string(uid)] = ct;
            body["skdm_ciphertexts"] = cts;
        }
        m_http.del("/groups/" + std::to_string(groupId)
                   + "/members/" + std::to_string(userId),
                   body.empty() ? nullptr : body, accessToken);
    }

    nlohmann::json sendGroupMessage(const std::string& accessToken,
                                     int32_t groupId, int32_t epoch,
                                     const std::string& ciphertextB64) {
        return m_http.post("/groups/" + std::to_string(groupId) + "/messages",
                           {{"epoch", epoch}, {"ciphertext", ciphertextB64}},
                           accessToken);
    }

    nlohmann::json listGroupMessages(const std::string& accessToken, int32_t groupId) {
        return m_http.get("/groups/" + std::to_string(groupId) + "/messages",
                          accessToken);
    }

    void acknowledgeGroupReceipt(const std::string& accessToken,
                                  int32_t groupId, int32_t messageId) {
        m_http.postEmpty("/groups/" + std::to_string(groupId)
                         + "/messages/" + std::to_string(messageId) + "/receipt",
                         accessToken);
    }

    void revokeGroupMessage(const std::string& accessToken,
                             int32_t groupId, int32_t messageId) {
        m_http.del("/groups/" + std::to_string(groupId)
                   + "/messages/" + std::to_string(messageId), nullptr, accessToken);
    }

    void postSkdm(const std::string& accessToken, int32_t groupId,
                   const std::map<int32_t, std::string>& skdmCiphertexts) {
        nlohmann::json cts;
        for (const auto& [uid, ct] : skdmCiphertexts)
            cts[std::to_string(uid)] = ct;
        m_http.post("/groups/" + std::to_string(groupId) + "/skdm",
                    {{"skdm_ciphertexts", cts}}, accessToken);
    }

    nlohmann::json fetchSkdm(const std::string& accessToken, int32_t groupId) {
        return m_http.get("/groups/" + std::to_string(groupId) + "/skdm",
                          accessToken);
    }

private:
    HttpClient m_http;
};
