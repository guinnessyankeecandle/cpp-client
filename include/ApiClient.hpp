#pragma once
#include <string>
#include <memory>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

struct CurlDeleter {
    void operator()(CURL* h) const { curl_easy_cleanup(h); }
};

class ApiClient {
public:
    explicit ApiClient(std::string baseUrl, bool verifyTls = true);
    ~ApiClient();

    // Auth
    nlohmann::json registerUser(const std::string& username,
                                const std::string& srpSaltHex,
                                const std::string& srpVerifierHex);

    nlohmann::json srpInit(const std::string& username,
                           const std::string& clientPublicHex);

    nlohmann::json srpVerify(const std::string& sessionId,
                             const std::string& clientProofHex);

    nlohmann::json verify2FA(const std::string& preAuthToken,
                             const std::string& totpCode);

    nlohmann::json refreshTokens(const std::string& refreshToken);

    void logout(const std::string& refreshToken);

    // Keys
    nlohmann::json getKeyBundle(const std::string& accessToken, int userId);

    void publishKeyBundle(const std::string& accessToken,
                          const nlohmann::json& bundle);

    // Messages
    nlohmann::json sendMessage(const std::string& accessToken,
                               int recipientId,
                               const std::string& ciphertextB64,
                               const std::string& headerEncB64);

    nlohmann::json listMessages(const std::string& accessToken);

    void acknowledgeReceipt(const std::string& accessToken, int messageId);

    void revokeMessage(const std::string& accessToken,
                       int messageId,
                       const std::string& revocationTokenB64);

private:
    nlohmann::json doPost(const std::string& path,
                          const nlohmann::json& body,
                          const std::string& accessToken = "");

    nlohmann::json doGet(const std::string& path,
                         const std::string& accessToken = "");

    nlohmann::json doDelete(const std::string& path,
                            const nlohmann::json& body,
                            const std::string& accessToken = "");

    nlohmann::json doPostEmpty(const std::string& path,
                               const std::string& accessToken = "");

    std::string m_baseUrl;
    bool        m_verifyTls;
    std::unique_ptr<CURL, CurlDeleter> m_curl;
};
