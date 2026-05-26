#include "ApiClient.hpp"
#include <stdexcept>
#include <sstream>

// libcurl write callback — appends received data to a std::string.
static std::size_t writeCallback(char* ptr, std::size_t size, std::size_t nmemb, std::string* out) {
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// ── Construction ─────────────────────────────────────────────────────────────

ApiClient::ApiClient(std::string baseUrl, bool verifyTls)
    : m_baseUrl(std::move(baseUrl))
    , m_verifyTls(verifyTls)
    , m_curl(curl_easy_init())
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (!m_curl) throw std::runtime_error("curl_easy_init failed");
}

ApiClient::~ApiClient() {
    // m_curl cleaned up by CurlDeleter; global cleanup here.
    curl_global_cleanup();
}

// ── Internal request helpers ──────────────────────────────────────────────────

nlohmann::json ApiClient::doPost(const std::string& path,
                                  const nlohmann::json& body,
                                  const std::string& accessToken)
{
    CURL* curl = m_curl.get();
    std::string url      = m_baseUrl + path;
    std::string bodyStr  = body.dump();
    std::string response;
    long        httpCode = 0;

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!accessToken.empty()) {
        std::string auth = "Authorization: Bearer " + accessToken;
        headers = curl_slist_append(headers, auth.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST,            1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,      bodyStr.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,   static_cast<long>(bodyStr.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  m_verifyTls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  m_verifyTls ? 2L : 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));

    if (response.empty()) return nullptr;

    auto j = nlohmann::json::parse(response, nullptr, false);
    if (j.is_discarded())
        throw std::runtime_error("Invalid JSON response from server (HTTP " +
                                  std::to_string(httpCode) + "): " + response);

    if (httpCode >= 400) {
        std::string detail = j.value("detail", response);
        throw std::runtime_error("HTTP " + std::to_string(httpCode) + ": " + detail);
    }
    return j;
}

nlohmann::json ApiClient::doGet(const std::string& path, const std::string& accessToken) {
    CURL* curl = m_curl.get();
    std::string url      = m_baseUrl + path;
    std::string response;
    long        httpCode = 0;

    curl_slist* headers = nullptr;
    if (!accessToken.empty()) {
        std::string auth = "Authorization: Bearer " + accessToken;
        headers = curl_slist_append(headers, auth.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET,       1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, m_verifyTls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_verifyTls ? 2L : 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));

    auto j = nlohmann::json::parse(response, nullptr, false);
    if (j.is_discarded())
        throw std::runtime_error("Invalid JSON (HTTP " + std::to_string(httpCode) + "): " + response);
    if (httpCode >= 400)
        throw std::runtime_error("HTTP " + std::to_string(httpCode) + ": " + j.value("detail", response));
    return j;
}

nlohmann::json ApiClient::doDelete(const std::string& path,
                                    const nlohmann::json& body,
                                    const std::string& accessToken)
{
    CURL* curl = m_curl.get();
    std::string url      = m_baseUrl + path;
    std::string bodyStr  = body.dump();
    std::string response;
    long        httpCode = 0;

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!accessToken.empty()) {
        std::string auth = "Authorization: Bearer " + accessToken;
        headers = curl_slist_append(headers, auth.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    bodyStr.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, m_verifyTls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_verifyTls ? 2L : 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));

    if (httpCode >= 400) {
        auto j = nlohmann::json::parse(response, nullptr, false);
        throw std::runtime_error("HTTP " + std::to_string(httpCode) + ": " +
                                  (j.is_discarded() ? response : j.value("detail", response)));
    }
    if (response.empty()) return nullptr;
    return nlohmann::json::parse(response, nullptr, false);
}

nlohmann::json ApiClient::doPostEmpty(const std::string& path, const std::string& accessToken) {
    CURL* curl = m_curl.get();
    std::string url      = m_baseUrl + path;
    std::string response;
    long        httpCode = 0;

    curl_slist* headers = nullptr;
    if (!accessToken.empty()) {
        std::string auth = "Authorization: Bearer " + accessToken;
        headers = curl_slist_append(headers, auth.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST,            1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,   0L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,      "");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  m_verifyTls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  m_verifyTls ? 2L : 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));
    if (httpCode >= 400)
        throw std::runtime_error("HTTP " + std::to_string(httpCode));
    return nullptr;
}

// ── Auth ─────────────────────────────────────────────────────────────────────

nlohmann::json ApiClient::registerUser(const std::string& username,
                                        const std::string& srpSaltHex,
                                        const std::string& srpVerifierHex)
{
    return doPost("/api/v1/auth/register", {
        {"username",     username},
        {"srp_salt",     srpSaltHex},
        {"srp_verifier", srpVerifierHex}
    });
}

nlohmann::json ApiClient::srpInit(const std::string& username,
                                   const std::string& clientPublicHex)
{
    return doPost("/api/v1/auth/srp-init", {
        {"username",      username},
        {"client_public", clientPublicHex}
    });
}

nlohmann::json ApiClient::srpVerify(const std::string& sessionId,
                                     const std::string& clientProofHex)
{
    return doPost("/api/v1/auth/srp-verify", {
        {"session_id",    sessionId},
        {"client_proof",  clientProofHex}
    });
}

nlohmann::json ApiClient::verify2FA(const std::string& preAuthToken,
                                     const std::string& totpCode)
{
    return doPost("/api/v1/auth/verify-2fa", {
        {"pre_auth_token", preAuthToken},
        {"totp_code",      totpCode}
    });
}

nlohmann::json ApiClient::refreshTokens(const std::string& refreshToken) {
    return doPost("/api/v1/auth/refresh", {{"refresh_token", refreshToken}});
}

void ApiClient::logout(const std::string& refreshToken) {
    doPost("/api/v1/auth/logout", {{"refresh_token", refreshToken}});
}

// ── Keys ─────────────────────────────────────────────────────────────────────

nlohmann::json ApiClient::getKeyBundle(const std::string& accessToken, int userId) {
    return doGet("/api/v1/keys/" + std::to_string(userId), accessToken);
}

void ApiClient::publishKeyBundle(const std::string& accessToken,
                                  const nlohmann::json& bundle)
{
    doPost("/api/v1/keys/bundle", bundle, accessToken);
}

// ── Messages ─────────────────────────────────────────────────────────────────

nlohmann::json ApiClient::sendMessage(const std::string& accessToken,
                                       int recipientId,
                                       const std::string& ciphertextB64,
                                       const std::string& headerEncB64)
{
    return doPost("/api/v1/messages/", {
        {"recipient_id",      recipientId},
        {"ciphertext",        ciphertextB64},
        {"ratchet_header_enc", headerEncB64}
    }, accessToken);
}

nlohmann::json ApiClient::listMessages(const std::string& accessToken) {
    return doGet("/api/v1/messages/", accessToken);
}

void ApiClient::acknowledgeReceipt(const std::string& accessToken, int messageId) {
    doPostEmpty("/api/v1/messages/" + std::to_string(messageId) + "/receipt", accessToken);
}

void ApiClient::revokeMessage(const std::string& accessToken,
                               int messageId,
                               const std::string& revocationTokenB64)
{
    doDelete("/api/v1/messages/" + std::to_string(messageId),
             {{"revocation_token", revocationTokenB64}},
             accessToken);
}

// ── Groups ────────────────────────────────────────────────────────────────────

nlohmann::json ApiClient::listGroups(const std::string& accessToken) {
    return doGet("/api/v1/groups/", accessToken);
}

nlohmann::json ApiClient::createGroup(const std::string& accessToken,
                                       const std::string& name)
{
    return doPost("/api/v1/groups/", {{"name", name}, {"initial_members", nlohmann::json::object()}}, accessToken);
}

nlohmann::json ApiClient::getGroup(const std::string& accessToken, int groupId) {
    return doGet("/api/v1/groups/" + std::to_string(groupId), accessToken);
}

void ApiClient::addGroupMember(const std::string& accessToken, int groupId,
                                int userId, const std::string& skdmCiphertextB64)
{
    doPost("/api/v1/groups/" + std::to_string(groupId) + "/members",
           {{"user_id", userId}, {"skdm_ciphertext", skdmCiphertextB64}},
           accessToken);
}

void ApiClient::removeGroupMember(const std::string& accessToken, int groupId, int userId) {
    doDelete("/api/v1/groups/" + std::to_string(groupId) + "/members/" + std::to_string(userId),
             nlohmann::json::object(), accessToken);
}

nlohmann::json ApiClient::sendGroupMessage(const std::string& accessToken, int groupId,
                                            int epoch, const std::string& ciphertextB64)
{
    return doPost("/api/v1/groups/" + std::to_string(groupId) + "/messages",
                  {{"epoch", epoch}, {"ciphertext", ciphertextB64}},
                  accessToken);
}

nlohmann::json ApiClient::listGroupMessages(const std::string& accessToken, int groupId) {
    return doGet("/api/v1/groups/" + std::to_string(groupId) + "/messages", accessToken);
}

void ApiClient::acknowledgeGroupReceipt(const std::string& accessToken,
                                         int groupId, int messageId)
{
    doPostEmpty("/api/v1/groups/" + std::to_string(groupId) +
                "/messages/" + std::to_string(messageId) + "/receipt", accessToken);
}

void ApiClient::revokeGroupMessage(const std::string& accessToken,
                                    int groupId, int messageId)
{
    doDelete("/api/v1/groups/" + std::to_string(groupId) + "/messages/" + std::to_string(messageId),
             nlohmann::json::object(), accessToken);
}

void ApiClient::postSkdm(const std::string& accessToken, int groupId,
                          const nlohmann::json& skdmCiphertexts)
{
    doPost("/api/v1/groups/" + std::to_string(groupId) + "/skdm",
           {{"skdm_ciphertexts", skdmCiphertexts}}, accessToken);
}

nlohmann::json ApiClient::fetchSkdm(const std::string& accessToken, int groupId) {
    return doGet("/api/v1/groups/" + std::to_string(groupId) + "/skdm", accessToken);
}

nlohmann::json ApiClient::lookupByUsername(const std::string& accessToken,
                                            const std::string& username)
{
    return doGet("/api/v1/keys/lookup/by-username?username=" + username, accessToken);
}
