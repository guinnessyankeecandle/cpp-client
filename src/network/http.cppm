module;
#include <curl/curl.h>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
export module securemsg.network.http;

struct CurlDeleter {
  void operator()(CURL *h) const { curl_easy_cleanup(h); }
};
using CurlPtr = std::unique_ptr<CURL, CurlDeleter>;

struct CurlSlistDeleter {
  void operator()(curl_slist *s) const { curl_slist_free_all(s); }
};
using SlistPtr = std::unique_ptr<curl_slist, CurlSlistDeleter>;

static std::size_t writeCallback(const char *ptr, const std::size_t size,
                                 const std::size_t nmemb, std::string *out) {
  out->append(ptr, size * nmemb);
  return size * nmemb;
}

export class HttpClient {
public:
  explicit HttpClient(std::string baseUrl)
      : m_baseUrl(std::move(baseUrl)), m_curl(curl_easy_init()) {
    if (!m_curl)
      throw std::runtime_error("curl_easy_init failed");
  }

  [[nodiscard]] nlohmann::json post(const std::string &path,
                                    const nlohmann::json &body,
                                    const std::string &accessToken = "") const {
    return request("POST", path, body.dump(), accessToken);
  }

  [[nodiscard]] nlohmann::json get(const std::string &path,
                                   const std::string &accessToken = "") const {
    return request("GET", path, "", accessToken);
  }

  [[nodiscard]] nlohmann::json del(const std::string &path,
                                   const nlohmann::json &body = nullptr,
                                   const std::string &accessToken = "") const {
    return request("DELETE", path, body.is_null() ? "" : body.dump(),
                   accessToken);
  }

  [[nodiscard]] nlohmann::json
  postEmpty(const std::string &path,
            const std::string &accessToken = "") const {
    return request("POST", path, "", accessToken);
  }

  void setRetryAfterCallback(std::function<void(int)> cb) {
    m_retryAfterCb = std::move(cb);
  }

private:
  std::string m_baseUrl;
  CurlPtr m_curl;
  std::function<void(int)> m_retryAfterCb = [](int) {};

  [[nodiscard]] nlohmann::json request(const std::string &method,
                                       const std::string &path,
                                       const std::string &bodyStr,
                                       const std::string &accessToken) const {
    const std::string url = m_baseUrl + "/api/v1" + path;
    std::string responseBody;
    long responseCode = 0;

    curl_easy_reset(m_curl.get());
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(m_curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, &responseBody);

    SlistPtr headers(
        curl_slist_append(nullptr, "Content-Type: application/json"));
    if (!accessToken.empty())
      headers.reset(curl_slist_append(
          headers.release(), ("Authorization: Bearer " + accessToken).c_str()));
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, headers.get());

    if (method == "POST") {
      curl_easy_setopt(m_curl.get(), CURLOPT_POST, 1L);
      curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDS, bodyStr.c_str());
      curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDSIZE,
                       static_cast<long>(bodyStr.size()));
    } else if (method == "DELETE") {
      curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, "DELETE");
      if (!bodyStr.empty()) {
        curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDS, bodyStr.c_str());
        curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(bodyStr.size()));
      }
    }

    const auto res = curl_easy_perform(m_curl.get());
    if (res != CURLE_OK)
      throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(res));

    curl_easy_getinfo(m_curl.get(), CURLINFO_RESPONSE_CODE, &responseCode);

    if (responseCode == 429) {
      m_retryAfterCb(1);
      throw std::runtime_error("Rate limited (429)");
    }
    if (responseCode == 401)
      throw std::runtime_error("Unauthorised (401)");
    if (responseCode >= 400)
      throw std::runtime_error("HTTP " + std::to_string(responseCode) + ": " +
                               responseBody);

    if (responseBody.empty())
      return nullptr;
    return nlohmann::json::parse(responseBody, nullptr, false);
  }
};
