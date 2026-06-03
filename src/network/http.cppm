module;
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>
export module securemsg.network.http;

// RAII: file descriptor

class SocketFd {
  int m_fd;

public:
  explicit SocketFd(const int fd) noexcept : m_fd(fd) {}
  ~SocketFd() {
    if (m_fd != -1)
      ::close(m_fd);
  }
  SocketFd(const SocketFd &) = delete;
  SocketFd &operator=(const SocketFd &) = delete;
  SocketFd(SocketFd &&o) noexcept : m_fd(o.m_fd) { o.m_fd = -1; }
  SocketFd &operator=(SocketFd &&o) noexcept {
    if (this != &o) {
      if (m_fd != -1)
        ::close(m_fd);
      m_fd = o.m_fd;
      o.m_fd = -1;
    }
    return *this;
  }
  [[nodiscard]] int get() const noexcept { return m_fd; }
  [[nodiscard]] bool valid() const noexcept { return m_fd != -1; }
};

// RAII: OpenSSL handles

struct SslCtxDeleter {
  void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
};
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

struct SslDeleter {
  void operator()(SSL *p) const { SSL_free(p); }
};
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

struct AddrInfoDeleter {
  void operator()(addrinfo *p) const { freeaddrinfo(p); }
};
using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

// helpers

static std::string sslError() {
  const unsigned long e = ERR_get_error();
  const char *reason = ERR_reason_error_string(e);
  return reason ? reason : "unknown SSL error";
}

// Port silently defaults to "443" when port absent.
static std::pair<std::string, std::string> parseHostPort(const std::string &url) {
  // Strip scheme
  const std::size_t start = url.find("://");
  const std::string authority =
      (start == std::string::npos) ? url : url.substr(start + 3);

  // Strip any path. Take name before first /
  const std::size_t slash = authority.find('/');
  const std::string hostPort =
      (slash == std::string::npos) ? authority : authority.substr(0, slash);

  const std::size_t colon = hostPort.rfind(':');
  if (colon == std::string::npos)
    return {hostPort, "443"};
  return {hostPort.substr(0, colon), hostPort.substr(colon + 1)};
}

// HttpClient

export class HttpClient {
public:
  explicit HttpClient(std::string baseUrl) : m_baseUrl(std::move(baseUrl)) {
    const auto [host, port] = parseHostPort(m_baseUrl);
    m_host = host;
    m_port = port;

    // Tell ssl that this will be the client
    SSL_CTX *raw = SSL_CTX_new(TLS_client_method());
    if (!raw)
      throw std::runtime_error("SSL_CTX_new failed: " + sslError());
    m_ctx.reset(raw); // Pass to smart pointer

    SSL_CTX_set_min_proto_version(m_ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_verify(m_ctx.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(m_ctx.get()) != 1)
      throw std::runtime_error("SSL_CTX_set_default_verify_paths failed: " + sslError());
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
    return request("DELETE", path, body.is_null() ? "" : body.dump(), accessToken);
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
  std::string m_host;
  std::string m_port;
  SslCtxPtr m_ctx{nullptr, SslCtxDeleter{}};
  std::function<void(int)> m_retryAfterCb = [](int) {};

  [[nodiscard]] nlohmann::json
  request(const std::string &method, const std::string &path,
          const std::string &bodyStr,
          const std::string &accessToken) const {
    // ── 1. DNS ────────────────────────────────────────────────────────────
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *rawAddr = nullptr;
    const int dnsResult =
        ::getaddrinfo(m_host.c_str(), m_port.c_str(), &hints, &rawAddr);
    if (dnsResult != 0)
      throw std::runtime_error(std::string("getaddrinfo: ") +
                               gai_strerror(dnsResult));
    AddrInfoPtr addrList(rawAddr);

    // ── 2. TCP connect ────────────────────────────────────────────────────
    SocketFd sock(-1);
    for (const addrinfo *addr = addrList.get(); addr != nullptr; addr = addr->ai_next) {
      // open socket
      SocketFd candidate(::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol));
      if (!candidate.valid())
        continue;
      //connect
      if (::connect(candidate.get(), addr->ai_addr, addr->ai_addrlen) == 0) {
        sock = std::move(candidate);
        break;
      }
    }
    if (!sock.valid())
      throw std::runtime_error(std::string("connect: ") + strerror(errno));

    // ── 3. TLS handshake ──────────────────────────────────────────────────
    SslPtr ssl(SSL_new(m_ctx.get()), SslDeleter{});
    if (!ssl)
      throw std::runtime_error("SSL_new failed: " + sslError());

    if (SSL_set_fd(ssl.get(), sock.get()) != 1)
      throw std::runtime_error("SSL_set_fd failed: " + sslError());

    // SNI (Server Name Indication - set hostname)
    if (SSL_set_tlsext_host_name(ssl.get(), m_host.c_str()) != 1)
      throw std::runtime_error("SSL_set_tlsext_host_name failed: " + sslError());

    // Checks does hostname match cert
    if (SSL_set1_host(ssl.get(), m_host.c_str()) != 1)
      throw std::runtime_error("SSL_set1_host failed: " + sslError());

    if (SSL_connect(ssl.get()) != 1)
      throw std::runtime_error("SSL_connect failed: " + sslError());

    // ── 4. Build HTTP/1.1 request ─────────────────────────────────────────
    std::string req = method + " /api/v1" + path + " HTTP/1.1\r\n";
    req += "Host: " + m_host + "\r\n";
    req += "Content-Type: application/json\r\n";
    if (!accessToken.empty())
      req += "Authorization: Bearer " + accessToken + "\r\n";
    if (!bodyStr.empty())
      req += "Content-Length: " + std::to_string(bodyStr.size()) + "\r\n";
    req += "Connection: close\r\n";
    req += "\r\n";
    req += bodyStr;

    // ── 5. Write request (loop handles short writes) ──────────────────────
    const char *ptr = req.data();
    std::size_t remaining = req.size();
    while (remaining > 0) {
      const int toWrite =
          static_cast<int>(std::min(remaining, static_cast<std::size_t>(INT_MAX)));
      const int written = SSL_write(ssl.get(), ptr, toWrite);
      if (written <= 0)
        throw std::runtime_error("SSL_write failed: " + sslError());
      ptr += written;
      remaining -= static_cast<std::size_t>(written);
    }

    // ── 6. Read response ──────────────────────────────────────────────────
    std::vector<uint8_t> buf;
    buf.reserve(4096);
    std::array<uint8_t, 4096> tmp{};
    while (true) {
      const int n = SSL_read(ssl.get(), tmp.data(), tmp.size());
      if (n > 0) {
        buf.insert(buf.end(), tmp.data(), tmp.data() + n);
        continue;
      }
      const int err = SSL_get_error(ssl.get(), n);
      if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_NONE)
        break; // clean TLS close
      if (err == SSL_ERROR_SYSCALL && n == 0)
        break; // TCP EOF without TLS close_notify (tolerate)
      throw std::runtime_error("SSL_read failed: " + sslError());
    }

    // ── 7. Graceful TLS shutdown ──────────────────────────────────────────
    // Set a 3s timeout so we don't block forever if the server never sends close_notify
    constexpr timeval tv{3, 0};
    ::setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (SSL_shutdown(ssl.get()) == 0)
      SSL_shutdown(ssl.get()); // wait for peer close_notify
    // ssl and sock destructors fire here (reverse declaration order)

    // ── 8. Parse response ─────────────────────────────────────────────────
    const std::string response(buf.begin(), buf.end());

    // Status line: "HTTP/1.1 200 OK"
    const std::size_t firstCrlf = response.find("\r\n");
    if (firstCrlf == std::string::npos)
      throw std::runtime_error("Malformed HTTP response: no status line");

    const std::string statusLine = response.substr(0, firstCrlf);

    // Extract status code from after the first space — works for any HTTP version
    const std::size_t firstSpace = statusLine.find(' ');
    if (firstSpace == std::string::npos)
      throw std::runtime_error("Malformed HTTP status line: " + statusLine);

    const std::string codeStr = statusLine.substr(firstSpace + 1, 3);
    if (codeStr.size() != 3 || !std::ranges::all_of(codeStr, [](const unsigned char c) { return std::isdigit(c); }))
      throw std::runtime_error("Invalid HTTP status code: " + codeStr);

    const int responseCode = std::stoi(codeStr);

    // Locate header/body separator
    const std::size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
      throw std::runtime_error("Malformed HTTP response: no header terminator");

    const std::string responseBody = response.substr(headerEnd + 4);

    // ── 9. HTTP error handling ────────────────────────────────────────────
    if (responseCode == 429) {
      m_retryAfterCb(1);
      throw std::runtime_error("Rate limited (429)");
    }
    if (responseCode == 401)
      throw std::runtime_error("Unauthorised (401)");
    if (responseCode >= 400) {
      const std::string msg =
          "HTTP " + std::to_string(responseCode) + ": " + responseBody;
      std::ofstream log("securemsg.log", std::ios::app);
      log << msg << "\n";
      throw std::runtime_error(msg);
    }

    if (responseBody.empty())
      return nullptr;
    return nlohmann::json::parse(responseBody, nullptr, false);
  }
};
