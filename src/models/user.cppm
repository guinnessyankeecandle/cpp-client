module;
#include <string>
#include <cstdint>
export module securemsg.models.user;

export class User {
public:
    User() = default;
    User(int32_t id, std::string username,
         std::string accessToken, std::string refreshToken)
        : m_id(id)
        , m_username(std::move(username))
        , m_accessToken(std::move(accessToken))
        , m_refreshToken(std::move(refreshToken)) {}

    int32_t            getId()           const { return m_id; }
    const std::string& getUsername()     const { return m_username; }
    const std::string& getAccessToken()  const { return m_accessToken; }
    const std::string& getRefreshToken() const { return m_refreshToken; }

    void setAccessToken(std::string t)  { m_accessToken  = std::move(t); }
    void setRefreshToken(std::string t) { m_refreshToken = std::move(t); }

private:
    int32_t     m_id{0};
    std::string m_username;
    std::string m_accessToken;
    std::string m_refreshToken;
};
