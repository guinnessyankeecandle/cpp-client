#pragma once
#include <string>

class User {
public:
    User() = default;
    User(int id, std::string username, std::string accessToken, std::string refreshToken);

    int                getId()           const;
    const std::string& getUsername()     const;
    const std::string& getAccessToken()  const;
    const std::string& getRefreshToken() const;

    void setTokens(std::string accessToken, std::string refreshToken);
    bool isAuthenticated() const;

private:
    int         m_id{0};
    std::string m_username;
    std::string m_accessToken;
    std::string m_refreshToken;
};
