#include "User.hpp"

User::User(int id, std::string username, std::string accessToken, std::string refreshToken)
    : m_id(id)
    , m_username(std::move(username))
    , m_accessToken(std::move(accessToken))
    , m_refreshToken(std::move(refreshToken))
{}

int                User::getId()           const { return m_id; }
const std::string& User::getUsername()     const { return m_username; }
const std::string& User::getAccessToken()  const { return m_accessToken; }
const std::string& User::getRefreshToken() const { return m_refreshToken; }

bool User::isAuthenticated() const { return !m_accessToken.empty(); }

void User::setTokens(std::string accessToken, std::string refreshToken) {
    m_accessToken  = std::move(accessToken);
    m_refreshToken = std::move(refreshToken);
}
