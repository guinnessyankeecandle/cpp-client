module;
#include <string>
#include <cstdint>
export module securemsg.models.user;

export class User {
public:
    // Caller decides whether to move or copy the value into these
    // User u (std::move(string)) - pass by reference object destroyed.
    // User u (string) - pass by value, copy made origional left ok
    User(const int32_t id, std::string username,
         std::string accessToken, std::string refreshToken)
        : user_id(id)
        , user_username(std::move(username))
        , user_accessToken(std::move(accessToken))
        , user_refreshToken(std::move(refreshToken)) {}

    [[nodiscard]] int32_t            getId()           const { return user_id; }
    [[nodiscard]] const std::string& getUsername()     const { return user_username; }
    [[nodiscard]] const std::string& getAccessToken()  const { return user_accessToken; }
    [[nodiscard]] const std::string& getRefreshToken() const { return user_refreshToken; }

    void setAccessToken(std::string token)  { user_accessToken  = std::move(token); }
    void setRefreshToken(std::string token) { user_refreshToken = std::move(token); }

private:
    int32_t     user_id;
    std::string user_username;
    std::string user_accessToken;
    std::string user_refreshToken;
};
