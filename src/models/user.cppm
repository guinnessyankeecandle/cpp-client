module;
#include <cstdint>
#include <string>
export module securemsg.models.user;

export class User {
public:
  User(const int32_t id, std::string username)
      : user_id(id), user_username(std::move(username)) {}

  [[nodiscard]] int32_t getId() const { return user_id; }
  [[nodiscard]] const std::string &getUsername() const { return user_username; }

private:
  int32_t user_id;
  std::string user_username;
};
