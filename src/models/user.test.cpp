#include <catch2/catch.hpp>
import securemsg.models.user;

TEST_CASE("User construction and getters", "[user]") {
  const User u{1, "alice", "acc123", "ref456"};
  REQUIRE(u.getId() == 1);
  REQUIRE(u.getUsername() == "alice");
  REQUIRE(u.getAccessToken() == "acc123");
  REQUIRE(u.getRefreshToken() == "ref456");
}

TEST_CASE("User token mutation", "[user]") {
  User u{1, "alice", "old_acc", "old_ref"};
  u.setAccessToken("new_acc");
  u.setRefreshToken("new_ref");
  REQUIRE(u.getAccessToken() == "new_acc");
  REQUIRE(u.getRefreshToken() == "new_ref");
}
