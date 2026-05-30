#include <catch2/catch.hpp>
import securemsg.models.user;

TEST_CASE("User construction and getters", "[user]") {
  const User u{1, "alice"};
  REQUIRE(u.getId() == 1);
  REQUIRE(u.getUsername() == "alice");
}
