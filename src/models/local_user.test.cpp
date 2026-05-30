#include <catch2/catch.hpp>
#include <filesystem>
import securemsg.models.local_user;

static const std::string TEST_KEY_PATH = "/tmp/test_local_user.key";

TEST_CASE("LocalUser generates keys when file absent", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  const LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  REQUIRE(u.getId() == 1);
  REQUIRE(u.getUsername() == "alice");
  REQUIRE(u.getAccessToken() == "acc");
  REQUIRE(u.getRefreshToken() == "ref");
  REQUIRE(u.getKeyBundle().ik.pub.size() == 32);
  REQUIRE(std::filesystem::exists(TEST_KEY_PATH));
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser loads keys when file exists", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  const std::vector<uint8_t> firstPub = [&] {
    const LocalUser first{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
    return first.getKeyBundle().ik.pub;
  }();
  const LocalUser second{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  REQUIRE(second.getKeyBundle().ik.pub == firstPub);
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser token setters", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "old_acc", "old_ref", TEST_KEY_PATH, "pass"};
  u.setAccessToken("new_acc");
  u.setRefreshToken("new_ref");
  REQUIRE(u.getAccessToken() == "new_acc");
  REQUIRE(u.getRefreshToken() == "new_ref");
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser wrong password throws on load", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  {
    LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "correct"};
  }
  REQUIRE_THROWS_AS(
      (LocalUser{1, "alice", "acc", "ref", TEST_KEY_PATH, "wrong"}),
      std::runtime_error);
  std::filesystem::remove(TEST_KEY_PATH);
}
