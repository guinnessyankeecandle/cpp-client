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
  const LocalUser correct{1, "alice", "acc", "ref", TEST_KEY_PATH, "correct"};
  (void)correct;
  REQUIRE_THROWS_AS(
      (LocalUser{1, "alice", "acc", "ref", TEST_KEY_PATH, "wrong"}),
      std::runtime_error);
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser replenishOneTimePrekeys returns correct count",
          "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  const auto pubs = u.replenishOneTimePrekeys(5, "pass");
  REQUIRE(pubs.size() == 5);
  for (const auto &pub : pubs)
    REQUIRE(pub.size() == 32);
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser replenishOneTimePrekeys persists keys", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  const std::size_t before = u.getKeyBundle().opks.size();
  u.replenishOneTimePrekeys(3, "pass");
  REQUIRE(u.getKeyBundle().opks.size() == before + 3);
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser consumeOneTimePrekey removes key", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  const std::size_t before = u.getKeyBundle().opks.size();
  REQUIRE(before > 0);
  const auto opkPub = u.getKeyBundle().opks.front().pub;
  u.consumeOneTimePrekey(opkPub, "pass");
  REQUIRE(u.getKeyBundle().opks.size() == before - 1);
  const auto &opks = u.getKeyBundle().opks;
  REQUIRE(std::ranges::none_of(opks, [&](const auto &kp) {
    return kp.pub == opkPub;
  }));
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser consumeOneTimePrekey unknown key is no-op", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  const std::size_t before = u.getKeyBundle().opks.size();
  const std::vector<uint8_t> unknown(32, 0xFF);
  u.consumeOneTimePrekey(unknown, "pass");
  REQUIRE(u.getKeyBundle().opks.size() == before);
  std::filesystem::remove(TEST_KEY_PATH);
}

TEST_CASE("LocalUser rotateSPK produces new key", "[local_user]") {
  std::filesystem::remove(TEST_KEY_PATH);
  LocalUser u{1, "alice", "acc", "ref", TEST_KEY_PATH, "pass"};
  const auto oldSpk = u.getKeyBundle().spk.pub;
  const auto [newPub, newSig] = u.rotateSPK("pass");
  REQUIRE(newPub != oldSpk);
  REQUIRE(newPub.size() == 32);
  REQUIRE(newSig.size() == 64);
  REQUIRE(u.getKeyBundle().spk.pub == newPub);
  std::filesystem::remove(TEST_KEY_PATH);
}
