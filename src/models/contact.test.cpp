#include <catch2/catch.hpp>
#include <filesystem>
#include <unordered_map>
import securemsg.models.contact;

TEST_CASE("Contact construction and getters", "[contact]") {
  const Contact c{1, "alice", {0x01, 0x02, 0x03}};
  REQUIRE(c.getId() == 1);
  REQUIRE(c.getUsername() == "alice");
  REQUIRE(c.getIdentityPub() == std::vector<uint8_t>{0x01, 0x02, 0x03});
  REQUIRE_FALSE(c.isVerified());
}

TEST_CASE("Contact markVerified", "[contact]") {
  Contact c{1, "alice", {0x01}};
  REQUIRE_FALSE(c.isVerified());
  c.markVerified();
  REQUIRE(c.isVerified());
}

TEST_CASE("Contact constructed as verified", "[contact]") {
  const Contact c{1, "alice", {0x01}, true};
  REQUIRE(c.isVerified());
}

TEST_CASE("contactCache save-load roundtrip", "[contact]") {
  std::unordered_map<int32_t, Contact> cache;
  cache.emplace(1, Contact{1, "alice", {0x01, 0x02, 0x03}, true});
  cache.emplace(2, Contact{2, "bob", {0x04, 0x05, 0x06}, false});
  const std::string path = "/tmp/test_contact_cache.json";
  contactCacheSave(path, cache);
  const auto loaded = contactCacheLoad(path);
  REQUIRE(loaded.at(1).getUsername() == "alice");
  REQUIRE(loaded.at(1).isVerified());
  REQUIRE(loaded.at(2).getUsername() == "bob");
  REQUIRE_FALSE(loaded.at(2).isVerified());
  std::filesystem::remove(path);
}
