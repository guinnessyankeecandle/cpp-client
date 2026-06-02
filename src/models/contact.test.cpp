#include <catch2/catch.hpp>
#include <filesystem>
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
  std::vector<Contact> cache;
  cache.emplace_back(1, "alice", std::vector<uint8_t>{0x01, 0x02, 0x03}, true);
  cache.emplace_back(2, "bob", std::vector<uint8_t>{0x04, 0x05, 0x06}, false);
  const std::string path = "/tmp/test_contact_cache.json";
  contactCacheSave(path, cache);
  const auto loaded = contactCacheLoad(path);
  REQUIRE(loaded.at(0).getUsername() == "alice");
  REQUIRE(loaded.at(0).isVerified());
  REQUIRE(loaded.at(1).getUsername() == "bob");
  REQUIRE_FALSE(loaded.at(1).isVerified());
  std::filesystem::remove(path);
}

TEST_CASE("Contact constructed with identity pub exposes it correctly", "[contact]") {
  const std::vector<uint8_t> ikPub(32, 0xAB);
  const Contact c(42, "alice", ikPub);
  REQUIRE(c.getIdentityPub() == ikPub);
  REQUIRE(c.getId() == 42);
  REQUIRE(c.getUsername() == "alice");
}

TEST_CASE("Contact constructed with empty identity pub reports not verified", "[contact]") {
  const Contact c(1, "bob", {});
  REQUIRE(c.getIdentityPub().empty());
  REQUIRE(!c.isVerified());
}
