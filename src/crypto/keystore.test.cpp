#include <catch2/catch.hpp>
#include <filesystem>
import securemsg.crypto.keystore;
import securemsg.crypto.ed25519;

TEST_CASE("keystoreGenerate produces valid bundle", "[keystore]") {
  auto kb = keystoreGenerate();
  REQUIRE(kb.ik.pub.size() == 32);
  REQUIRE(kb.spk.pub.size() == 32);
  REQUIRE(kb.spkSig.size() == 64);
  REQUIRE(kb.pq.pub.size() == 1568);
  REQUIRE(kb.pqSig.size() == 64);
  REQUIRE(kb.opks.size() == 20);
}

TEST_CASE("keystoreGenerate SPK signature verifies", "[keystore]") {
  auto kb = keystoreGenerate();
  REQUIRE(ed25519Verify(kb.ik.pub, kb.spk.pub, kb.spkSig));
}

TEST_CASE("keystoreGenerate PQ prekey signature verifies", "[keystore]") {
  auto kb = keystoreGenerate();
  REQUIRE(ed25519Verify(kb.ik.pub, kb.pq.pub, kb.pqSig));
}

TEST_CASE("keystore save-load roundtrip recovers bundle", "[keystore]") {
  auto kb = keystoreGenerate();
  std::string path = "/tmp/test_identity_roundtrip.key";
  keystoreSave(path, kb, "testpassword");
  auto kb2 = keystoreLoad(path, "testpassword");
  REQUIRE(kb2.ik.pub == kb.ik.pub);
  REQUIRE(kb2.spk.pub == kb.spk.pub);
  REQUIRE(kb2.pq.pub == kb.pq.pub);
  REQUIRE(kb2.opks.size() == kb.opks.size());
  std::filesystem::remove(path);
}

TEST_CASE("keystoreLoad wrong password throws", "[keystore]") {
  auto kb = keystoreGenerate();
  std::string path = "/tmp/test_identity_wrongpass.key";
  keystoreSave(path, kb, "correctpassword");
  REQUIRE_THROWS_AS(keystoreLoad(path, "wrongpassword"), std::runtime_error);
  std::filesystem::remove(path);
}

TEST_CASE("identityCache save-load roundtrip", "[keystore]") {
  std::unordered_map<int32_t, Identity> cache;
  cache[1] = {"alice", {0x01, 0x02, 0x03}, true};
  cache[2] = {"bob", {0x04, 0x05, 0x06}, false};
  std::string path = "/tmp/test_identity_cache.json";
  identityCacheSave(path, cache);
  auto loaded = identityCacheLoad(path);
  REQUIRE(loaded[1].username == "alice");
  REQUIRE(loaded[1].verified == true);
  REQUIRE(loaded[2].username == "bob");
  REQUIRE(loaded[2].verified == false);
  std::filesystem::remove(path);
}
