#include <catch2/catch.hpp>
import securemsg.crypto.aead;
import securemsg.crypto.random;

static std::vector<uint8_t> makeKey() { return randomBytes(KEY_BYTES); }

TEST_CASE("AEAD encrypt-decrypt roundtrip", "[aead]") {
  const auto key = makeKey();
  const std::vector<uint8_t> plain = {1, 2, 3, 4, 5};
  const auto pkt = aeadEncrypt(plain, key);
  const auto decoded = aeadDecrypt(pkt, key);
  REQUIRE(decoded == plain);
}

TEST_CASE("AEAD wrong key fails authentication", "[aead]") {
  const auto key1 = makeKey();
  const auto key2 = makeKey();
  const auto pkt = aeadEncrypt({1, 2, 3}, key1);
  REQUIRE_THROWS_AS(aeadDecrypt(pkt, key2), std::runtime_error);
}

TEST_CASE("AEAD tampered tag fails", "[aead]") {
  const auto key = makeKey();
  auto pkt = aeadEncrypt({1, 2, 3}, key);
  pkt.tag[0] ^= 0xFF;
  REQUIRE_THROWS_AS(aeadDecrypt(pkt, key), std::runtime_error);
}

TEST_CASE("AEAD tampered ciphertext fails", "[aead]") {
  const auto key = makeKey();
  auto pkt = aeadEncrypt({1, 2, 3}, key);
  pkt.ciphertext[0] ^= 0xFF;
  REQUIRE_THROWS_AS(aeadDecrypt(pkt, key), std::runtime_error);
}

TEST_CASE("AEAD empty plaintext roundtrip", "[aead]") {
  const auto key = makeKey();
  const auto pkt = aeadEncrypt({}, key);
  const auto out = aeadDecrypt(pkt, key);
  REQUIRE(out.empty());
}

TEST_CASE("packAead / unpackAead roundtrip", "[aead]") {
  const auto key = makeKey();
  const auto pkt = aeadEncrypt({10, 20, 30}, key);
  const auto raw = packAead(pkt);
  const auto pkt2 = unpackAead(raw);
  REQUIRE(aeadDecrypt(pkt2, key) == std::vector<uint8_t>{10, 20, 30});
}

TEST_CASE("unpackAead throws on too-short input", "[aead]") {
  const std::vector<uint8_t> bad(IV_BYTES + TAG_BYTES - 1, 0);
  REQUIRE_THROWS_AS(unpackAead(bad), std::runtime_error);
}
