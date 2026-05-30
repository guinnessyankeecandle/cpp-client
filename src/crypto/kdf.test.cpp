#include <catch2/catch.hpp>
import securemsg.crypto.kdf;

TEST_CASE("HKDF matches RFC 5869 test vector case 1", "[kdf]") {
  const std::vector<uint8_t> ikm(22, 0x0b);
  const std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  const std::string info = {'\xf0', '\xf1', '\xf2', '\xf3', '\xf4',
                            '\xf5', '\xf6', '\xf7', '\xf8', '\xf9'};
  const auto out = hkdf(ikm, salt, info, 42);

  const std::vector<uint8_t> expected = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
      0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
  REQUIRE(out == expected);
}

TEST_CASE("HKDF different info strings produce different keys", "[kdf]") {
  const std::vector<uint8_t> ikm(32, 0x42);
  const std::vector<uint8_t> salt(32, 0x00);
  const auto a = hkdf(ikm, salt, "info-a", 32);
  const auto b = hkdf(ikm, salt, "info-b", 32);
  REQUIRE(a != b);
}

TEST_CASE("HKDF different salts produce different keys", "[kdf]") {
  const std::vector<uint8_t> ikm(32, 0x42);
  const std::string info = "test";
  const auto a = hkdf(ikm, std::vector<uint8_t>(16, 0x01), info, 32);
  const auto b = hkdf(ikm, std::vector<uint8_t>(16, 0x02), info, 32);
  REQUIRE(a != b);
}

TEST_CASE("PBKDF2 output length is correct", "[kdf]") {
  const std::vector<uint8_t> salt(16, 0xAB);
  const auto out = pbkdf2(\1, 32);
  REQUIRE(out.size() == 32);
}

TEST_CASE("PBKDF2 different passwords produce different keys", "[kdf]") {
  const std::vector<uint8_t> salt(16, 0x01);
  const auto a = pbkdf2(\1, 32);
  const auto b = pbkdf2(\1, 32);
  REQUIRE(a != b);
}

TEST_CASE("PBKDF2 different salts produce different keys", "[kdf]") {
  const auto a = pbkdf2(\1, 32);
  const auto b = pbkdf2(\1, 32);
  REQUIRE(a != b);
}
