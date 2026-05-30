#include <catch2/catch.hpp>
import securemsg.crypto.kdf;

TEST_CASE("HKDF matches RFC 5869 test vector case 1", "[kdf]") {
    std::vector<uint8_t> ikm(22, 0x0b);
    std::vector<uint8_t> salt = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                  0x08,0x09,0x0a,0x0b,0x0c};
    std::string info = {'\xf0','\xf1','\xf2','\xf3','\xf4','\xf5','\xf6','\xf7','\xf8','\xf9'};
    auto out = hkdf(ikm, salt, info, 42);

    std::vector<uint8_t> expected = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,
        0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,
        0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    REQUIRE(out == expected);
}

TEST_CASE("HKDF different info strings produce different keys", "[kdf]") {
    std::vector<uint8_t> ikm(32, 0x42);
    std::vector<uint8_t> salt(32, 0x00);
    auto a = hkdf(ikm, salt, "info-a", 32);
    auto b = hkdf(ikm, salt, "info-b", 32);
    REQUIRE(a != b);
}

TEST_CASE("HKDF different salts produce different keys", "[kdf]") {
    std::vector<uint8_t> ikm(32, 0x42);
    std::string info = "test";
    auto a = hkdf(ikm, std::vector<uint8_t>(16, 0x01), info, 32);
    auto b = hkdf(ikm, std::vector<uint8_t>(16, 0x02), info, 32);
    REQUIRE(a != b);
}

TEST_CASE("PBKDF2 output length is correct", "[kdf]") {
    std::vector<uint8_t> salt(16, 0xAB);
    auto out = pbkdf2("password", salt, 1000, 32);
    REQUIRE(out.size() == 32);
}

TEST_CASE("PBKDF2 different passwords produce different keys", "[kdf]") {
    std::vector<uint8_t> salt(16, 0x01);
    auto a = pbkdf2("password1", salt, 1000, 32);
    auto b = pbkdf2("password2", salt, 1000, 32);
    REQUIRE(a != b);
}

TEST_CASE("PBKDF2 different salts produce different keys", "[kdf]") {
    auto a = pbkdf2("password", std::vector<uint8_t>(16, 0x01), 1000, 32);
    auto b = pbkdf2("password", std::vector<uint8_t>(16, 0x02), 1000, 32);
    REQUIRE(a != b);
}
