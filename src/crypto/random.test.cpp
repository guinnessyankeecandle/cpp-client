#include <catch2/catch.hpp>
import securemsg.crypto.random;

TEST_CASE("randomBytes returns correct length", "[random]") {
    REQUIRE(randomBytes(16).size() == 16);
    REQUIRE(randomBytes(32).size() == 32);
    REQUIRE(randomBytes(0).size()  == 0);
}

TEST_CASE("randomBytes two calls are not equal", "[random]") {
    auto a = randomBytes(32);
    auto b = randomBytes(32);
    REQUIRE(a != b);
}

TEST_CASE("sslAssert throws on failure", "[random]") {
    REQUIRE_THROWS_AS(sslAssert(0, "test_op"), std::runtime_error);
}

TEST_CASE("sslAssert does not throw on success", "[random]") {
    REQUIRE_NOTHROW(sslAssert(1, "test_op"));
}

TEST_CASE("base64 encode-decode roundtrip", "[random]") {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0xAB, 0xCD};
    auto encoded = base64Encode(data);
    auto decoded = base64Decode(encoded);
    REQUIRE(decoded == data);
}

TEST_CASE("base64 empty input", "[random]") {
    std::vector<uint8_t> empty;
    auto encoded = base64Encode(empty);
    auto decoded = base64Decode(encoded);
    REQUIRE(decoded.empty());
}
