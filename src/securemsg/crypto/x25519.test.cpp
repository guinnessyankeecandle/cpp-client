#include <catch2/catch.hpp>
import securemsg.crypto.x25519;

TEST_CASE("X25519 DH is commutative", "[x25519]") {
    auto a = x25519Generate();
    auto b = x25519Generate();
    REQUIRE(x25519DH(a.priv, b.pub) == x25519DH(b.priv, a.pub));
}

TEST_CASE("X25519 DH output is 32 bytes", "[x25519]") {
    auto a = x25519Generate();
    auto b = x25519Generate();
    REQUIRE(x25519DH(a.priv, b.pub).size() == 32);
}

TEST_CASE("X25519 different key pairs produce different shared secrets", "[x25519]") {
    auto a = x25519Generate();
    auto b = x25519Generate();
    auto c = x25519Generate();
    REQUIRE(x25519DH(a.priv, b.pub) != x25519DH(a.priv, c.pub));
}

TEST_CASE("X25519 publicFromPrivate matches generated public key", "[x25519]") {
    auto kp  = x25519Generate();
    auto pub = x25519PublicFromPrivate(kp.priv);
    REQUIRE(pub == kp.pub);
}

TEST_CASE("X25519 key sizes are 32 bytes", "[x25519]") {
    auto kp = x25519Generate();
    REQUIRE(kp.priv.size() == 32);
    REQUIRE(kp.pub.size()  == 32);
}
