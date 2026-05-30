#include <catch2/catch.hpp>
import securemsg.crypto.mlkem;

TEST_CASE("ML-KEM-1024 encap-decap roundtrip produces equal shared secrets", "[mlkem]") {
    auto kp  = mlkemGenerate();
    auto enc = mlkemEncap(kp.pub);
    auto ss  = mlkemDecap(kp.priv, enc.ciphertext);
    REQUIRE(ss == enc.sharedSecret);
}

TEST_CASE("ML-KEM-1024 public key is 1568 bytes (FIPS 203)", "[mlkem]") {
    auto kp = mlkemGenerate();
    REQUIRE(kp.pub.size() == 1568);
}

TEST_CASE("ML-KEM-1024 ciphertext is 1568 bytes", "[mlkem]") {
    auto kp  = mlkemGenerate();
    auto enc = mlkemEncap(kp.pub);
    REQUIRE(enc.ciphertext.size() == 1568);
}

TEST_CASE("ML-KEM-1024 shared secret is 32 bytes", "[mlkem]") {
    auto kp  = mlkemGenerate();
    auto enc = mlkemEncap(kp.pub);
    REQUIRE(enc.sharedSecret.size() == 32);
}

TEST_CASE("ML-KEM-1024 decap with wrong key produces different shared secret", "[mlkem]") {
    auto kp1 = mlkemGenerate();
    auto kp2 = mlkemGenerate();
    auto enc = mlkemEncap(kp1.pub);
    auto ss1 = mlkemDecap(kp1.priv, enc.ciphertext);
    auto ss2 = mlkemDecap(kp2.priv, enc.ciphertext);
    REQUIRE(ss1 != ss2);
}
