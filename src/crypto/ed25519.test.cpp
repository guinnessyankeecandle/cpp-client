#include <catch2/catch.hpp>
import securemsg.crypto.ed25519;

TEST_CASE("Ed25519 sign-verify roundtrip", "[ed25519]") {
  auto kp = ed25519Generate();
  std::vector<uint8_t> msg = {1, 2, 3, 4};
  auto sig = ed25519Sign(kp.priv, msg);
  REQUIRE(ed25519Verify(kp.pub, msg, sig));
}

TEST_CASE("Ed25519 signature is 64 bytes", "[ed25519]") {
  auto kp = ed25519Generate();
  auto sig = ed25519Sign(kp.priv, {1, 2, 3});
  REQUIRE(sig.size() == 64);
}

TEST_CASE("Ed25519 tampered message fails verification", "[ed25519]") {
  auto kp = ed25519Generate();
  auto sig = ed25519Sign(kp.priv, {1, 2, 3});
  REQUIRE_FALSE(ed25519Verify(kp.pub, {1, 2, 4}, sig));
}

TEST_CASE("Ed25519 wrong key fails verification", "[ed25519]") {
  auto kp1 = ed25519Generate();
  auto kp2 = ed25519Generate();
  auto sig = ed25519Sign(kp1.priv, {1, 2, 3});
  REQUIRE_FALSE(ed25519Verify(kp2.pub, {1, 2, 3}, sig));
}

TEST_CASE("Ed25519 public key is 32 bytes", "[ed25519]") {
  auto kp = ed25519Generate();
  REQUIRE(kp.pub.size() == 32);
  REQUIRE(kp.priv.size() == 32);
}
