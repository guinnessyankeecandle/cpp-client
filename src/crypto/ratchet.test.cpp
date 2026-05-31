#include <catch2/catch.hpp>
import securemsg.crypto.ratchet;
import securemsg.crypto.random;
import securemsg.crypto.x25519;

static std::pair<RatchetState, RatchetState> makeAliceBob() {
  const auto sk = randomBytes(32);
  const auto bobSpk = x25519Generate();
  auto alice = RatchetState::initSender(sk, bobSpk.pub);
  auto bob = RatchetState::initReceiver(sk, bobSpk);
  return {std::move(alice), std::move(bob)};
}

TEST_CASE("Ratchet single message roundtrip", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  const std::vector<uint8_t> plain = {1, 2, 3, 4};
  const auto msg = alice.encrypt(plain);
  REQUIRE(bob.decrypt(msg).plaintext == plain);
}

TEST_CASE("Ratchet multiple sequential messages", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  for (uint8_t i = 0; i < 5; ++i) {
    const std::vector<uint8_t> p = {i};
    REQUIRE(bob.decrypt(alice.encrypt(p)).plaintext == p);
  }
}

TEST_CASE("Ratchet out-of-order messages decrypt correctly", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  const auto m1 = alice.encrypt({1});
  const auto m2 = alice.encrypt({2});
  const auto m3 = alice.encrypt({3});
  REQUIRE(bob.decrypt(m2).plaintext == std::vector<uint8_t>{2});
  REQUIRE(bob.decrypt(m1).plaintext == std::vector<uint8_t>{1});
  REQUIRE(bob.decrypt(m3).plaintext == std::vector<uint8_t>{3});
}

TEST_CASE("Ratchet bidirectional exchange", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  const auto m1 = alice.encrypt({0xAA});
  REQUIRE(bob.decrypt(m1).plaintext == std::vector<uint8_t>{0xAA});
  const auto m2 = bob.encrypt({0xBB});
  REQUIRE(alice.decrypt(m2).plaintext == std::vector<uint8_t>{0xBB});
  const auto m3 = alice.encrypt({0xCC});
  REQUIRE(bob.decrypt(m3).plaintext == std::vector<uint8_t>{0xCC});
}

TEST_CASE("Ratchet too many skipped messages throws", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  std::vector<RatchetMessage> msgs;
  for (int i = 0; i <= 1001; ++i)
    msgs.push_back(alice.encrypt({static_cast<uint8_t>(i)}));
  REQUIRE_THROWS_AS(bob.decrypt(msgs.back()), std::runtime_error);
}

TEST_CASE("SenderKeyRatchet single message roundtrip", "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  const std::vector<uint8_t> plain = {1, 2, 3, 4};
  REQUIRE(bob.decrypt(alice.encrypt(plain)).plaintext == plain);
}

TEST_CASE("SenderKeyRatchet multiple messages in order", "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  for (uint8_t i = 0; i < 10; ++i) {
    const std::vector<uint8_t> p = {i};
    REQUIRE(bob.decrypt(alice.encrypt(p)).plaintext == p);
  }
}

TEST_CASE("SenderKeyRatchet out-of-order messages decrypt correctly",
          "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  auto carol = SenderKeyRatchetState::init(sk);
  const auto m1 = alice.encrypt({1});
  const auto m2 = alice.encrypt({2});
  const auto m3 = alice.encrypt({3});
  REQUIRE(bob.decrypt(m2).plaintext == std::vector<uint8_t>{2});
  REQUIRE(bob.decrypt(m1).plaintext == std::vector<uint8_t>{1});
  REQUIRE(bob.decrypt(m3).plaintext == std::vector<uint8_t>{3});
  REQUIRE(carol.decrypt(m1).plaintext == std::vector<uint8_t>{1});
}

TEST_CASE("SenderKeyRatchet multiple recipients share same sender key",
          "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  auto carol = SenderKeyRatchetState::init(sk);
  const auto wire = alice.encrypt({0xAB});
  REQUIRE(bob.decrypt(wire).plaintext == std::vector<uint8_t>{0xAB});
  REQUIRE(carol.decrypt(wire).plaintext == std::vector<uint8_t>{0xAB});
}

TEST_CASE("SenderKeyRatchet duplicate message throws", "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  const auto wire = alice.encrypt({1});
  bob.decrypt(wire);
  REQUIRE_THROWS_AS(bob.decrypt(wire), std::runtime_error);
}

TEST_CASE("SenderKeyRatchet too many skipped messages throws", "[ratchet]") {
  const auto sk = randomBytes(32);
  auto alice = SenderKeyRatchetState::init(sk);
  auto bob = SenderKeyRatchetState::init(sk);
  std::vector<std::vector<uint8_t>> msgs;
  for (int i = 0; i <= 1001; ++i)
    msgs.push_back(alice.encrypt({static_cast<uint8_t>(i)}));
  REQUIRE_THROWS_AS(bob.decrypt(msgs.back()), std::runtime_error);
}

TEST_CASE("Ratchet receiver cannot encrypt before first decrypt", "[ratchet]") {
  const auto sk = randomBytes(32);
  const auto bobSpk = x25519Generate();
  auto bob = RatchetState::initReceiver(sk, bobSpk);
  REQUIRE_THROWS_AS(bob.encrypt({1}), std::runtime_error);
}

TEST_CASE("Ratchet replayed message throws", "[ratchet]") {
  auto [alice, bob] = makeAliceBob();
  const auto msg = alice.encrypt({0xDE});
  bob.decrypt(msg);
  REQUIRE_THROWS_AS(bob.decrypt(msg), std::runtime_error);
}
