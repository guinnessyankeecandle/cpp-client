#include <catch2/catch.hpp>
import securemsg.messaging.send_receive;
import securemsg.crypto.ratchet;
import securemsg.crypto.random;
import securemsg.crypto.x25519;

TEST_CASE("Direct message ratchet encrypt-decrypt roundtrip",
          "[send_receive]") {
  auto sk = randomBytes(32);
  auto spk = x25519Generate();
  auto alice = RatchetState::initSender(sk, spk.pub);
  auto bob = RatchetState::initReceiver(sk, spk);
  std::vector<uint8_t> plain = {'h', 'e', 'l', 'l', 'o'};
  auto msg = alice.encrypt(plain);
  REQUIRE(bob.decrypt(msg).plaintext == plain);
}

TEST_CASE("Multiple direct messages decrypt in order", "[send_receive]") {
  auto sk = randomBytes(32);
  auto spk = x25519Generate();
  auto alice = RatchetState::initSender(sk, spk.pub);
  auto bob = RatchetState::initReceiver(sk, spk);
  for (uint8_t i = 0; i < 10; ++i) {
    std::vector<uint8_t> p = {i};
    REQUIRE(bob.decrypt(alice.encrypt(p)).plaintext == p);
  }
}

TEST_CASE("Bidirectional ratchet exchange", "[send_receive]") {
  auto sk = randomBytes(32);
  auto spk = x25519Generate();
  auto alice = RatchetState::initSender(sk, spk.pub);
  auto bob = RatchetState::initReceiver(sk, spk);
  REQUIRE(bob.decrypt(alice.encrypt({0xAA})).plaintext ==
          std::vector<uint8_t>{0xAA});
  REQUIRE(alice.decrypt(bob.encrypt({0xBB})).plaintext ==
          std::vector<uint8_t>{0xBB});
  REQUIRE(bob.decrypt(alice.encrypt({0xCC})).plaintext ==
          std::vector<uint8_t>{0xCC});
}

TEST_CASE("SkdmEpochTracker stale incoming discarded", "[send_receive]") {
  SkdmEpochTracker tracker;
  tracker.recordPosted(1, 3);
  REQUIRE(tracker.resolve(1, 3) == -1);
}

TEST_CASE("SkdmEpochTracker conflict: theirs owns same epoch",
          "[send_receive]") {
  SkdmEpochTracker tracker;
  tracker.recordPosted(1, 3);
  REQUIRE(tracker.resolve(1, 4) == 4);
}

TEST_CASE("SkdmEpochTracker newer epoch: use theirs", "[send_receive]") {
  SkdmEpochTracker tracker;
  tracker.recordPosted(1, 3);
  REQUIRE(tracker.resolve(1, 5) == 5);
}

TEST_CASE("SkdmEpochTracker no prior post: passthrough", "[send_receive]") {
  SkdmEpochTracker tracker;
  REQUIRE(tracker.resolve(99, 7) == 7);
}

TEST_CASE("SkdmEpochTracker hasPosted returns false before recording",
          "[send_receive]") {
  SkdmEpochTracker tracker;
  REQUIRE_FALSE(tracker.hasPosted(1));
  REQUIRE_FALSE(tracker.hasPosted(99));
}

TEST_CASE("SkdmEpochTracker hasPosted returns true after recording",
          "[send_receive]") {
  SkdmEpochTracker tracker;
  tracker.recordPosted(1, 0);
  REQUIRE(tracker.hasPosted(1));
  REQUIRE_FALSE(tracker.hasPosted(2));
}

TEST_CASE("SkdmEpochTracker recordPosted multiple groups", "[send_receive]") {
  SkdmEpochTracker tracker;
  tracker.recordPosted(1, 0);
  tracker.recordPosted(2, 5);
  REQUIRE(tracker.hasPosted(1));
  REQUIRE(tracker.hasPosted(2));
  REQUIRE_FALSE(tracker.hasPosted(3));
  REQUIRE(tracker.resolve(1, 1) == 1);
  REQUIRE(tracker.resolve(2, 6) == 6);
}
