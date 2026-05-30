#include <catch2/catch.hpp>
import securemsg.crypto.ratchet;
import securemsg.crypto.random;
import securemsg.crypto.x25519;

static std::pair<RatchetState, RatchetState> makeAliceBob() {
    auto sk     = randomBytes(32);
    auto bobSpk = x25519Generate();
    auto alice  = RatchetState::initSender(sk, bobSpk.pub);
    auto bob    = RatchetState::initReceiver(sk, bobSpk);
    return {std::move(alice), std::move(bob)};
}

TEST_CASE("Ratchet single message roundtrip", "[ratchet]") {
    auto [alice, bob] = makeAliceBob();
    std::vector<uint8_t> plain = {1, 2, 3, 4};
    auto msg = alice.encrypt(plain);
    REQUIRE(bob.decrypt(msg) == plain);
}

TEST_CASE("Ratchet multiple sequential messages", "[ratchet]") {
    auto [alice, bob] = makeAliceBob();
    for (uint8_t i = 0; i < 5; ++i) {
        std::vector<uint8_t> p = {i};
        REQUIRE(bob.decrypt(alice.encrypt(p)) == p);
    }
}

TEST_CASE("Ratchet out-of-order messages decrypt correctly", "[ratchet]") {
    auto [alice, bob] = makeAliceBob();
    auto m1 = alice.encrypt({1});
    auto m2 = alice.encrypt({2});
    auto m3 = alice.encrypt({3});
    REQUIRE(bob.decrypt(m2) == std::vector<uint8_t>{2});
    REQUIRE(bob.decrypt(m1) == std::vector<uint8_t>{1});
    REQUIRE(bob.decrypt(m3) == std::vector<uint8_t>{3});
}

TEST_CASE("Ratchet bidirectional exchange", "[ratchet]") {
    auto [alice, bob] = makeAliceBob();
    auto m1 = alice.encrypt({0xAA});
    REQUIRE(bob.decrypt(m1) == std::vector<uint8_t>{0xAA});
    auto m2 = bob.encrypt({0xBB});
    REQUIRE(alice.decrypt(m2) == std::vector<uint8_t>{0xBB});
    auto m3 = alice.encrypt({0xCC});
    REQUIRE(bob.decrypt(m3) == std::vector<uint8_t>{0xCC});
}

TEST_CASE("Ratchet too many skipped messages throws", "[ratchet]") {
    auto [alice, bob] = makeAliceBob();
    std::vector<RatchetMessage> msgs;
    for (int i = 0; i <= 1001; ++i)
        msgs.push_back(alice.encrypt({static_cast<uint8_t>(i)}));
    REQUIRE_THROWS_AS(bob.decrypt(msgs.back()), std::runtime_error);
}
