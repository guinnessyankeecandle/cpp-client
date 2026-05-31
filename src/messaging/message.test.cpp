#include <catch2/catch.hpp>
import securemsg.messaging.message;

TEST_CASE("Message construction and getters", "[message]") {
  const Message m{1, 2, "ct", "hdr", Message::Direction::Received, 0, 0, ""};
  REQUIRE(m.getId() == 1);
  REQUIRE(m.getUserId() == 2);
  REQUIRE(m.getCiphertext() == "ct");
  REQUIRE(m.getRatchetHeaderEnc() == "hdr");
  REQUIRE(m.getDirection() == Message::Direction::Received);
  REQUIRE(m.getPlaintext().empty());
}

TEST_CASE("Message plaintext via constructor", "[message]") {
  const Message m{1, 2, "ct", "hdr", Message::Direction::Sent, 0, 0, "hello"};
  REQUIRE(m.getPlaintext() == "hello");
}

TEST_CASE("Message Direction enum values distinct", "[message]") {
  REQUIRE(Message::Direction::Sent != Message::Direction::Received);
}

TEST_CASE("GroupMessage construction and getters", "[message]") {
  const GroupMessage gm{1, 10, 2, 42, "ct", BaseMessage::Direction::Received,
                        0, ""};
  REQUIRE(gm.getId() == 1);
  REQUIRE(gm.getGroupId() == 10);
  REQUIRE(gm.getChainEpoch() == 2);
  REQUIRE(gm.getUserId() == 42);
  REQUIRE(gm.getCiphertext() == "ct");
  REQUIRE(gm.getPlaintext().empty());
}

TEST_CASE("GroupMessage plaintext via constructor", "[message]") {
  const GroupMessage gm{
      1, 10, 2, 42, "ct", BaseMessage::Direction::Received, 0, "hello group"};
  REQUIRE(gm.getPlaintext() == "hello group");
}
