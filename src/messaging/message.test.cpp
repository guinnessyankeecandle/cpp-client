#include <catch2/catch.hpp>
import securemsg.messaging.message;

TEST_CASE("Message construction and getters", "[message]") {
  const Message m{1, 2, "ct", "hdr", Message::Direction::Received};
  REQUIRE(m.getId() == 1);
  REQUIRE(m.getUserId() == 2);
  REQUIRE(m.getCiphertext() == "ct");
  REQUIRE(m.getRatchetHeaderEnc() == "hdr");
  REQUIRE(m.getDirection() == Message::Direction::Received);
  REQUIRE(m.getPlaintext().empty());
}

TEST_CASE("Message setPlaintext", "[message]") {
  Message m{1, 2, "ct", "hdr", Message::Direction::Sent};
  m.setPlaintext("hello");
  REQUIRE(m.getPlaintext() == "hello");
}

TEST_CASE("Message Direction enum values distinct", "[message]") {
  REQUIRE(Message::Direction::Sent != Message::Direction::Received);
}

TEST_CASE("GroupMessage construction and getters", "[message]") {
  const GroupMessage gm{1, 10, 2, 42, "ct", BaseMessage::Direction::Received};
  REQUIRE(gm.getId() == 1);
  REQUIRE(gm.getGroupId() == 10);
  REQUIRE(gm.getEpoch() == 2);
  REQUIRE(gm.getUserId() == 42);
  REQUIRE(gm.getCiphertext() == "ct");
  REQUIRE(gm.getPlaintext().empty());
}

TEST_CASE("GroupMessage setPlaintext", "[message]") {
  GroupMessage gm{1, 10, 2, 42, "ct", BaseMessage::Direction::Received};
  gm.setPlaintext("hello group");
  REQUIRE(gm.getPlaintext() == "hello group");
}
