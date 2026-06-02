#include <catch2/catch.hpp>
import securemsg.messaging.store;
import securemsg.messaging.message;

static Message makeMsg(const int32_t id, const int32_t userId = 1,
                       const uint64_t tsMs = 0) {
  return {id, userId, "ct", "hdr", BaseMessage::Direction::Received, tsMs, ""};
}

static GroupMessage makeGrpMsg(const int32_t id, const int32_t groupId = 10,
                               const uint64_t tsMs = 0) {
  return {id, groupId, 2, "ct", BaseMessage::Direction::Received, tsMs, ""};
}

TEST_CASE("MessageStore add direct and retrieve by user", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(1, 42, 0));
  s.add(makeMsg(2, 42, 1));
  s.add(makeMsg(3, 99, 0));
  REQUIRE(s.getByUser(42).size() == 2);
  REQUIRE(s.getByUser(99).size() == 1);
  REQUIRE(s.getByUser(0).empty());
}

TEST_CASE("MessageStore add group and retrieve by group", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeGrpMsg(1, 10, 0));
  s.add(makeGrpMsg(2, 10, 1));
  s.add(makeGrpMsg(3, 20, 0));
  REQUIRE(s.getByGroup(10).size() == 2);
  REQUIRE(s.getByGroup(20).size() == 1);
  REQUIRE(s.getByGroup(99).empty());
}

TEST_CASE("MessageStore getByUser returns in timestamp order", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(3, 42, 2000));
  s.add(makeMsg(1, 42, 0));
  s.add(makeMsg(2, 42, 1000));
  const auto msgs = s.getByUser(42);
  REQUIRE(msgs[0].getId() == 1);
  REQUIRE(msgs[1].getId() == 2);
  REQUIRE(msgs[2].getId() == 3);
}

TEST_CASE("MessageStore containsDirect uses userId", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(5, 42, 0));
  REQUIRE(s.containsDirect(42, 5));
  REQUIRE_FALSE(s.containsDirect(99, 5));
}

TEST_CASE("MessageStore containsGroup uses groupId", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeGrpMsg(1, 10, 0));
  s.add(makeGrpMsg(2, 20, 0));
  REQUIRE(s.containsGroup(10, 1));
  REQUIRE(s.containsGroup(20, 2));
  REQUIRE_FALSE(s.containsGroup(99, 1));
}

TEST_CASE("MessageStore duplicate direct ID is ignored", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(1, 42, 0));
  s.add(makeMsg(1, 42, 1));
  REQUIRE(s.getByUser(42).size() == 1);
}

TEST_CASE("MessageStore removeMessage removes from direct", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(1, 42, 0));
  s.removeDirectMessage(42, 1);
  REQUIRE_FALSE(s.containsDirect(42, 1));
}

TEST_CASE("MessageStore removeMessage removes from group", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeGrpMsg(1, 10, 0));
  s.removeGroupMessage(10, 1);
  REQUIRE_FALSE(s.containsGroup(10, 1));
}

TEST_CASE("MessageStore clear", "[store]") {
  MessageStore s(":memory:", {});
  s.add(makeMsg(1, 1, 0));
  s.add(makeGrpMsg(2, 10, 0));
  s.clear();
  REQUIRE(s.getByUser(1).empty());
  REQUIRE(s.getByGroup(10).empty());
}

TEST_CASE("MessageStore sent message appears in getByUser", "[store]") {
  MessageStore s(":memory:", {});
  // Simulate sending a message (Sent direction, userId = recipient)
  const Message sent{1, 42, "ct", "hdr", BaseMessage::Direction::Sent, 1000, "hello"};
  s.add(sent);
  const auto msgs = s.getByUser(42);
  REQUIRE(msgs.size() == 1);
  REQUIRE(msgs[0].getPlaintext() == "hello");
  REQUIRE(msgs[0].getDirection() == BaseMessage::Direction::Sent);
}

TEST_CASE("MessageStore received message appears in getByUser", "[store]") {
  MessageStore s(":memory:", {});
  const Message recv{2, 99, "ct", "hdr", BaseMessage::Direction::Received, 2000, "world"};
  s.add(recv);
  const auto msgs = s.getByUser(99);
  REQUIRE(msgs.size() == 1);
  REQUIRE(msgs[0].getPlaintext() == "world");
  REQUIRE(msgs[0].getDirection() == BaseMessage::Direction::Received);
}

TEST_CASE("MessageStore mixed sent and received ordered by timestamp", "[store]") {
  MessageStore s(":memory:", {});
  s.add(Message{1, 5, "ct", "hdr", BaseMessage::Direction::Sent,     1000, "first"});
  s.add(Message{2, 5, "ct", "hdr", BaseMessage::Direction::Received, 2000, "second"});
  s.add(Message{3, 5, "ct", "hdr", BaseMessage::Direction::Sent,     3000, "third"});
  const auto msgs = s.getByUser(5);
  REQUIRE(msgs.size() == 3);
  REQUIRE(msgs[0].getPlaintext() == "first");
  REQUIRE(msgs[1].getPlaintext() == "second");
  REQUIRE(msgs[2].getPlaintext() == "third");
}
