#include <catch2/catch.hpp>
import securemsg.messaging.store;
import securemsg.messaging.message;

static Message makeMsg(const int32_t id, const int32_t userId = 1) {
  return {id, userId, "ct", "hdr", BaseMessage::Direction::Received};
}

static GroupMessage makeGrpMsg(const int32_t id, const int32_t groupId = 10) {
  return {id, groupId, 0, 2, "ct"};
}

TEST_CASE("MessageStore add direct and retrieve by user", "[store]") {
  MessageStore s;
  s.add(makeMsg(1, 42));
  s.add(makeMsg(2, 42));
  s.add(makeMsg(3, 99));
  REQUIRE(s.getByUser(42).size() == 2);
  REQUIRE(s.getByUser(99).size() == 1);
  REQUIRE(s.getByUser(0).empty());
}

TEST_CASE("MessageStore add group and retrieve by group", "[store]") {
  MessageStore s;
  s.add(makeGrpMsg(1, 10));
  s.add(makeGrpMsg(2, 10));
  s.add(makeGrpMsg(3, 20));
  REQUIRE(s.getByGroup(10).size() == 2);
  REQUIRE(s.getByGroup(20).size() == 1);
  REQUIRE(s.getByGroup(99).empty());
}

TEST_CASE("MessageStore containsDirect uses userId", "[store]") {
  MessageStore s;
  s.add(makeMsg(5, 42));
  REQUIRE(s.containsDirect(42, 5));
  REQUIRE_FALSE(s.containsDirect(99, 5));
}

TEST_CASE("MessageStore containsGroup uses groupId", "[store]") {
  MessageStore s;
  s.add(makeGrpMsg(1, 10));
  s.add(makeGrpMsg(1, 20));
  REQUIRE(s.containsGroup(10, 1));
  REQUIRE(s.containsGroup(20, 1));
  REQUIRE_FALSE(s.containsGroup(99, 1));
}

TEST_CASE("MessageStore duplicate direct ID throws", "[store]") {
  MessageStore s;
  s.add(makeMsg(1, 42));
  REQUIRE_THROWS_AS(s.add(makeMsg(1, 42)), std::invalid_argument);
}

TEST_CASE("MessageStore direct and group can share id", "[store]") {
  MessageStore s;
  s.add(makeMsg(1, 42));
  s.add(makeGrpMsg(1, 10));
  REQUIRE(s.containsDirect(42, 1));
  REQUIRE(s.containsGroup(10, 1));
}

TEST_CASE("MessageStore clear", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  s.add(makeGrpMsg(2));
  s.clear();
  REQUIRE(s.getByUser(1).empty());
  REQUIRE(s.getByGroup(10).empty());
}
