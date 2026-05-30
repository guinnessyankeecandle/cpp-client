#include <catch2/catch.hpp>
#include <variant>
import securemsg.messaging.store;
import securemsg.messaging.message;

static Message makeMsg(const int32_t id) {
  return {id, 1, "ct", "hdr", BaseMessage::Direction::Received};
}

static GroupMessage makeGrpMsg(const int32_t id) {
  return {id, 10, 0, 2, "ct"};
}

TEST_CASE("MessageStore add and getById direct message", "[store]") {
  MessageStore s;
  s.add(makeMsg(42));
  REQUIRE(std::get<Message>(s.getById(42)).getId() == 42);
}

TEST_CASE("MessageStore add and getById group message", "[store]") {
  MessageStore s;
  s.add(makeGrpMsg(7));
  REQUIRE(std::get<GroupMessage>(s.getById(7)).getGroupId() == 10);
}

TEST_CASE("MessageStore getAll returns insertion order", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  s.add(makeMsg(2));
  s.add(makeMsg(3));
  const auto &all = s.getAll();
  REQUIRE(std::get<Message>(all[0]).getId() == 1);
  REQUIRE(std::get<Message>(all[1]).getId() == 2);
  REQUIRE(std::get<Message>(all[2]).getId() == 3);
}

TEST_CASE("MessageStore duplicate ID overwrites", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  Message updated{1, 1, "new_ct", "hdr", BaseMessage::Direction::Sent};
  s.add(std::move(updated));
  REQUIRE(s.size() == 1);
  REQUIRE(std::get<Message>(s.getById(1)).getCiphertext() == "new_ct");
}

TEST_CASE("MessageStore getById throws on missing ID", "[store]") {
  MessageStore s;
  REQUIRE_THROWS_AS(s.getById(99), std::out_of_range);
}

TEST_CASE("MessageStore contains", "[store]") {
  MessageStore s;
  s.add(makeMsg(5));
  REQUIRE(s.contains(5));
  REQUIRE_FALSE(s.contains(6));
}

TEST_CASE("MessageStore mixed direct and group messages", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  s.add(makeGrpMsg(2));
  REQUIRE(s.size() == 2);
  REQUIRE(s.contains(1));
  REQUIRE(s.contains(2));
}
