#include <catch2/catch.hpp>
import securemsg.messaging.store;
import securemsg.messaging.message;

static Message makeMsg(int32_t id) {
  return {id, 1, 2, "ct", "hdr", 0, Message::Direction::Received};
}

TEST_CASE("MessageStore add and getById", "[store]") {
  MessageStore s;
  s.add(makeMsg(42));
  REQUIRE(s.getById(42).getId() == 42);
}

TEST_CASE("MessageStore getAll returns insertion order", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  s.add(makeMsg(2));
  s.add(makeMsg(3));
  auto &all = s.getAll();
  REQUIRE(all[0].getId() == 1);
  REQUIRE(all[1].getId() == 2);
  REQUIRE(all[2].getId() == 3);
}

TEST_CASE("MessageStore duplicate ID overwrites", "[store]") {
  MessageStore s;
  s.add(makeMsg(1));
  Message updated{1, 1, 2, "new_ct", "hdr", 0, Message::Direction::Sent};
  s.add(std::move(updated));
  REQUIRE(s.size() == 1);
  REQUIRE(s.getById(1).getCiphertext() == "new_ct");
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
