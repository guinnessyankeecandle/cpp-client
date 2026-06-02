#include <catch2/catch.hpp>
import securemsg.models.group;

TEST_CASE("Group construction and getters", "[group]") {
  const Group g{1, "engineering", {42, 7, 3}, 0};
  REQUIRE(g.getId() == 1);
  REQUIRE(g.getName() == "engineering");
  REQUIRE(g.getEpoch() == 0);
  REQUIRE(g.getMembers().size() == 3);
}

TEST_CASE("Group addMember ignores duplicates", "[group]") {
  Group g{1, "eng", {1}, 0};
  g.addMember(2);
  g.addMember(2);
  REQUIRE(g.getMembers().size() == 2);
}

TEST_CASE("Group removeMember", "[group]") {
  Group g{1, "eng", {1, 2, 3}, 0};
  g.removeMember(2);
  REQUIRE(g.getMembers().size() == 2);
  REQUIRE_FALSE(g.hasMember(2));
}

TEST_CASE("Group setEpoch", "[group]") {
  Group g{1, "eng", {1}, 0};
  g.setEpoch(5);
  REQUIRE(g.getEpoch() == 5);
}

TEST_CASE("Group hasMember", "[group]") {
  const Group g{1, "eng", {1, 2}, 0};
  REQUIRE(g.hasMember(1));
  REQUIRE_FALSE(g.hasMember(99));
}

// ── Group member management tests ────────────────────────────────────────────

TEST_CASE("Group members from constructor are accessible", "[group]") {
  const Group g{5, "team", {10, 20, 30}, 2};
  const auto &m = g.getMembers();
  REQUIRE(m.size() == 3);
  REQUIRE(g.hasMember(10));
  REQUIRE(g.hasMember(20));
  REQUIRE(g.hasMember(30));
  REQUIRE_FALSE(g.hasMember(99));
}

TEST_CASE("Group addMember increases member count", "[group]") {
  Group g{1, "g", {1, 2}, 0};
  g.addMember(3);
  REQUIRE(g.getMembers().size() == 3);
  REQUIRE(g.hasMember(3));
}

TEST_CASE("Group removeMember on non-existent member is a no-op", "[group]") {
  Group g{1, "g", {1, 2}, 0};
  g.removeMember(99);
  REQUIRE(g.getMembers().size() == 2);
}

TEST_CASE("Group removeMember then re-add works", "[group]") {
  Group g{1, "g", {1, 2, 3}, 0};
  g.removeMember(2);
  REQUIRE_FALSE(g.hasMember(2));
  g.addMember(2);
  REQUIRE(g.hasMember(2));
  REQUIRE(g.getMembers().size() == 3);
}

TEST_CASE("Group epoch increments track membership changes", "[group]") {
  Group g{1, "g", {1}, 0};
  g.setEpoch(1);
  REQUIRE(g.getEpoch() == 1);
  g.setEpoch(2);
  REQUIRE(g.getEpoch() == 2);
}
