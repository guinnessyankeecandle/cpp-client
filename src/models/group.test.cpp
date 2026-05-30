#include <catch2/catch.hpp>
import securemsg.models.group;

TEST_CASE("Group construction and getters", "[group]") {
    const Group g{1, "engineering", {42, 7, 3}, 0};
    REQUIRE(g.getId()             == 1);
    REQUIRE(g.getName()           == "engineering");
    REQUIRE(g.getEpoch()          == 0);
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
