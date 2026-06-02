#include <catch2/catch.hpp>
import securemsg.main_logic;

TEST_CASE("resolveMenuSelection selects first contact", "[main_logic]") {
  const std::vector<int32_t> contacts{10, 20, 30};
  const std::vector<int32_t> groups{100};
  const auto sel = resolveMenuSelection(contacts, groups, 0);
  REQUIRE(sel.isContact);
  REQUIRE(!sel.isGroup);
  REQUIRE(sel.id == 10);
}

TEST_CASE("resolveMenuSelection selects last contact", "[main_logic]") {
  const std::vector<int32_t> contacts{10, 20, 30};
  const std::vector<int32_t> groups{100};
  const auto sel = resolveMenuSelection(contacts, groups, 2);
  REQUIRE(sel.isContact);
  REQUIRE(sel.id == 30);
}

TEST_CASE("resolveMenuSelection selects group after contacts", "[main_logic]") {
  const std::vector<int32_t> contacts{10, 20};
  const std::vector<int32_t> groups{100, 200};
  const auto sel = resolveMenuSelection(contacts, groups, 2);
  REQUIRE(!sel.isContact);
  REQUIRE(sel.isGroup);
  REQUIRE(sel.id == 100);
}

TEST_CASE("resolveMenuSelection selects second group", "[main_logic]") {
  const std::vector<int32_t> contacts{10};
  const std::vector<int32_t> groups{100, 200};
  const auto sel = resolveMenuSelection(contacts, groups, 2);
  REQUIRE(sel.isGroup);
  REQUIRE(sel.id == 200);
}

TEST_CASE("resolveMenuSelection returns empty for negative index", "[main_logic]") {
  const auto sel = resolveMenuSelection({10}, {}, -1);
  REQUIRE(!sel.isContact);
  REQUIRE(!sel.isGroup);
}

TEST_CASE("resolveMenuSelection returns empty for out-of-range index", "[main_logic]") {
  const std::vector<int32_t> contacts{10};
  const std::vector<int32_t> groups{100};
  const auto sel = resolveMenuSelection(contacts, groups, 5);
  REQUIRE(!sel.isContact);
  REQUIRE(!sel.isGroup);
}

TEST_CASE("resolveMenuSelection works with no groups", "[main_logic]") {
  const std::vector<int32_t> contacts{10, 20};
  const auto sel = resolveMenuSelection(contacts, {}, 1);
  REQUIRE(sel.isContact);
  REQUIRE(sel.id == 20);
}

TEST_CASE("resolveMenuSelection works with no contacts", "[main_logic]") {
  const std::vector<int32_t> groups{100, 200};
  const auto sel = resolveMenuSelection({}, groups, 0);
  REQUIRE(sel.isGroup);
  REQUIRE(sel.id == 100);
}

TEST_CASE("buildMessageLabel formats correctly", "[main_logic]") {
  REQUIRE(buildMessageLabel("alice", "hello") == " alice: hello");
  REQUIRE(buildMessageLabel("You", "test") == " You: test");
}

TEST_CASE("buildContactLabel normal mode uses verified marker", "[main_logic]") {
  REQUIRE(buildContactLabel("alice", true,  false, false) == "✓ alice");
  REQUIRE(buildContactLabel("bob",   false, false, false) == "  bob");
}

TEST_CASE("buildContactLabel group creation mode shows checkbox", "[main_logic]") {
  REQUIRE(buildContactLabel("alice", true,  true, false) == "[ ] alice");
  REQUIRE(buildContactLabel("alice", true,  true, true)  == "[x] alice");
  REQUIRE(buildContactLabel("bob",   false, true, false) == "[ ] bob");
  REQUIRE(buildContactLabel("bob",   false, true, true)  == "[x] bob");
}

TEST_CASE("buildContactLabel verified flag ignored in group creation mode", "[main_logic]") {
  // verification status should not affect the label when creating a group
  REQUIRE(buildContactLabel("carol", true,  true, true) ==
          buildContactLabel("carol", false, true, true));
  REQUIRE(buildContactLabel("dave",  true,  true, false) ==
          buildContactLabel("dave",  false, true, false));
}
