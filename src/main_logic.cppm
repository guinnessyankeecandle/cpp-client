module;
#include <cstdint>
#include <string>
#include <vector>
export module securemsg.main_logic;

// Result of resolving a flat menu index into a contact or group selection.
// allLabels = contacts[0..contactCount) ++ groups[contactCount..)
export struct MenuSelection {
  bool isContact{false};
  bool isGroup{false};
  int32_t id{-1};
};

// Maps a flat menu index to a contact or group.
export inline MenuSelection
resolveMenuSelection(const std::vector<int32_t> &contactIds,
                     const std::vector<int32_t> &groupIds,
                     const int menuSelected) {
  if (menuSelected < 0)
    return {};
  const int contactCount = static_cast<int>(contactIds.size());
  if (menuSelected < contactCount)
    return {true, false, contactIds.at(menuSelected)};
  const int groupIndex = menuSelected - contactCount;
  if (groupIndex < static_cast<int>(groupIds.size()))
    return {false, true, groupIds.at(groupIndex)};
  return {};
}

// Builds the display label for a single message.
export inline std::string buildMessageLabel(const std::string &senderName,
                                            const std::string &plaintext) {
  return " " + senderName + ": " + plaintext;
}

// Builds the menu label for a contact, optionally with a group-creation checkbox.
export inline std::string buildContactLabel(const std::string &username,
                                            const bool verified,
                                            const bool creatingGroup,
                                            const bool selected) {
  if (creatingGroup)
    return std::string(selected ? "[x] " : "[ ] ") + username;
  return std::string(verified ? "✓ " : "  ") + username;
}
