module;
#include <cstdint>
#include <ranges>
#include <stdexcept>
#include <unordered_map>
#include <variant>
#include <vector>
export module securemsg.messaging.store;
import securemsg.messaging.message;

export using AnyMessage = std::variant<Message, GroupMessage>;

export class MessageStore {
public:
  void add(Message msg) {
    const auto userId = msg.getUserId();
    const auto id = msg.getId();
    if (m_direct[userId].contains(id))
      throw std::invalid_argument("Duplicate direct message ID");
    m_direct[userId].emplace(id, std::move(msg));
  }

  void add(GroupMessage msg) {
    const auto groupId = msg.getGroupId();
    const auto id = msg.getId();
    if (m_groups[groupId].contains(id))
      throw std::invalid_argument("Duplicate group message ID");
    m_groups[groupId].emplace(id, std::move(msg));
  }

  [[nodiscard]] bool containsDirect(const int32_t userId,
                                    const int32_t id) const {
    const auto uit = m_direct.find(userId);
    return uit != m_direct.end() && uit->second.contains(id);
  }

  [[nodiscard]] bool containsGroup(const int32_t groupId,
                                   const int32_t id) const {
    const auto git = m_groups.find(groupId);
    return git != m_groups.end() && git->second.contains(id);
  }

  [[nodiscard]] std::vector<Message> getByUser(const int32_t userId) const {
    const auto uit = m_direct.find(userId);
    if (uit == m_direct.end())
      return {};
    std::vector<Message> result;
    result.reserve(uit->second.size());
    for (const auto &msg : uit->second | std::views::values)
      result.push_back(msg);
    return result;
  }

  [[nodiscard]] std::vector<GroupMessage>
  getByGroup(const int32_t groupId) const {
    const auto group_it = m_groups.find(groupId);
    if (group_it == m_groups.end())
      return {};
    std::vector<GroupMessage> result;
    result.reserve(group_it->second.size());
    for (const auto &msg : group_it->second | std::views::values)
      result.push_back(msg);
    return result;
  }

  void clear() {
    m_direct.clear();
    m_groups.clear();
  }

private:
  std::unordered_map<int32_t, std::unordered_map<int32_t, Message>> m_direct;
  std::unordered_map<int32_t, std::unordered_map<int32_t, GroupMessage>>
      m_groups;
};
