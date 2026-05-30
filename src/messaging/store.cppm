module;
#include <algorithm>
#include <cstdint>
#include <map>
#include <ranges>
#include <stdexcept>
#include <unordered_map>
#include <variant>
#include <vector>
export module securemsg.messaging.store;
import securemsg.messaging.message;

export using AnyMessage = std::variant<Message, GroupMessage>;

using SeqKey = std::pair<uint32_t, uint32_t>; // (chainEpoch, seqInChain)

export class MessageStore {
public:
  void add(Message msg) {
    const auto userId = msg.getUserId();
    const auto id = msg.getId();
    auto &bucket = m_direct[userId];
    if (std::ranges::any_of(bucket | std::views::values,
                            [id](const auto &m) { return m.getId() == id; }))
      throw std::invalid_argument("Duplicate direct message ID");
    bucket.emplace(SeqKey{msg.getChainEpoch(), msg.getSeqInChain()},
                   std::move(msg));
  }

  void add(GroupMessage msg) {
    const auto groupId = msg.getGroupId();
    const auto id = msg.getId();
    auto &bucket = m_groups[groupId];
    if (std::ranges::any_of(bucket | std::views::values,
                            [id](const auto &m) { return m.getId() == id; }))
      throw std::invalid_argument("Duplicate group message ID");
    bucket.emplace(SeqKey{msg.getChainEpoch(), msg.getSeqInChain()},
                   std::move(msg));
  }

  [[nodiscard]] bool containsDirect(const int32_t userId,
                                    const int32_t id) const {
    const auto uit = m_direct.find(userId);
    return uit != m_direct.end() &&
           std::ranges::any_of(uit->second | std::views::values,
                               [id](const auto &m) { return m.getId() == id; });
  }

  [[nodiscard]] bool containsGroup(const int32_t groupId,
                                   const int32_t id) const {
    const auto group_it = m_groups.find(groupId);
    return group_it != m_groups.end() &&
           std::ranges::any_of(group_it->second | std::views::values,
                               [id](const auto &m) { return m.getId() == id; });
  }

  // Returns messages in sender-intended order (chainEpoch, seqInChain)
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

  // Returns messages in sender-intended order (groupEpoch, senderKeyIteration)
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
  std::unordered_map<int32_t, std::map<SeqKey, Message>> m_direct;
  std::unordered_map<int32_t, std::map<SeqKey, GroupMessage>> m_groups;
};
