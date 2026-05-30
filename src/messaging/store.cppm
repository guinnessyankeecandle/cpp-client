module;
#include <cstdint>
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
    const auto id = msg.getId();
    if (auto it = m_index.find(id); it != m_index.end())
      m_messages[it->second] = std::move(msg);
    else {
      m_index[id] = m_messages.size();
      m_messages.emplace_back(std::move(msg));
    }
  }

  void add(GroupMessage msg) {
    const auto id = msg.getId();
    if (auto it = m_index.find(id); it != m_index.end())
      m_messages[it->second] = std::move(msg);
    else {
      m_index[id] = m_messages.size();
      m_messages.emplace_back(std::move(msg));
    }
  }

  [[nodiscard]] const AnyMessage &getById(const int32_t id) const {
    const auto it = m_index.find(id);
    if (it == m_index.end())
      throw std::out_of_range("Message ID not found");
    return m_messages.at(it->second);
  }

  [[nodiscard]] const std::vector<AnyMessage> &getAll() const {
    return m_messages;
  }

  [[nodiscard]] bool contains(const int32_t id) const {
    return m_index.contains(id);
  }

  void clear() {
    m_messages.clear();
    m_index.clear();
  }

  [[nodiscard]] std::size_t size() const { return m_messages.size(); }

private:
  std::vector<AnyMessage> m_messages;
  std::unordered_map<int32_t, std::size_t> m_index;
};
