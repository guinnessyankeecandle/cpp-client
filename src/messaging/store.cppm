module;
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <stdexcept>
export module securemsg.messaging.store;
import securemsg.messaging.message;

export class MessageStore {
public:
    void add(Message msg) {
        auto id = msg.getId();
        if (auto it = m_index.find(id); it != m_index.end())
            m_messages[it->second] = std::move(msg);
        else {
            m_index[id] = m_messages.size();
            m_messages.push_back(std::move(msg));
        }
    }
    const Message& getById(int32_t id) const {
        auto it = m_index.find(id);
        if (it == m_index.end()) throw std::out_of_range("Message ID not found");
        return m_messages.at(it->second);
    }
    const std::vector<Message>& getAll() const { return m_messages; }
    bool contains(int32_t id) const { return m_index.contains(id); }
    void clear() { m_messages.clear(); m_index.clear(); }
    std::size_t size() const { return m_messages.size(); }
private:
    std::vector<Message>               m_messages;
    std::unordered_map<int32_t,size_t> m_index;
};
