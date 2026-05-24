#include "MessageStore.hpp"
#include <algorithm>
#include <stdexcept>

void MessageStore::addMessage(Message msg) {
    int id = msg.getId();
    if (m_indexById.count(id)) return;   // already present, skip
    m_indexById[id] = m_messages.size();
    m_messages.push_back(std::move(msg));
}

void MessageStore::removeById(int id) {
    auto it = m_indexById.find(id);
    if (it == m_indexById.end()) return;

    std::size_t idx = it->second;
    m_messages.erase(m_messages.begin() + static_cast<std::ptrdiff_t>(idx));
    m_indexById.erase(it);

    // Shift all indices that were above the removed element.
    for (auto& [key, pos] : m_indexById) {
        if (pos > idx) --pos;
    }
}

std::optional<Message> MessageStore::findById(int id) const {
    auto it = m_indexById.find(id);
    if (it == m_indexById.end()) return std::nullopt;
    return m_messages[it->second];
}

std::vector<Message> MessageStore::getSent() const {
    std::vector<Message> result;
    std::copy_if(m_messages.begin(), m_messages.end(), std::back_inserter(result),
                 [](const Message& m) { return m.getDirection() == Message::Direction::Sent; });
    return result;
}

std::vector<Message> MessageStore::getReceived() const {
    std::vector<Message> result;
    std::copy_if(m_messages.begin(), m_messages.end(), std::back_inserter(result),
                 [](const Message& m) { return m.getDirection() == Message::Direction::Received; });
    return result;
}

std::vector<Message> MessageStore::getAll() const { return m_messages; }

std::size_t MessageStore::size()  const { return m_messages.size(); }
void        MessageStore::clear()       { m_messages.clear(); m_indexById.clear(); }
