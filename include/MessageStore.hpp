#pragma once
#include "Message.hpp"
#include <vector>
#include <unordered_map>
#include <optional>

class MessageStore {
public:
    void                   addMessage(Message msg);
    void                   removeById(int id);
    std::vector<Message>   getSent()     const;
    std::vector<Message>   getReceived() const;
    std::vector<Message>   getAll()      const;
    std::optional<Message> findById(int id) const;
    std::size_t            size()  const;
    void                   clear();

private:
    std::vector<Message>              m_messages;
    std::unordered_map<int, std::size_t> m_indexById;
};
