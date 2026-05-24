#include "Message.hpp"

Message::Message(int id, int senderId, int recipientId,
                 std::string ciphertext, std::string headerEnc,
                 int64_t sentAt, Direction dir)
    : m_id(id)
    , m_senderId(senderId)
    , m_recipientId(recipientId)
    , m_ciphertext(std::move(ciphertext))
    , m_headerEnc(std::move(headerEnc))
    , m_sentAt(sentAt)
    , m_direction(dir)
{}

int                Message::getId()              const { return m_id; }
int                Message::getSenderId()        const { return m_senderId; }
int                Message::getRecipientId()     const { return m_recipientId; }
const std::string& Message::getCiphertext()      const { return m_ciphertext; }
const std::string& Message::getHeaderEnc()       const { return m_headerEnc; }
int64_t            Message::getSentAt()          const { return m_sentAt; }
Message::Direction Message::getDirection()       const { return m_direction; }
const std::string& Message::getPlaintext()       const { return m_plaintext; }
const std::string& Message::getRevocationToken() const { return m_revocationToken; }

void Message::setPlaintext(std::string plaintext)         { m_plaintext = std::move(plaintext); }
void Message::setRevocationToken(std::string token)       { m_revocationToken = std::move(token); }
