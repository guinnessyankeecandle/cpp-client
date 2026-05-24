#pragma once
#include <string>
#include <cstdint>

class Message {
public:
    enum class Direction { Sent, Received };

    Message() = default;
    Message(int id, int senderId, int recipientId,
            std::string ciphertext, std::string headerEnc,
            int64_t sentAt, Direction dir);

    int                getId()             const;
    int                getSenderId()       const;
    int                getRecipientId()    const;
    const std::string& getCiphertext()     const;
    const std::string& getHeaderEnc()      const;
    int64_t            getSentAt()         const;
    Direction          getDirection()      const;
    const std::string& getPlaintext()      const;
    const std::string& getRevocationToken() const;

    void setPlaintext(std::string plaintext);
    void setRevocationToken(std::string token);

private:
    int         m_id{0};
    int         m_senderId{0};
    int         m_recipientId{0};
    std::string m_ciphertext;
    std::string m_headerEnc;     // ephemeral public key (base64)
    int64_t     m_sentAt{0};
    Direction   m_direction{Direction::Received};
    std::string m_plaintext;
    std::string m_revocationToken;
};
