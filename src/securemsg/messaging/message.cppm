module;
#include <string>
#include <cstdint>
export module securemsg.messaging.message;

export class Message {
public:
    enum class Direction { Sent, Received };

    Message() = default;
    Message(int32_t id, int32_t senderId, int32_t recipientId,
            std::string ciphertext, std::string ratchetHeaderEnc,
            int64_t sentAt, Direction dir)
        : m_id(id), m_senderId(senderId), m_recipientId(recipientId)
        , m_ciphertext(std::move(ciphertext))
        , m_ratchetHeaderEnc(std::move(ratchetHeaderEnc))
        , m_sentAt(sentAt), m_direction(dir) {}

    int32_t            getId()               const { return m_id; }
    int32_t            getSenderId()         const { return m_senderId; }
    int32_t            getRecipientId()      const { return m_recipientId; }
    const std::string& getCiphertext()       const { return m_ciphertext; }
    const std::string& getRatchetHeaderEnc() const { return m_ratchetHeaderEnc; }
    int64_t            getSentAt()           const { return m_sentAt; }
    Direction          getDirection()        const { return m_direction; }
    const std::string& getPlaintext()        const { return m_plaintext; }
    void setPlaintext(std::string p) { m_plaintext = std::move(p); }

private:
    int32_t     m_id{0}, m_senderId{0}, m_recipientId{0};
    std::string m_ciphertext, m_ratchetHeaderEnc, m_plaintext;
    int64_t     m_sentAt{0};
    Direction   m_direction{Direction::Received};
};

export class GroupMessage {
public:
    GroupMessage() = default;
    GroupMessage(int32_t id, int32_t groupId, int32_t epoch,
                 std::string ciphertext, int64_t sentAt)
        : m_id(id), m_groupId(groupId), m_epoch(epoch)
        , m_ciphertext(std::move(ciphertext)), m_sentAt(sentAt) {}

    int32_t            getId()         const { return m_id; }
    int32_t            getGroupId()    const { return m_groupId; }
    int32_t            getEpoch()      const { return m_epoch; }
    const std::string& getCiphertext() const { return m_ciphertext; }
    int64_t            getSentAt()     const { return m_sentAt; }
    const std::string& getPlaintext()  const { return m_plaintext; }
    void setPlaintext(std::string p) { m_plaintext = std::move(p); }

private:
    int32_t     m_id{0}, m_groupId{0}, m_epoch{0};
    std::string m_ciphertext, m_plaintext;
    int64_t     m_sentAt{0};
};
