module;
#include <cstdint>
#include <string>
export module securemsg.messaging.message;

export class BaseMessage {
public:
  enum class Direction { Sent, Received };

  BaseMessage(const int32_t id, const int32_t userId, std::string ciphertext,
              const Direction dir, const uint64_t timestampMs,
              std::string plaintext)
      : m_id(id), m_userId(userId), m_ciphertext(std::move(ciphertext)),
        m_plaintext(std::move(plaintext)), m_direction(dir),
        m_timestampMs(timestampMs) {}

  [[nodiscard]] int32_t getId() const { return m_id; }
  [[nodiscard]] int32_t getUserId() const { return m_userId; }
  [[nodiscard]] const std::string &getCiphertext() const {
    return m_ciphertext;
  }
  [[nodiscard]] Direction getDirection() const { return m_direction; }
  [[nodiscard]] uint64_t getTimestampMs() const { return m_timestampMs; }
  [[nodiscard]] const std::string &getPlaintext() const { return m_plaintext; }

private:
  int32_t m_id, m_userId;
  std::string m_ciphertext, m_plaintext;
  Direction m_direction;
  uint64_t m_timestampMs;
};

export class Message : public BaseMessage {
public:
  Message(const int32_t id, const int32_t otherUserId, std::string ciphertext,
          std::string ratchetHeaderEnc, const Direction dir,
          const uint64_t timestampMs, std::string plaintext)
      : BaseMessage(id, otherUserId, std::move(ciphertext), dir, timestampMs,
                    std::move(plaintext)),
        m_ratchetHeaderEnc(std::move(ratchetHeaderEnc)) {}

  [[nodiscard]] const std::string &getRatchetHeaderEnc() const {
    return m_ratchetHeaderEnc;
  }

private:
  std::string m_ratchetHeaderEnc;
};

export class GroupMessage : public BaseMessage {
public:
  GroupMessage(const int32_t id, const int32_t groupId, const int32_t senderId,
               std::string ciphertext, const Direction dir,
               const uint64_t timestampMs, std::string plaintext)
      : BaseMessage(id, senderId, std::move(ciphertext), dir, timestampMs,
                    std::move(plaintext)),
        m_groupId(groupId) {}

  [[nodiscard]] int32_t getGroupId() const { return m_groupId; }

private:
  int32_t m_groupId;
};
