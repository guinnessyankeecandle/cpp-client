module;
#include <cstdint>
#include <string>
export module securemsg.messaging.message;

export class BaseMessage {
public:
  enum class Direction { Sent, Received };

  BaseMessage(const int32_t id, const int32_t userId, std::string ciphertext,
              const Direction dir)
      : m_id(id), m_userId(userId), m_ciphertext(std::move(ciphertext)),
        m_direction(dir) {}

  [[nodiscard]] int32_t getId() const { return m_id; }
  [[nodiscard]] int32_t getUserId() const { return m_userId; }
  [[nodiscard]] const std::string &getCiphertext() const {
    return m_ciphertext;
  }
  [[nodiscard]] Direction getDirection() const { return m_direction; }
  [[nodiscard]] const std::string &getPlaintext() const { return m_plaintext; } // Get a read only plaintext
  void setPlaintext(std::string p) { m_plaintext = std::move(p); }

private:
  int32_t m_id, m_userId;
  std::string m_ciphertext, m_plaintext;
  Direction m_direction;
};

export class Message : public BaseMessage {
public:
  Message(const int32_t id, const int32_t otherUserId, std::string ciphertext,
          std::string ratchetHeaderEnc, const Direction dir)
      : BaseMessage(id, otherUserId, std::move(ciphertext), dir),
        m_ratchetHeaderEnc(std::move(ratchetHeaderEnc)) {}

  [[nodiscard]] const std::string &getRatchetHeaderEnc() const {
    return m_ratchetHeaderEnc;
  }

private:
  std::string m_ratchetHeaderEnc;
};

export class GroupMessage : public BaseMessage {
public:
  GroupMessage(const int32_t id, const int32_t groupId, const int32_t epoch,
               const int32_t senderId, std::string ciphertext)
      : BaseMessage(id, senderId, std::move(ciphertext), Direction::Received),
        m_groupId(groupId), m_epoch(epoch) {}

  [[nodiscard]] int32_t getGroupId() const { return m_groupId; }
  [[nodiscard]] int32_t getEpoch() const { return m_epoch; }

private:
  int32_t m_groupId, m_epoch;
};
