module;
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <sqlite_orm/sqlite_orm.h>
export module securemsg.messaging.store;
import securemsg.messaging.message;
import securemsg.crypto.aead;
import securemsg.crypto.random;

using namespace sqlite_orm;


struct DirectRow {
  int id{};
  int userId{};
  std::string ciphertext;
  std::string headerEnc;
  int direction{};
  int64_t timestampMs{};
  std::vector<char> plaintextEnc;
};

struct GroupRow {
  int id{};
  int groupId{};
  int senderId{};
  std::string ciphertext;
  int direction{};
  int64_t timestampMs{};
  std::vector<char> plaintextEnc;
};

static auto makeStorage(const std::string &path) {
  return make_storage(
      path,
      make_index("idx_dm_user", &DirectRow::userId, &DirectRow::timestampMs,
                 &DirectRow::id),
      make_table("direct_messages",
                 make_column("id", &DirectRow::id, primary_key()),
                 make_column("user_id", &DirectRow::userId),
                 make_column("ciphertext", &DirectRow::ciphertext),
                 make_column("header_enc", &DirectRow::headerEnc),
                 make_column("direction", &DirectRow::direction),
                 make_column("timestamp_ms", &DirectRow::timestampMs),
                 make_column("plaintext_enc", &DirectRow::plaintextEnc)),
      make_index("idx_gm_group", &GroupRow::groupId, &GroupRow::timestampMs,
                 &GroupRow::id),
      make_table("group_messages",
                 make_column("id", &GroupRow::id, primary_key()),
                 make_column("group_id", &GroupRow::groupId),
                 make_column("sender_id", &GroupRow::senderId),
                 make_column("ciphertext", &GroupRow::ciphertext),
                 make_column("direction", &GroupRow::direction),
                 make_column("timestamp_ms", &GroupRow::timestampMs),
                 make_column("plaintext_enc", &GroupRow::plaintextEnc)));
}

using Storage = decltype(makeStorage(""));

static constexpr int PAGE_SIZE = 100;

// ── MessageStore ─────────────────────────────────────────────────────────────

export class MessageStore {
public:
  MessageStore(const std::string &path, std::vector<uint8_t> encKey)
      : m_storage(std::make_unique<Storage>(makeStorage(path))),
        m_encKey(std::move(encKey)) {
    m_storage->pragma.journal_mode(journal_mode::WAL);
    m_storage->sync_schema();
  }

  void add(const Message &msg) const {
    if (!containsDirect(msg.getUserId(), msg.getId()))
      m_storage->replace(toRow(msg));
  }

  void add(const GroupMessage &msg) const {
    if (!containsGroup(msg.getGroupId(), msg.getId()))
      m_storage->replace(toRow(msg));
  }

  [[nodiscard]] bool containsDirect(const int32_t userId,
                                    const int32_t id) const {
    return m_storage->count<DirectRow>(
               where(c(&DirectRow::id) == id and
                     c(&DirectRow::userId) == userId)) > 0;
  }

  [[nodiscard]] bool containsGroup(const int32_t groupId,
                                   const int32_t id) const {
    return m_storage->count<GroupRow>(
               where(c(&GroupRow::id) == id and
                     c(&GroupRow::groupId) == groupId)) > 0;
  }

  // Returns PAGE_SIZE messages ending at offset (0 = most recent page)
  [[nodiscard]] std::vector<Message> getByUser(const int32_t userId,
                                               const int pageOffset = 0) const {
    auto rows = m_storage->get_all<DirectRow>(
        where(c(&DirectRow::userId) == userId),
        multi_order_by(order_by(&DirectRow::timestampMs).desc(),
                       order_by(&DirectRow::id).desc()),
        limit(pageOffset * PAGE_SIZE, PAGE_SIZE));
    std::ranges::reverse(rows);
    std::vector<Message> result;
    result.reserve(rows.size());
    for (const auto &r : rows)
      result.push_back(fromRow(r));
    return result;
  }

  // Returns PAGE_SIZE messages ending at offset (0 = most recent page)
  [[nodiscard]] std::vector<GroupMessage>
  getByGroup(const int32_t groupId, const int pageOffset = 0) const {
    auto rows = m_storage->get_all<GroupRow>(
        where(c(&GroupRow::groupId) == groupId),
        multi_order_by(order_by(&GroupRow::timestampMs).desc(),
                       order_by(&GroupRow::id).desc()),
        limit(pageOffset * PAGE_SIZE, PAGE_SIZE));
    std::ranges::reverse(rows);
    std::vector<GroupMessage> result;
    result.reserve(rows.size());
    for (const auto &r : rows)
      result.push_back(fromRow(r));
    return result;
  }

  void removeDirectMessage(const int32_t userId, const int32_t id) const {
    m_storage->remove_all<DirectRow>(
        where(c(&DirectRow::id) == id and c(&DirectRow::userId) == userId));
  }

  void removeGroupMessage(const int32_t groupId, const int32_t id) const {
    m_storage->remove_all<GroupRow>(
        where(c(&GroupRow::id) == id and c(&GroupRow::groupId) == groupId));
  }

  void clear() const {
    m_storage->remove_all<DirectRow>();
    m_storage->remove_all<GroupRow>();
  }

private:
  std::unique_ptr<Storage> m_storage;
  std::vector<uint8_t> m_encKey;

  [[nodiscard]] std::vector<char>
  encryptPlaintext(const std::string &plain) const {
    if (m_encKey.empty())
      return {plain.begin(), plain.end()};
    const std::vector<uint8_t> bytes(plain.begin(), plain.end());
    const auto enc = packAead(aeadEncrypt(bytes, m_encKey));
    return {enc.begin(), enc.end()};
  }

  [[nodiscard]] std::string
  decryptPlaintext(const std::vector<char> &blob) const {
    if (m_encKey.empty())
      return {blob.begin(), blob.end()};
    try {
      const std::vector<uint8_t> bytes(blob.begin(), blob.end());
      const auto plain = aeadDecrypt(unpackAead(bytes), m_encKey);
      return {plain.begin(), plain.end()};
    } catch (...) {
      return "[encrypted with different key]";
    }
  }

  [[nodiscard]] DirectRow toRow(const Message &m) const {
    return {m.getId(),
            m.getUserId(),
            m.getCiphertext(),
            m.getRatchetHeaderEnc(),
            m.getDirection() == BaseMessage::Direction::Sent ? 0 : 1,
            static_cast<int64_t>(m.getTimestampMs()),
            encryptPlaintext(m.getPlaintext())};
  }

  [[nodiscard]] Message fromRow(const DirectRow &r) const {
    const auto dir = r.direction == 0 ? BaseMessage::Direction::Sent
                                      : BaseMessage::Direction::Received;
    return {r.id,     r.userId, r.ciphertext, r.headerEnc,
            dir,      static_cast<uint64_t>(r.timestampMs),
            decryptPlaintext(r.plaintextEnc)};
  }

  [[nodiscard]] GroupRow toRow(const GroupMessage &m) const {
    return {m.getId(),
            m.getGroupId(),
            m.getUserId(),
            m.getCiphertext(),
            m.getDirection() == BaseMessage::Direction::Sent ? 0 : 1,
            static_cast<int64_t>(m.getTimestampMs()),
            encryptPlaintext(m.getPlaintext())};
  }

  [[nodiscard]] GroupMessage fromRow(const GroupRow &r) const {
    const auto dir = r.direction == 0 ? BaseMessage::Direction::Sent
                                      : BaseMessage::Direction::Received;
    return {r.id,  r.groupId, r.senderId, r.ciphertext,
            dir,   static_cast<uint64_t>(r.timestampMs),
            decryptPlaintext(r.plaintextEnc)};
  }
};
