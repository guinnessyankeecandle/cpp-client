module;
#include <cstdint>
#include <cstring>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
export module securemsg.messaging.send_receive;
import securemsg.crypto;
import securemsg.network;
import securemsg.messaging.message;
import securemsg.messaging.store;
import securemsg.models;

export using RatchetMap = std::unordered_map<int32_t, RatchetState>;
// Keyed by groupId → per-sender ratchet: senderId → SenderKeyRatchetState
export using GroupRatchetMap =
    std::unordered_map<int32_t,
                       std::unordered_map<int32_t, SenderKeyRatchetState>>;
// Sender keys we hold for groups we're in: groupId → our own sender key bytes
export using GroupSenderKeys =
    std::unordered_map<int32_t, std::vector<uint8_t>>;

export struct SendResult {
  int32_t messageId;
};

static constexpr uint8_t PQXDH_FLAG_INITIAL = 0x01;
static constexpr uint8_t PQXDH_FLAG_REGULAR = 0x00;
static constexpr std::ptrdiff_t PQXDH_FLAG_BYTES = 1;
// 3× X25519_KEY_BYTES: senderIkXPub + ephemeralPub + opkPub
static constexpr std::ptrdiff_t PQXDH_PREFIX_BYTES =
    PQXDH_FLAG_BYTES + X25519_KEY_BYTES + X25519_KEY_BYTES +
    MLKEM1024_PUB_BYTES + X25519_KEY_BYTES;

constexpr std::size_t HEADER_BYTES_GROUP =
    X25519_KEY_BYTES + X25519_KEY_BYTES + MLKEM1024_PUB_BYTES;

static std::vector<uint8_t>
packRatchetHeader(const PqxdhSenderResult &pqxdh,
                  const std::vector<uint8_t> &senderIkXPub,
                  const std::optional<std::vector<uint8_t>> &usedOpkPub,
                  const std::vector<uint8_t> &encryptedHeader) {
  std::vector<uint8_t> out;
  out.reserve(PQXDH_PREFIX_BYTES + encryptedHeader.size());
  out.push_back(PQXDH_FLAG_INITIAL);
  out.insert(out.end(), senderIkXPub.begin(), senderIkXPub.end());
  out.insert(out.end(), pqxdh.ephemeralPub.begin(), pqxdh.ephemeralPub.end());
  out.insert(out.end(), pqxdh.pqCiphertext.begin(), pqxdh.pqCiphertext.end());
  if (usedOpkPub)
    out.insert(out.end(), usedOpkPub->begin(), usedOpkPub->end());
  else
    out.insert(out.end(), X25519_KEY_BYTES, 0x00); // Set opk to 0s
  out.insert(out.end(), encryptedHeader.begin(), encryptedHeader.end());
  return out;
}

static std::vector<uint8_t>
packRatchetHeader(const std::vector<uint8_t> &encryptedHeader) {
  std::vector<uint8_t> out;
  out.reserve(PQXDH_FLAG_BYTES + encryptedHeader.size());
  out.push_back(PQXDH_FLAG_REGULAR);
  out.insert(out.end(), encryptedHeader.begin(), encryptedHeader.end());
  return out;
}

static RemoteKeyBundle parseKeyBundle(const nlohmann::json &bundle) {
  static constexpr std::array required{"identity_pub",      "identity_x_pub",
                                       "identity_x_sig",    "signed_prekey_pub",
                                       "signed_prekey_sig", "pq_prekey_pub",
                                       "pq_prekey_sig"};
  for (const auto *field : required)
    if (!bundle.contains(field))
      throw std::runtime_error(std::string("Key bundle missing field: ") +
                               field);

  const auto ikEdPub =
      base64Decode(bundle.at("identity_pub").get<std::string>());
  const auto ikXPub =
      base64Decode(bundle.at("identity_x_pub").get<std::string>());
  const auto ikXSig =
      base64Decode(bundle.at("identity_x_sig").get<std::string>());
  const auto spkPub =
      base64Decode(bundle.at("signed_prekey_pub").get<std::string>());
  const auto spkSig =
      base64Decode(bundle.at("signed_prekey_sig").get<std::string>());
  const auto pqPub =
      base64Decode(bundle.at("pq_prekey_pub").get<std::string>());
  const auto pqSig =
      base64Decode(bundle.at("pq_prekey_sig").get<std::string>());

  std::optional<std::vector<uint8_t>> opkPub;
  if (bundle.contains("one_time_prekey") &&
      !bundle["one_time_prekey"].is_null())
    opkPub = base64Decode(bundle["one_time_prekey"].get<std::string>());

  return {ikEdPub, ikXPub, ikXSig, spkPub, spkSig, opkPub, pqPub, pqSig};
}

// Direct messaging

export SendResult sendDirectMessage(const ApiClient &api, RatchetMap &ratchets,
                                    const MessageStore &store,
                                    const std::string &accessToken,
                                    int32_t recipientId,
                                    const std::string &plaintext,
                                    const RawKeyPair &senderIkX,
                                    const std::vector<Contact> &contactCache) {

  std::optional<PqxdhSenderResult> pqxdhResult;
  std::vector<uint8_t> pqxdhSenderIkXPub;
  std::optional<std::vector<uint8_t>> pqxdhUsedOpkPub;

  if (!ratchets.contains(recipientId)) {
    const auto remote =
        parseKeyBundle(api.getKeyBundle(accessToken, recipientId));

    const auto it = std::ranges::find_if(
        contactCache, [&](const auto &c) { return c.getId() == recipientId; });
    if (it != contactCache.end() &&
        CRYPTO_memcmp(it->getIdentityPub().data(), remote.ikEdPub.data(),
                      remote.ikEdPub.size()) != 0)
      throw std::runtime_error("Identity key mismatch for user " +
                               std::to_string(recipientId));

    pqxdhUsedOpkPub = remote.opkPub;
    pqxdhSenderIkXPub = senderIkX.pub;

    pqxdhResult = pqxdhSend(senderIkX, remote);
    ratchets.emplace(recipientId, RatchetState::initSender(
                                      pqxdhResult->sessionKey, remote.spkPub));
    OPENSSL_cleanse(pqxdhResult->sessionKey.data(),
                    pqxdhResult->sessionKey.size());
  }

  auto &ratchet = ratchets.at(recipientId);
  const std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  const auto msg = ratchet.encrypt(plaintextBytes);

  const auto packedHeader =
      pqxdhResult ? packRatchetHeader(*pqxdhResult, pqxdhSenderIkXPub,
                                      pqxdhUsedOpkPub, msg.headerCiphertext)
                  : packRatchetHeader(msg.headerCiphertext);

  const auto result =
      api.sendMessage(accessToken, recipientId, base64Encode(msg.ciphertext),
                      base64Encode(packedHeader));
  if (!result.contains("id"))
    throw std::runtime_error("sendMessage: server response missing 'id'");
  const int32_t msgId = result.at("id").get<int32_t>();

  store.add(Message{msgId, recipientId, base64Encode(msg.ciphertext),
                    base64Encode(packedHeader), BaseMessage::Direction::Sent,
                    nowMs(), plaintext});
  return {msgId};
}

// ── Split fetch/process API ───────────────────────────────────────────────────
//
// Each receive operation is split into two phases so that HTTP calls (slow)
// are separate from crypto+store operations (fast).  The caller holds
// messageMutex only during the process phase, giving the render thread a
// chance to acquire the lock between groups.

// Process pre-fetched direct messages. Returns IDs to acknowledge via API.
// Caller must hold messageMutex.
export std::vector<int32_t>
processDirectMessages(const nlohmann::json &messages,
                      RatchetMap &ratchets, const MessageStore &store,
                      const RawKeyPair &myIkX, const RawKeyPair &mySpk,
                      const std::vector<RawKeyPair> &myOpks,
                      const RawKeyPair &myPq, LocalUser &localUser,
                      const std::string &passphrase) {
  std::vector<int32_t> toAck;
  if (!messages.is_array())
    return toAck;

  for (const auto &msg : messages) {
    if (!msg.contains("id") || !msg.contains("sender_id") ||
        !msg.contains("ciphertext") || !msg.contains("ratchet_header_enc"))
      throw std::runtime_error(
          "processDirectMessages: malformed message from server");

    const int32_t id = msg.at("id").get<int32_t>();
    const int32_t otherUserId = msg.at("sender_id").get<int32_t>();

    if (store.containsDirect(otherUserId, id))
      continue;

    auto rawHeader =
        base64Decode(msg.at("ratchet_header_enc").get<std::string>());
    if (rawHeader.empty())
      continue;

    const bool isInitial = rawHeader[0] == PQXDH_FLAG_INITIAL;

    if (isInitial) {
      if (rawHeader.size() < PQXDH_PREFIX_BYTES)
        continue;

      std::ptrdiff_t off = PQXDH_FLAG_BYTES;
      PqxdhInitialHeader hdr;
      hdr.senderIkXPub.assign(rawHeader.begin() + off,
                              rawHeader.begin() + off + X25519_KEY_BYTES);
      off += static_cast<std::ptrdiff_t>(X25519_KEY_BYTES);

      hdr.ephemeralPub.assign(rawHeader.begin() + off,
                              rawHeader.begin() + off + X25519_KEY_BYTES);
      off += static_cast<std::ptrdiff_t>(X25519_KEY_BYTES);

      hdr.pqCiphertext.assign(rawHeader.begin() + off,
                              rawHeader.begin() + off + MLKEM1024_PUB_BYTES);
      off += static_cast<std::ptrdiff_t>(MLKEM1024_PUB_BYTES);

      std::vector opkField(rawHeader.begin() + off,
                           rawHeader.begin() + off + X25519_KEY_BYTES);
      if (std::ranges::any_of(opkField,
                              [](const uint8_t bit) { return bit != 0; }))
        hdr.usedOpkPub = std::move(opkField);

      auto sessionKey = pqxdhReceive(myIkX, mySpk, myOpks, myPq, hdr);
      ratchets.insert_or_assign(otherUserId,
                                RatchetState::initReceiver(sessionKey, mySpk));
      OPENSSL_cleanse(sessionKey.data(), sessionKey.size());
      if (hdr.usedOpkPub)
        localUser.consumeOneTimePrekey(*hdr.usedOpkPub, passphrase);
    } else if (!ratchets.contains(otherUserId)) {
      continue;
    }

    const std::ptrdiff_t prefixLen =
        !isInitial ? PQXDH_FLAG_BYTES : PQXDH_PREFIX_BYTES;
    std::vector encHeader(rawHeader.begin() + prefixLen, rawHeader.end());

    try {
      auto &ratchet = ratchets.at(otherUserId);
      RatchetMessage rmsg{
          std::move(encHeader),
          base64Decode(msg.at("ciphertext").get<std::string>())};
      auto [plain, tsMs] = ratchet.decrypt(rmsg);
      store.add(Message{id, otherUserId,
                        msg.at("ciphertext").get<std::string>(),
                        msg.at("ratchet_header_enc").get<std::string>(),
                        BaseMessage::Direction::Received, tsMs,
                        std::string(plain.begin(), plain.end())});
      toAck.push_back(id);
    } catch (...) {
    }
  }
  return toAck;
}

// Apply pre-fetched SKDMs to group ratchets. Caller must hold messageMutex.
// Process pre-fetched group messages. Returns {groupId, msgId} pairs to ack.
// Caller must hold messageMutex.
export std::vector<std::pair<int32_t, int32_t>>
processGroupMessages(const nlohmann::json &msgs,
                     GroupRatchetMap &groupRatchets, const MessageStore &store,
                     const int32_t myUserId, const int32_t groupId) {
  std::vector<std::pair<int32_t, int32_t>> toAck;
  if (!msgs.is_array())
    return toAck;

  for (const auto &m : msgs) {
    if (!m.contains("id") || !m.contains("sender_id") ||
        !m.contains("ciphertext") || !m.contains("epoch"))
      throw std::runtime_error(
          "processGroupMessages: malformed message from server");

    const int32_t id = m.at("id").get<int32_t>();
    const int32_t senderId = m.at("sender_id").get<int32_t>();
    if (senderId == myUserId)
      continue;
    if (store.containsGroup(groupId, id))
      continue;
    if (!groupRatchets.contains(groupId) ||
        !groupRatchets.at(groupId).contains(senderId))
      continue;

    try {
      auto &ratchet = groupRatchets.at(groupId).at(senderId);
      auto wire = base64Decode(m.at("ciphertext").get<std::string>());
      auto [plain] = ratchet.decrypt(wire);
      store.add(GroupMessage{id, groupId, senderId,
                             m.at("ciphertext").get<std::string>(),
                             BaseMessage::Direction::Received, nowMs(),
                             std::string(plain.begin(), plain.end())});
      toAck.emplace_back(groupId, id);
    } catch (...) {
    }
  }
  return toAck;
}

// Legacy combined functions kept for callers that don't need the split.
export void receiveDirectMessages(const ApiClient &api, RatchetMap &ratchets,
                                  const MessageStore &store,
                                  const std::string &accessToken,
                                  const RawKeyPair &myIkX,
                                  const RawKeyPair &mySpk,
                                  const std::vector<RawKeyPair> &myOpks,
                                  const RawKeyPair &myPq, LocalUser &localUser,
                                  const std::string &passphrase) {
  const auto messages = api.listMessages(accessToken);
  const auto toAck = processDirectMessages(messages, ratchets, store,
                                           myIkX, mySpk, myOpks, myPq,
                                           localUser, passphrase);
  for (const int32_t id : toAck)
    api.acknowledgeReceipt(accessToken, id);
}

// SKDM epoch tracking

export class SkdmEpochTracker {
public:
  void recordPosted(const int32_t groupId, const int32_t currentEpoch) {
    m_postedEpoch[groupId] = currentEpoch + 1;
  }

  [[nodiscard]] int32_t resolve(const int32_t groupId,
                                const int32_t incomingEpoch) const {
    const auto it = m_postedEpoch.find(groupId);
    if (it == m_postedEpoch.end())
      return incomingEpoch;

    const int32_t myPosted = it->second;
    if (incomingEpoch >= myPosted)
      return incomingEpoch;

    return -1; // stale — our posted epoch wins
  }

  // True when the epoch change was triggered by our own postSkdm call.
  [[nodiscard]] bool weCausedEpoch(const int32_t groupId,
                                   const int32_t epoch) const {
    const auto it = m_postedEpoch.find(groupId);
    return it != m_postedEpoch.end() && epoch == it->second;
  }

private:
  std::unordered_map<int32_t, int32_t> m_postedEpoch;
};

// ── Group messaging

export std::string encryptSkdmForMember(const ApiClient &api,
                                        const std::string &accessToken,
                                        const int32_t memberId,
                                        const RawKeyPair &senderIkX,
                                        const std::vector<uint8_t> &senderKey) {

  const auto remote = parseKeyBundle(api.getKeyBundle(accessToken, memberId));
  auto pqxdhResult = pqxdhSend(senderIkX, remote);

  // Encrypt the 64-byte sender key with the derived session key
  const auto pkt = aeadEncrypt(senderKey, pqxdhResult.sessionKey);
  OPENSSL_cleanse(pqxdhResult.sessionKey.data(), pqxdhResult.sessionKey.size());
  auto packed = packAead(pkt);

  // Payload: senderEdPub(32) + ephemeralPub(32) + pqCiphertext + packed_aead
  std::vector<uint8_t> payload;
  payload.insert(payload.end(), senderIkX.pub.begin(), senderIkX.pub.end());
  payload.insert(payload.end(), pqxdhResult.ephemeralPub.begin(),
                 pqxdhResult.ephemeralPub.end());
  payload.insert(payload.end(), pqxdhResult.pqCiphertext.begin(),
                 pqxdhResult.pqCiphertext.end());
  payload.insert(payload.end(), packed.begin(), packed.end());
  return base64Encode(payload);
}

static std::vector<uint8_t>
decryptSkdmPayload(const std::vector<uint8_t> &payload, const RawKeyPair &myIkX,
                   const RawKeyPair &mySpk,
                   const std::vector<RawKeyPair> &myOpks,
                   const RawKeyPair &myPq) {

  if (payload.size() <= HEADER_BYTES_GROUP)
    throw std::runtime_error("SKDM payload too short");

  std::ptrdiff_t off = 0;
  PqxdhInitialHeader hdr;
  hdr.senderIkXPub.assign(payload.begin() + off,
                          payload.begin() + off + X25519_KEY_BYTES);
  off += static_cast<std::ptrdiff_t>(X25519_KEY_BYTES);

  hdr.ephemeralPub.assign(payload.begin() + off,
                          payload.begin() + off + X25519_KEY_BYTES);
  off += static_cast<std::ptrdiff_t>(X25519_KEY_BYTES);

  hdr.pqCiphertext.assign(payload.begin() + off,
                          payload.begin() + off + MLKEM1024_PUB_BYTES);
  off += static_cast<std::ptrdiff_t>(MLKEM1024_PUB_BYTES);

  auto sessionKey = pqxdhReceive(myIkX, mySpk, myOpks, myPq, hdr);
  const std::vector packed_cipher(payload.begin() + off, payload.end());
  auto senderKey = aeadDecrypt(unpackAead(packed_cipher), sessionKey);
  OPENSSL_cleanse(sessionKey.data(), sessionKey.size());
  return senderKey;
}

// Apply pre-fetched SKDMs to group ratchets. Caller must hold messageMutex.
export void applySkdms(const nlohmann::json &skdms,
                       const int32_t groupId,
                       const RawKeyPair &myIkX, const RawKeyPair &mySpk,
                       const std::vector<RawKeyPair> &myOpks,
                       const RawKeyPair &myPq,
                       GroupRatchetMap &groupRatchets,
                       const SkdmEpochTracker &tracker) {
  if (!skdms.is_array())
    return;

  for (const auto &entry : skdms) {
    if (!entry.contains("sender_id") || !entry.contains("epoch") ||
        !entry.contains("skdm_ciphertext"))
      continue;

    const int32_t senderId = entry.at("sender_id").get<int32_t>();
    const int32_t epoch = entry.at("epoch").get<int32_t>();

    if (tracker.resolve(groupId, epoch) < 0)
      continue;

    try {
      const auto payload =
          base64Decode(entry.at("skdm_ciphertext").get<std::string>());
      auto senderKey = decryptSkdmPayload(payload, myIkX, mySpk, myOpks, myPq);
      groupRatchets[groupId][senderId] = SenderKeyRatchetState::init(senderKey);
      OPENSSL_cleanse(senderKey.data(), senderKey.size());
    } catch (...) {
    }
  }
}

export void
postGroupSenderKey(const ApiClient &api, const std::string &accessToken,
                   const int32_t groupId, const std::vector<int32_t> &memberIds,
                   const RawKeyPair &myIkX, GroupSenderKeys &senderKeys,
                   SkdmEpochTracker &tracker) {

  const auto groupInfo = api.getGroup(accessToken, groupId);
  const int32_t epoch = groupInfo.at("epoch").get<int32_t>();

  auto senderKey = randomBytes(KEY_BYTES);
  senderKeys[groupId] = senderKey;

  std::map<int32_t, std::string> skdms;
  for (const int32_t memberId : memberIds)
    skdms[memberId] =
        encryptSkdmForMember(api, accessToken, memberId, myIkX, senderKey);
  OPENSSL_cleanse(senderKey.data(), senderKey.size());

  api.postSkdm(accessToken, groupId, skdms);
  tracker.recordPosted(groupId, epoch);
}

// Legacy combined wrappers — fetch + process in one call.
export void fetchAndApplySkdms(
    const ApiClient &api, const std::string &accessToken, const int32_t groupId,
    const RawKeyPair &myIkX, const RawKeyPair &mySpk,
    const std::vector<RawKeyPair> &myOpks, const RawKeyPair &myPq,
    GroupRatchetMap &groupRatchets, const SkdmEpochTracker &tracker) {
  const auto skdms = api.fetchSkdm(accessToken, groupId);
  applySkdms(skdms, groupId, myIkX, mySpk, myOpks, myPq, groupRatchets, tracker);
}

export void
receiveGroupMessages(const ApiClient &api, GroupRatchetMap &groupRatchets,
                     const MessageStore &store, const std::string &accessToken,
                     const int32_t groupId, const int32_t myUserId) {
  const auto msgs = api.listGroupMessages(accessToken, groupId);
  const auto toAck = processGroupMessages(msgs, groupRatchets, store,
                                          myUserId, groupId);
  for (const auto &[gid, id] : toAck)
    api.acknowledgeGroupReceipt(accessToken, gid, id);
}

export SendResult
sendGroupMessage(const ApiClient &api, const GroupSenderKeys &senderKeys,
                 GroupRatchetMap &groupRatchets, const MessageStore &store,
                 const std::string &accessToken, const int32_t groupId,
                 const int32_t myUserId, const std::string &plaintext) {

  if (!senderKeys.contains(groupId))
    throw std::runtime_error("No sender key for group " +
                             std::to_string(groupId));

  if (!groupRatchets[groupId].contains(myUserId))
    groupRatchets[groupId][myUserId] =
        SenderKeyRatchetState::init(senderKeys.at(groupId));

  auto &ratchet = groupRatchets[groupId][myUserId];
  const std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  auto encrypted_rachet = ratchet.encrypt(plaintextBytes);

  uint32_t sentIter;
  std::memcpy(&sentIter, encrypted_rachet.data(), sizeof(sentIter));

  const auto groupInfo = api.getGroup(accessToken, groupId);
  const int32_t epoch = groupInfo.at("epoch").get<int32_t>();
  const auto result = api.sendGroupMessage(accessToken, groupId, epoch,
                                           base64Encode(encrypted_rachet));
  if (!result.contains("id"))
    throw std::runtime_error("sendGroupMessage: server response missing 'id'");
  const int32_t msgId = result.at("id").get<int32_t>();
  store.add(GroupMessage{msgId, groupId, myUserId,
                         base64Encode(encrypted_rachet),
                         BaseMessage::Direction::Sent, nowMs(), plaintext});
  return {msgId};
}

