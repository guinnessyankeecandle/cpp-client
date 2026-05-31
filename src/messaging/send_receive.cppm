module;
#include <cstdint>
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

// Direct messaging

export SendResult
sendDirectMessage(ApiClient &api, RatchetMap &ratchets, MessageStore &store,
                  const std::string &accessToken, int32_t recipientId,
                  const std::string &plaintext, const RawKeyPair &senderIk,
                  const std::vector<Contact> &contactCache) {

  if (!ratchets.contains(recipientId)) {
    auto bundle = api.getKeyBundle(accessToken, recipientId);

    auto ikEdPub = base64Decode(bundle.at("identity_pub").get<std::string>());
    auto ikXPub = base64Decode(bundle.at("identity_x_pub").get<std::string>());
    auto spkPub =
        base64Decode(bundle.at("signed_prekey_pub").get<std::string>());
    auto spkSig =
        base64Decode(bundle.at("signed_prekey_sig").get<std::string>());
    auto pqPub = base64Decode(bundle.at("pq_prekey_pub").get<std::string>());
    auto pqSig = base64Decode(bundle.at("pq_prekey_sig").get<std::string>());

    std::optional<std::vector<uint8_t>> opkPub;
    if (bundle.contains("one_time_prekey") &&
        !bundle["one_time_prekey"].is_null())
      opkPub = base64Decode(bundle["one_time_prekey"].get<std::string>());

    if (const auto it = std::ranges::find_if(
            contactCache,
            [&](const auto &c) { return c.getId() == recipientId; });
        it != contactCache.end()) {
      if (CRYPTO_memcmp(it->getIdentityPub().data(), ikEdPub.data(),
                        ikEdPub.size()) != 0)
        throw std::runtime_error("Identity key mismatch for user " +
                                 std::to_string(recipientId));
    }

    RemoteKeyBundle remote{ikEdPub, ikXPub, spkPub, spkSig,
                           opkPub,  pqPub,  pqSig};
    auto pqxdhResult = pqxdhSend(senderIk, remote);
    ratchets.emplace(recipientId,
                     RatchetState::initSender(pqxdhResult.sessionKey, spkPub));
  }

  auto &ratchet = ratchets.at(recipientId);
  const uint32_t sendEpoch = ratchet.getEpoch();
  const uint32_t sendSeq = ratchet.getNextSendSeq();
  std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  auto msg = ratchet.encrypt(plaintextBytes);

  const auto result =
      api.sendMessage(accessToken, recipientId, base64Encode(msg.ciphertext),
                      base64Encode(msg.headerCiphertext));
  const int32_t msgId = result.value("id", 0);
  Message sent{msgId,
               recipientId,
               base64Encode(msg.ciphertext),
               base64Encode(msg.headerCiphertext),
               BaseMessage::Direction::Sent,
               sendEpoch,
               sendSeq};
  sent.setPlaintext(plaintext);
  store.add(std::move(sent));
  return {msgId};
}

export void receiveDirectMessages(
    ApiClient &api, RatchetMap &ratchets, MessageStore &store,
    const std::string &accessToken, int32_t myUserId,
    const RawKeyPair & /*mySpk*/, const std::optional<RawKeyPair> &myOpk,
    const RawKeyPair &myPq, std::vector<Contact> & /*contactCache*/,
    const ApiClient &apiForLookup) {

  auto messages = api.listMessages(accessToken);
  if (!messages.is_array())
    return;

  (void)myUserId;
  (void)myOpk;
  (void)myPq;
  (void)apiForLookup;

  for (const auto &m : messages) {
    const int32_t id = m.value("id", 0);
    const int32_t otherUserId = m.value("sender_id", 0);
    if (store.containsDirect(otherUserId, id))
      continue;
    if (!ratchets.contains(otherUserId))
      continue;

    try {
      auto &ratchet = ratchets.at(otherUserId);
      RatchetMessage rmsg{base64Decode(m.value("ratchet_header_enc", "")),
                          base64Decode(m.value("ciphertext", ""))};
      auto [plain, epoch, seq] = ratchet.decrypt(rmsg);
      Message msg{id,
                  otherUserId,
                  m.value("ciphertext", ""),
                  m.value("ratchet_header_enc", ""),
                  BaseMessage::Direction::Received,
                  epoch,
                  seq};
      msg.setPlaintext(std::string(plain.begin(), plain.end()));
      store.add(std::move(msg));
    } catch (...) {
    }
  }
}

// ── Group messaging
// ───────────────────────────────────────────────────────────

// Distribute our sender key to a new group member via X3DH-style encryption.
// Returns the base64-encoded SKDM payload for that member.
export std::string encryptSkdmForMember(ApiClient &api,
                                        const std::string &accessToken,
                                        int32_t memberId,
                                        const RawKeyPair &senderIk,
                                        const std::vector<uint8_t> &senderKey) {
  auto bundle = api.getKeyBundle(accessToken, memberId);
  auto ikEdPub = base64Decode(bundle.at("identity_pub").get<std::string>());
  auto ikXPub = base64Decode(bundle.at("identity_x_pub").get<std::string>());
  auto spkPub = base64Decode(bundle.at("signed_prekey_pub").get<std::string>());
  auto spkSig = base64Decode(bundle.at("signed_prekey_sig").get<std::string>());
  auto pqPub = base64Decode(bundle.at("pq_prekey_pub").get<std::string>());
  auto pqSig = base64Decode(bundle.at("pq_prekey_sig").get<std::string>());
  std::optional<std::vector<uint8_t>> opkPub;
  if (bundle.contains("one_time_prekey") &&
      !bundle["one_time_prekey"].is_null())
    opkPub = base64Decode(bundle["one_time_prekey"].get<std::string>());

  RemoteKeyBundle remote{ikEdPub, ikXPub, spkPub, spkSig, opkPub, pqPub, pqSig};
  auto pqxdhResult = pqxdhSend(senderIk, remote);

  // Encrypt the 64-byte sender key with the derived session key
  auto pkt = aeadEncrypt(senderKey, pqxdhResult.sessionKey);
  auto packed = packAead(pkt);

  // Payload: senderEdPub(32) + ephemeralPub(32) + pqCiphertext + packed_aead
  std::vector<uint8_t> payload;
  payload.insert(payload.end(), senderIk.pub.begin(), senderIk.pub.end());
  payload.insert(payload.end(), pqxdhResult.ephemeralPub.begin(),
                 pqxdhResult.ephemeralPub.end());
  payload.insert(payload.end(), pqxdhResult.pqCiphertext.begin(),
                 pqxdhResult.pqCiphertext.end());
  payload.insert(payload.end(), packed.begin(), packed.end());
  return base64Encode(payload);
}

export SendResult
sendGroupMessage(ApiClient &api, const GroupSenderKeys &senderKeys,
                 GroupRatchetMap &groupRatchets, MessageStore &store,
                 const std::string &accessToken, int32_t groupId,
                 int32_t myUserId, const std::string &plaintext) {
  if (!senderKeys.contains(groupId))
    throw std::runtime_error("No sender key for group " +
                             std::to_string(groupId));

  auto &ratchet = groupRatchets[groupId][myUserId];
  if (groupRatchets[groupId].empty() ||
      !groupRatchets[groupId].contains(myUserId))
    ratchet = SenderKeyRatchetState::init(senderKeys.at(groupId));

  const std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  auto wire = ratchet.encrypt(plaintextBytes);
  const uint32_t sentIter = (uint32_t(wire[0]) << 24) |
                            (uint32_t(wire[1]) << 16) |
                            (uint32_t(wire[2]) << 8) | uint32_t(wire[3]);

  const auto groupInfo = api.getGroup(accessToken, groupId);
  const int32_t epoch = groupInfo.value("epoch", 0);
  const auto result =
      api.sendGroupMessage(accessToken, groupId, epoch, base64Encode(wire));
  const int32_t msgId = result.value("id", 0);
  GroupMessage sent{msgId,
                    groupId,
                    epoch,
                    myUserId,
                    base64Encode(wire),
                    BaseMessage::Direction::Sent,
                    sentIter};
  sent.setPlaintext(plaintext);
  store.add(std::move(sent));
  return {msgId};
}

export void receiveGroupMessages(ApiClient &api, GroupRatchetMap &groupRatchets,
                                 MessageStore &store,
                                 const std::string &accessToken,
                                 int32_t groupId, int32_t myUserId) {
  auto msgs = api.listGroupMessages(accessToken, groupId);
  if (!msgs.is_array())
    return;

  for (const auto &m : msgs) {
    const int32_t id = m.value("id", 0);
    const int32_t senderId = m.value("sender_id", 0);
    if (senderId == myUserId)
      continue; // don't store messages we sent
    if (store.containsGroup(groupId, id))
      continue;
    if (!groupRatchets.contains(groupId) ||
        !groupRatchets.at(groupId).contains(senderId))
      continue; // no ratchet for this sender yet

    try {
      auto &ratchet = groupRatchets.at(groupId).at(senderId);
      auto wire = base64Decode(m.value("ciphertext", ""));
      auto [plain, iter] = ratchet.decrypt(wire);
      GroupMessage msg{id,
                       groupId,
                       m.value("epoch", 0),
                       senderId,
                       m.value("ciphertext", ""),
                       BaseMessage::Direction::Received,
                       iter};
      msg.setPlaintext(std::string(plain.begin(), plain.end()));
      store.add(std::move(msg));
    } catch (...) {
    }
  }
}

// ── SKDM epoch tracking
// ───────────────────────────────────────────────────────

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
    if (incomingEpoch > myPosted)
      return incomingEpoch;
    if (incomingEpoch == myPosted)
      return myPosted;
    return -1;
  }

  [[nodiscard]] bool hasPosted(const int32_t groupId) const {
    return m_postedEpoch.contains(groupId);
  }

private:
  std::unordered_map<int32_t, int32_t> m_postedEpoch;
};
