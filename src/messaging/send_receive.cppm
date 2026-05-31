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

static constexpr uint8_t PQXDH_FLAG_INITIAL = 0x01;
static constexpr uint8_t PQXDH_FLAG_REGULAR = 0x00;
static constexpr std::ptrdiff_t PQXDH_FLAG_BYTES = 1;
// 3× X25519_KEY_BYTES: senderIkXPub + ephemeralPub + opkPub
static constexpr std::ptrdiff_t PQXDH_PREFIX_BYTES =
    PQXDH_FLAG_BYTES + X25519_KEY_BYTES + X25519_KEY_BYTES +
    MLKEM1024_PUB_BYTES + X25519_KEY_BYTES;

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

// Direct messaging

export SendResult sendDirectMessage(const ApiClient &api, RatchetMap &ratchets,
                                    MessageStore &store,
                                    const std::string &accessToken,
                                    int32_t recipientId,
                                    const std::string &plaintext,
                                    const RawKeyPair &senderIk,
                                    const std::vector<Contact> &contactCache) {

  std::optional<PqxdhSenderResult> pqxdhResult;
  std::vector<uint8_t> pqxdhSenderIkXPub;
  std::optional<std::vector<uint8_t>> pqxdhUsedOpkPub;

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

    const auto it = std::ranges::find_if(
        contactCache, [&](const auto &c) { return c.getId() == recipientId; });
    if (it != contactCache.end() &&
        CRYPTO_memcmp(it->getIdentityPub().data(), ikEdPub.data(),
                      ikEdPub.size()) != 0)
      throw std::runtime_error("Identity key mismatch for user " +
                               std::to_string(recipientId));

    pqxdhUsedOpkPub = opkPub;
    pqxdhSenderIkXPub = senderIk.pub;
    RemoteKeyBundle remote{ikEdPub, ikXPub, spkPub, spkSig,
                           opkPub,  pqPub,  pqSig};

    pqxdhResult = pqxdhSend(senderIk, remote);
    ratchets.emplace(recipientId,
                     RatchetState::initSender(pqxdhResult->sessionKey, spkPub));
    OPENSSL_cleanse(pqxdhResult->sessionKey.data(),
                    pqxdhResult->sessionKey.size());
  }

  auto &ratchet = ratchets.at(recipientId);
  const uint32_t sendEpoch = ratchet.getEpoch();
  const uint32_t sendSeq = ratchet.getNextSendSeq();
  const std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  auto msg = ratchet.encrypt(plaintextBytes);

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
                    sendEpoch, sendSeq, plaintext});
  return {msgId};
}

export void receiveDirectMessages(const ApiClient &api, RatchetMap &ratchets,
                                  MessageStore &store,
                                  const std::string &accessToken,
                                  const RawKeyPair &myIk,
                                  const RawKeyPair &mySpk,
                                  const std::vector<RawKeyPair> &myOpks,
                                  const RawKeyPair &myPq) {
  auto messages = api.listMessages(accessToken);
  if (!messages.is_array())
    return;

  for (const auto &msg : messages) {
    if (!msg.contains("id") || !msg.contains("sender_id") ||
        !msg.contains("ciphertext") || !msg.contains("ratchet_header_enc"))
      throw std::runtime_error(
          "receiveDirectMessages: malformed message from server");

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

      auto sessionKey = pqxdhReceive(myIk, mySpk, myOpks, myPq, hdr);
      ratchets.insert_or_assign(otherUserId,
                                RatchetState::initReceiver(sessionKey, mySpk));
      OPENSSL_cleanse(sessionKey.data(), sessionKey.size());
    } else if (!ratchets.contains(otherUserId)) {
      continue;
    }

    // Strip the flag byte (and PQXDH prefix if initial) to get the encrypted
    // header
    const std::ptrdiff_t prefixLen =
        !isInitial ? PQXDH_FLAG_BYTES : PQXDH_PREFIX_BYTES;
    std::vector encHeader(rawHeader.begin() + prefixLen, rawHeader.end());

    try {
      auto &ratchet = ratchets.at(otherUserId);
      RatchetMessage rmsg{
          std::move(encHeader),
          base64Decode(msg.at("ciphertext").get<std::string>())};
      auto [plain, epoch, seq] = ratchet.decrypt(rmsg);

      store.add(Message{id, otherUserId,
                        msg.at("ciphertext").get<std::string>(),
                        msg.at("ratchet_header_enc").get<std::string>(),
                        BaseMessage::Direction::Received, epoch, seq,
                        std::string(plain.begin(), plain.end())});
    } catch (...) {
    }
  }
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

private:
  std::unordered_map<int32_t, int32_t> m_postedEpoch;
};

// ── Group messaging

// Distribute our sender key to a new group member via X3DH-style encryption.
// Returns the base64-encoded SKDM payload for that member.
export std::string encryptSkdmForMember(const ApiClient &api,
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

// Decrypts an SKDM payload produced by encryptSkdmForMember.
// Payload: senderIkXPub(32) + ephemeralPub(32) + pqCiphertext(1568) +
// packed_aead
static std::vector<uint8_t>
decryptSkdmPayload(const std::vector<uint8_t> &payload, const RawKeyPair &myIk,
                   const RawKeyPair &mySpk,
                   const std::vector<RawKeyPair> &myOpks,
                   const RawKeyPair &myPq) {
  constexpr std::size_t HEADER_BYTES =
      X25519_KEY_BYTES + X25519_KEY_BYTES + MLKEM1024_PUB_BYTES;
  if (payload.size() <= HEADER_BYTES)
    throw std::runtime_error("SKDM payload too short");

  auto off = static_cast<std::ptrdiff_t>(0);
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

  auto sessionKey = pqxdhReceive(myIk, mySpk, myOpks, myPq, hdr);
  const std::vector<uint8_t> packed(payload.begin() + off, payload.end());
  auto senderKey = aeadDecrypt(unpackAead(packed), sessionKey);
  OPENSSL_cleanse(sessionKey.data(), sessionKey.size());
  return senderKey;
}

// Generate a new sender key for a group, encrypt it for all members, post it,
// and record the epoch in the tracker.
export void
postGroupSenderKey(const ApiClient &api, const std::string &accessToken,
                   const int32_t groupId, const std::vector<int32_t> &memberIds,
                   const RawKeyPair &myIk, GroupSenderKeys &senderKeys,
                   SkdmEpochTracker &tracker) {
  const auto groupInfo = api.getGroup(accessToken, groupId);
  const int32_t epoch = groupInfo.value("epoch", 0);

  auto senderKey = randomBytes(KEY_BYTES);
  senderKeys[groupId] = senderKey;

  std::map<int32_t, std::string> skdms;
  for (const int32_t memberId : memberIds)
    skdms[memberId] =
        encryptSkdmForMember(api, accessToken, memberId, myIk, senderKey);
  OPENSSL_cleanse(senderKey.data(), senderKey.size());

  api.postSkdm(accessToken, groupId, skdms);
  tracker.recordPosted(groupId, epoch);
}

// Fetch SKDMs for a group, resolve epoch conflicts, and init sender key
// ratchets.
export void fetchAndApplySkdms(const ApiClient &api,
                               const std::string &accessToken, int32_t groupId,
                               const RawKeyPair &myIk, const RawKeyPair &mySpk,
                               const std::vector<RawKeyPair> &myOpks,
                               const RawKeyPair &myPq,
                               GroupRatchetMap &groupRatchets,
                               const SkdmEpochTracker &tracker) {
  const auto skdms = api.fetchSkdm(accessToken, groupId);
  if (!skdms.is_array())
    return;

  for (const auto &entry : skdms) {
    if (!entry.contains("sender_id") || !entry.contains("epoch") ||
        !entry.contains("skdm_ciphertext"))
      continue;

    const int32_t senderId = entry.at("sender_id").get<int32_t>();
    const int32_t epoch = entry.at("epoch").get<int32_t>();

    if (tracker.resolve(groupId, epoch) < 0)
      continue; // stale — our posted epoch wins

    try {
      const auto payload =
          base64Decode(entry.at("skdm_ciphertext").get<std::string>());
      auto senderKey = decryptSkdmPayload(payload, myIk, mySpk, myOpks, myPq);
      groupRatchets[groupId][senderId] = SenderKeyRatchetState::init(senderKey);
      OPENSSL_cleanse(senderKey.data(), senderKey.size());
    } catch (...) {
    }
  }
}

export SendResult
sendGroupMessage(const ApiClient &api, const GroupSenderKeys &senderKeys,
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
  const uint32_t sentIter = (static_cast<uint32_t>(wire[0]) << 24) |
                            (static_cast<uint32_t>(wire[1]) << 16) |
                            (static_cast<uint32_t>(wire[2]) << 8) |
                            static_cast<uint32_t>(wire[3]);

  const auto groupInfo = api.getGroup(accessToken, groupId);
  const int32_t epoch = groupInfo.value("epoch", 0);
  const auto result =
      api.sendGroupMessage(accessToken, groupId, epoch, base64Encode(wire));
  if (!result.contains("id"))
    throw std::runtime_error("sendGroupMessage: server response missing 'id'");
  const int32_t msgId = result.at("id").get<int32_t>();
  store.add(GroupMessage{msgId, groupId, epoch, myUserId, base64Encode(wire),
                         BaseMessage::Direction::Sent, sentIter, plaintext});
  return {msgId};
}

export void receiveGroupMessages(const ApiClient &api,
                                 GroupRatchetMap &groupRatchets,
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
      store.add(GroupMessage{id, groupId, m.value("epoch", 0), senderId,
                             m.value("ciphertext", ""),
                             BaseMessage::Direction::Received, iter,
                             std::string(plain.begin(), plain.end())});
    } catch (...) {
    }
  }
}
