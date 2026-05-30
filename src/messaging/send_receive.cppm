module;
#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
export module securemsg.messaging.send_receive;
import securemsg.crypto.random;
import securemsg.crypto.aead;
import securemsg.crypto.kdf;
import securemsg.crypto.ed25519;
import securemsg.crypto.x25519;
import securemsg.crypto.mlkem;
import securemsg.crypto.pqxdh;
import securemsg.crypto.ratchet;
import securemsg.crypto.keystore;
import securemsg.crypto.srp;
import securemsg.network.api;
import securemsg.messaging.message;
import securemsg.messaging.store;
import securemsg.models.user;

export using RatchetMap = std::unordered_map<int32_t, RatchetState>;

export struct SendResult {
  int32_t messageId{0};
};

export SendResult
sendDirectMessage(ApiClient &api, RatchetMap &ratchets,
                  const std::string &accessToken, int32_t recipientId,
                  const std::string &plaintext, const X25519KeyPair &senderIk,
                  const std::unordered_map<int32_t, Identity> &identityCache) {

  if (!ratchets.contains(recipientId)) {
    auto bundle = api.getKeyBundle(accessToken, recipientId);

    auto ikEdPub = base64Decode(bundle.value("identity_pub", ""));
    auto ikXPub = base64Decode(bundle.value("identity_x_pub", ""));
    auto spkPub = base64Decode(bundle.value("signed_prekey_pub", ""));
    auto spkSig = base64Decode(bundle.value("signed_prekey_sig", ""));
    auto pqPub = base64Decode(bundle.value("pq_prekey_pub", ""));
    auto pqSig = base64Decode(bundle.value("pq_prekey_sig", ""));

    std::optional<std::vector<uint8_t>> opkPub;
    if (!bundle.value("one_time_prekey", "").empty())
      opkPub = base64Decode(bundle["one_time_prekey"].get<std::string>());

    if (auto it = identityCache.find(recipientId); it != identityCache.end()) {
      if (CRYPTO_memcmp(it->second.identityPub.data(), ikEdPub.data(),
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
  std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
  auto msg = ratchet.encrypt(plaintextBytes);

  auto result =
      api.sendMessage(accessToken, recipientId, base64Encode(msg.ciphertext),
                      base64Encode(msg.headerCiphertext));
  return {result.value("id", 0)};
}

export void
receiveDirectMessages(ApiClient &api, RatchetMap &ratchets, MessageStore &store,
                      const std::string &accessToken, int32_t myUserId,
                      const X25519KeyPair &mySpk,
                      const std::optional<X25519KeyPair> &myOpk,
                      const MlKemKeyPair &myPq,
                      std::unordered_map<int32_t, Identity> &identityCache,
                      ApiClient &apiForLookup) {

  auto messages = api.listMessages(accessToken);
  if (!messages.is_array())
    return;

  for (const auto &m : messages) {
    int32_t id = m.value("id", 0);
    int32_t senderId = m.value("sender_id", 0);
    if (store.contains(id))
      continue;

    auto ct = base64Decode(m.value("ciphertext", ""));
    auto hdrCt = base64Decode(m.value("ratchet_header_enc", ""));
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();

    (void)myUserId;
    (void)myOpk;
    (void)myPq;
    (void)apiForLookup;

    if (!ratchets.contains(senderId))
      continue; // skip if no session yet

    try {
      auto &ratchet = ratchets.at(senderId);
      RatchetMessage rmsg{hdrCt, ct};
      auto plain = ratchet.decrypt(rmsg);

      Message msg{id,
                  senderId,
                  myUserId,
                  m.value("ciphertext", ""),
                  m.value("ratchet_header_enc", ""),
                  now,
                  Message::Direction::Received};
      msg.setPlaintext(std::string(plain.begin(), plain.end()));
      store.add(std::move(msg));
    } catch (...) {
    }
  }
}

export struct SenderKey {
  std::vector<uint8_t> chainKey;
  int32_t epoch{0};
};

export class SkdmEpochTracker {
public:
  void recordPosted(int32_t groupId, int32_t currentEpoch) {
    m_postedEpoch[groupId] = currentEpoch + 1;
  }

  int32_t resolve(int32_t groupId, int32_t incomingEpoch) const {
    auto it = m_postedEpoch.find(groupId);
    if (it == m_postedEpoch.end())
      return incomingEpoch;
    int32_t myPosted = it->second;
    if (incomingEpoch > myPosted)
      return incomingEpoch;
    if (incomingEpoch == myPosted)
      return myPosted;
    return -1;
  }

  bool hasPosted(int32_t groupId) const {
    return m_postedEpoch.contains(groupId);
  }

private:
  std::unordered_map<int32_t, int32_t> m_postedEpoch;
};
