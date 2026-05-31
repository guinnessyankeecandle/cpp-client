module;
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <openssl/crypto.h>
#include <ranges>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <vector>
export module securemsg.crypto.ratchet;
import securemsg.crypto.random;
import securemsg.crypto.x25519;
import securemsg.crypto.aead;
import securemsg.crypto.kdf;

static constexpr uint32_t RATCHET_MAX_SKIP = 1000;
// header: X25519 pub + prevChainLen (4 bytes) + messageIndex (4 bytes)
static constexpr std::size_t HEADER_COUNTER_BYTES =
    sizeof(uint32_t) * 2; // prevChainLen + messageIndex
static constexpr std::size_t HEADER_BYTES = X25519_KEY_BYTES + HEADER_COUNTER_BYTES;

export struct RatchetHeader {
  std::vector<uint8_t> dhPub;
  uint32_t prevChainLen;
  uint32_t messageIndex;
};

export struct RatchetMessage {
  std::vector<uint8_t> headerCiphertext;
  std::vector<uint8_t> ciphertext;
};

static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kdfCk(const std::vector<uint8_t> &ck) {
  auto newCk = hkdf(ck, {}, "ratchet-chain-key", KEY_BYTES);
  auto mk = hkdf(ck, {}, "ratchet-message-key", KEY_BYTES);
  return {std::move(newCk), std::move(mk)};
}

static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kdfRk(const std::vector<uint8_t> &rk, const std::vector<uint8_t> &dhOut) {
  auto newRk = hkdf(dhOut, rk, "ratchet-root-key", KEY_BYTES);
  auto newCk = hkdf(dhOut, rk, "ratchet-chain-init", KEY_BYTES);
  return {std::move(newRk), std::move(newCk)};
}

// Sender Key Ratchet (group messages)
export class SenderKeyRatchetState {
public:
  static SenderKeyRatchetState init(const std::vector<uint8_t> &senderKey) {
    SenderKeyRatchetState state;
    state.m_chainKey = hkdf(senderKey, {}, "sender-key-chain-init", KEY_BYTES);
    return state;
  }

  // Wire format: 4-byte iteration (native byte order) || AEAD-encrypted body
  std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) {
    auto [newCk, mk] = advanceCk(m_chainKey);
    m_chainKey = std::move(newCk);

    std::vector<uint8_t> out(sizeof(uint32_t));
    std::memcpy(out.data(), &m_iteration, sizeof(uint32_t));
    m_iteration++;

    const auto pkt = aeadEncrypt(plaintext, mk);
    OPENSSL_cleanse(mk.data(), mk.size());
    const auto packed = packAead(pkt);
    out.insert(out.end(), packed.begin(), packed.end());
    return out;
  }

  struct DecryptResult {
    std::vector<uint8_t> plaintext;
    uint32_t iteration;
  };

  DecryptResult decrypt(const std::vector<uint8_t> &wire) {
    if (wire.size() < sizeof(uint32_t))
      throw std::runtime_error("SenderKey message too short");

    uint32_t iter{};
    std::memcpy(&iter, wire.data(), sizeof(uint32_t));
    const std::vector body(wire.begin() + sizeof(uint32_t), wire.end());

    // Deal with, out of order messages
    if (const auto it = m_MKSKIPPED.find(iter); it != m_MKSKIPPED.end()) {
      auto mk = it->second;
      m_MKSKIPPED.erase(it);
      auto plain = aeadDecrypt(unpackAead(body), mk);
      OPENSSL_cleanse(mk.data(), mk.size());
      return {std::move(plain), iter};
    }

    // Finds cases where messages were skipped and then found
    if (iter < m_iteration)
      throw std::runtime_error("SenderKey: duplicate or replayed message");

    if (iter - m_iteration > RATCHET_MAX_SKIP) {
      // Cleanse all stored skipped keys before throwing
      for (auto &v : m_MKSKIPPED | std::views::values)
        OPENSSL_cleanse(v.data(), v.size());

      m_MKSKIPPED.clear();
      throw std::runtime_error("SenderKey: too many skipped messages");
    }

    // Advance chain: store keys for skipped messages
    std::vector<uint8_t> messageMk;
    while (m_iteration <= iter) {
      auto [newCk, mk] = advanceCk(m_chainKey);
      m_chainKey = std::move(newCk);
      if (m_iteration < iter) {
        m_MKSKIPPED[m_iteration] = mk;
        OPENSSL_cleanse(mk.data(), mk.size());
      } else {
        messageMk = std::move(mk);
      }
      m_iteration++;
    }

    auto plain = aeadDecrypt(unpackAead(body), messageMk);
    OPENSSL_cleanse(messageMk.data(), messageMk.size());
    return {std::move(plain), iter};
  }

  ~SenderKeyRatchetState() {
    OPENSSL_cleanse(m_chainKey.data(), m_chainKey.size());
    for (auto &v : m_MKSKIPPED | std::views::values)
      OPENSSL_cleanse(v.data(), v.size());
  }

private:
  std::vector<uint8_t> m_chainKey;
  uint32_t m_iteration{0};
  std::unordered_map<uint32_t, std::vector<uint8_t>> m_MKSKIPPED;

  static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  advanceCk(const std::vector<uint8_t> &ck) {
    return {hkdf(ck, {}, "sender-key-chain", KEY_BYTES),
            hkdf(ck, {}, "sender-key-message", KEY_BYTES)};
  }
};

// ── Double Ratchet (direct messages) ────────────────────────────────────────

export class RatchetState {
public:
  // Initialise as sender (Alice) after PQXDH.
  static RatchetState initSender(const std::vector<uint8_t> &sk,
                                 const std::vector<uint8_t> &bobSpkPub) {
    RatchetState ratchet_state;
    ratchet_state.m_sendingKeyPair = x25519Generate();
    ratchet_state.m_remotePublicKey = bobSpkPub;
    // Both parties derive the same initial header key from sk
    ratchet_state.m_headerKey = hkdf(sk, {}, "ratchet-header-key", KEY_BYTES);
    auto [rk, cks] =
        kdfRk(sk, x25519DH(ratchet_state.m_sendingKeyPair.priv, bobSpkPub));
    ratchet_state.m_rootKey = std::move(rk);
    ratchet_state.m_sendChainKey = std::move(cks);
    return ratchet_state;
  }

  // Initialise as receiver (Bob) after PQXDH.
  static RatchetState initReceiver(const std::vector<uint8_t> &sk,
                                   const RawKeyPair &signed_pre_key) {
    RatchetState ratchet_state;
    ratchet_state.m_sendingKeyPair = signed_pre_key;
    ratchet_state.m_rootKey = sk;
    // Same header key as sender
    ratchet_state.m_headerKey = hkdf(sk, {}, "ratchet-header-key", KEY_BYTES);
    return ratchet_state;
  }

  RatchetMessage encrypt(const std::vector<uint8_t> &plaintext) {
    if (m_sendChainKey.empty())
      throw std::runtime_error(
          "Cannot encrypt before receiving a message as initialisedReceiver");
    auto [newSendChainKey, mk] = kdfCk(m_sendChainKey);
    m_sendChainKey = std::move(newSendChainKey);

    const RatchetHeader hdr{m_sendingKeyPair.pub, m_prevSendCount, m_sendCount};
    m_sendCount++;

    const auto hdrBytes = serialiseHeader(hdr);
    const auto hdrPkt = aeadEncrypt(hdrBytes, m_headerKey);

    const auto bodyPkt = aeadEncrypt(plaintext, mk);
    OPENSSL_cleanse(mk.data(), mk.size());

    return {packAead(hdrPkt), packAead(bodyPkt)};
  }

  [[nodiscard]] uint32_t getEpoch() const { return m_dhRatchetEpoch; }
  [[nodiscard]] uint32_t getNextSendSeq() const { return m_sendCount; }

  struct DecryptResult {
    std::vector<uint8_t> plaintext;
    uint32_t chainEpoch; // increments on each DH ratchet step
    uint32_t seqInChain; // message number within this chain (= header.n)
  };

  DecryptResult decrypt(const RatchetMessage &msg) {
    const auto hdr = decryptHeader(msg.headerCiphertext);
    const auto pkt = unpackAead(msg.ciphertext);
    const auto msgKey = std::make_pair(hdr.dhPub, hdr.messageIndex);

    // Reject any (dhPub, index) pair we have already successfully decrypted
    if (m_processed.contains(msgKey))
      throw std::runtime_error("Replayed message detected");

    // Out-of-order message: key was stashed when we skipped past this index
    if (const auto it = m_MKSKIPPED.find(msgKey); it != m_MKSKIPPED.end()) {
      auto mk = it->second;
      m_MKSKIPPED.erase(it);
      auto plain = aeadDecrypt(pkt, mk);
      OPENSSL_cleanse(mk.data(), mk.size());
      m_processed.insert(msgKey);
      // Recover the epoch recorded when this DH key was first seen
      if (!m_dhPubToEpoch.contains(hdr.dhPub))
        throw std::runtime_error("Skipped message has unknown DH epoch");
      const uint32_t epoch = m_dhPubToEpoch.at(hdr.dhPub);
      return {std::move(plain), epoch, hdr.messageIndex};
    }

    // New DH public key means the sender ratcheted; advance our side to match
    if (hdr.dhPub != m_remotePublicKey) {
      skipMessageKeys(hdr.prevChainLen);
      dhRatchetStep(hdr.dhPub);
    }

    skipMessageKeys(hdr.messageIndex);
    auto [newRecvChainKey, mk] = kdfCk(m_recvChainKey);
    m_recvChainKey = std::move(newRecvChainKey);
    m_recvCount++;

    auto plain = aeadDecrypt(pkt, mk);
    OPENSSL_cleanse(mk.data(), mk.size());
    m_processed.insert(msgKey);
    return {std::move(plain), m_dhRatchetEpoch, hdr.messageIndex};
  }

  ~RatchetState() {
    for (auto &v : m_MKSKIPPED | std::views::values)
      OPENSSL_cleanse(v.data(), v.size());

    OPENSSL_cleanse(m_rootKey.data(), m_rootKey.size());
    OPENSSL_cleanse(m_headerKey.data(), m_headerKey.size());
    OPENSSL_cleanse(m_sendChainKey.data(), m_sendChainKey.size());
    OPENSSL_cleanse(m_recvChainKey.data(), m_recvChainKey.size());
  }

private:
  RawKeyPair m_sendingKeyPair;
  std::vector<uint8_t> m_remotePublicKey;
  std::vector<uint8_t> m_rootKey;
  std::vector<uint8_t> m_headerKey;
  std::vector<uint8_t> m_sendChainKey;
  std::vector<uint8_t> m_recvChainKey;
  uint32_t m_sendCount{0};
  uint32_t m_recvCount{0};
  uint32_t m_prevSendCount{0};
  uint32_t m_dhRatchetEpoch{0};

  std::map<std::pair<std::vector<uint8_t>, uint32_t>, std::vector<uint8_t>>
      m_MKSKIPPED;
  std::set<std::pair<std::vector<uint8_t>, uint32_t>> m_processed;
  std::map<std::vector<uint8_t>, uint32_t> m_dhPubToEpoch;

  void skipMessageKeys(const uint32_t until) {
    if (m_recvCount >= until)
      return;

    if (until - m_recvCount > RATCHET_MAX_SKIP) {
      for (auto &v : m_MKSKIPPED | std::views::values)
        OPENSSL_cleanse(v.data(), v.size());

      m_MKSKIPPED.clear();
      throw std::runtime_error("Too many skipped messages");
    }

    while (m_recvCount < until) {
      auto [newRecvChainKey, mk] = kdfCk(m_recvChainKey);
      m_MKSKIPPED[{m_remotePublicKey, m_recvCount}] = mk;
      OPENSSL_cleanse(mk.data(), mk.size());
      m_recvChainKey = std::move(newRecvChainKey);
      m_recvCount++;
    }
  }

  void dhRatchetStep(const std::vector<uint8_t> &newRemoteKey) {
    m_prevSendCount = m_sendCount;
    m_sendCount = 0;
    m_recvCount = 0;
    m_remotePublicKey = newRemoteKey;
    m_dhPubToEpoch[newRemoteKey] = ++m_dhRatchetEpoch;
    auto [intermediateRootKey, newRecvChainKey] =
        kdfRk(m_rootKey, x25519DH(m_sendingKeyPair.priv, newRemoteKey));
    OPENSSL_cleanse(m_rootKey.data(), m_rootKey.size());
    OPENSSL_cleanse(m_sendingKeyPair.priv.data(), m_sendingKeyPair.priv.size());
    m_sendingKeyPair = x25519Generate();
    auto [newRootKey, newSendChainKey] = kdfRk(
        intermediateRootKey, x25519DH(m_sendingKeyPair.priv, newRemoteKey));
    OPENSSL_cleanse(intermediateRootKey.data(), intermediateRootKey.size());
    OPENSSL_cleanse(m_recvChainKey.data(), m_recvChainKey.size());
    OPENSSL_cleanse(m_sendChainKey.data(), m_sendChainKey.size());
    m_rootKey = std::move(newRootKey);
    m_recvChainKey = std::move(newRecvChainKey);
    m_sendChainKey = std::move(newSendChainKey);
    // m_headerKey stays fixed (derived from initial sk) for the session

    // Evict replay-detection entries from epochs before the current one;
    // their DH keys are gone so replay is impossible without them.
    std::erase_if(m_processed, [this](const auto &entry) {
      const auto it = m_dhPubToEpoch.find(entry.first);
      return it == m_dhPubToEpoch.end() || it->second < m_dhRatchetEpoch;
    });
  }

  static std::vector<uint8_t> serialiseHeader(const RatchetHeader &hdr) {
    std::vector<uint8_t> out(HEADER_BYTES);
    std::ranges::copy(hdr.dhPub, out.begin());
    std::memcpy(out.data() + X25519_KEY_BYTES, &hdr.prevChainLen,
                sizeof(uint32_t));
    std::memcpy(out.data() + X25519_KEY_BYTES + sizeof(uint32_t),
                &hdr.messageIndex, sizeof(uint32_t));
    return out;
  }

  RatchetHeader decryptHeader(const std::vector<uint8_t> &hdrCt) const {
    const auto pkt = unpackAead(hdrCt);
    auto bytes = aeadDecrypt(pkt, m_headerKey);

    if (bytes.size() < HEADER_BYTES)
      throw std::runtime_error("Header too short");

    RatchetHeader hdr;
    hdr.dhPub.assign(bytes.begin(), bytes.begin() + X25519_KEY_BYTES);

    std::memcpy(&hdr.prevChainLen, bytes.data() + X25519_KEY_BYTES,
                sizeof(uint32_t));
    std::memcpy(&hdr.messageIndex,
                bytes.data() + X25519_KEY_BYTES + sizeof(uint32_t),
                sizeof(uint32_t));
    return hdr;
  }
};
