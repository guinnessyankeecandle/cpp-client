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
static constexpr std::size_t HEADER_BYTES =
    static_cast<std::size_t>(X25519_KEY_BYTES) + HEADER_COUNTER_BYTES;

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
    state.m_CK = hkdf(senderKey, {}, "sender-key-chain-init", KEY_BYTES);
    return state;
  }

  // Wire format: 4-byte iteration (native byte order) || AEAD-encrypted body
  std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) {
    auto [newCk, mk] = advanceCk(m_CK);
    m_CK = std::move(newCk);

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
      auto [newCk, mk] = advanceCk(m_CK);
      m_CK = std::move(newCk);
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
    OPENSSL_cleanse(m_CK.data(), m_CK.size());
    for (auto &v : m_MKSKIPPED | std::views::values)
      OPENSSL_cleanse(v.data(), v.size());
  }

private:
  std::vector<uint8_t> m_CK;
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
  // sk is the shared session key; bobSpkPub is Bob's SPK public key.
  static RatchetState initSender(const std::vector<uint8_t> &sk,
                                 const std::vector<uint8_t> &bobSpkPub) {
    RatchetState s;
    s.m_DHs = x25519Generate();
    s.m_DHr = bobSpkPub;
    // Both parties derive the same initial header key from sk
    s.m_HK = hkdf(sk, {}, "ratchet-header-key", KEY_BYTES);
    auto [rk, cks] = kdfRk(sk, x25519DH(s.m_DHs.priv, bobSpkPub));
    s.m_RK = std::move(rk);
    s.m_CKs = std::move(cks);
    return s;
  }

  // Initialise as receiver (Bob) after PQXDH.
  static RatchetState initReceiver(const std::vector<uint8_t> &sk,
                                   const X25519KeyPair &spk) {
    RatchetState s;
    s.m_DHs = spk;
    s.m_RK = sk;
    // Same header key as sender
    s.m_HK = hkdf(sk, {}, "ratchet-header-key", KEY_BYTES);
    return s;
  }

  RatchetMessage encrypt(const std::vector<uint8_t> &plaintext) {
    auto [newCks, mk] = kdfCk(m_CKs);
    m_CKs = std::move(newCks);

    const RatchetHeader hdr{m_DHs.pub, m_PN, m_Ns};
    m_Ns++;

    const auto hdrBytes = serialiseHeader(hdr);
    const auto hdrPkt = aeadEncrypt(hdrBytes, m_HK);

    const auto bodyPkt = aeadEncrypt(plaintext, mk);
    OPENSSL_cleanse(mk.data(), mk.size());

    return {packAead(hdrPkt), packAead(bodyPkt)};
  }

  [[nodiscard]] uint32_t getEpoch() const { return m_epoch; }
  [[nodiscard]] uint32_t getNextSendSeq() const { return m_Ns; }

  struct DecryptResult {
    std::vector<uint8_t> plaintext;
    uint32_t chainEpoch; // increments on each DH ratchet step
    uint32_t seqInChain; // message number within this chain (= header.n)
  };

  DecryptResult decrypt(const RatchetMessage &msg) {
    const auto hdr = decryptHeader(msg.headerCiphertext);
    const auto pkt = unpackAead(msg.ciphertext);
    const auto msgKey = std::make_pair(hdr.dhPub, hdr.messageIndex);

    if (m_processed.contains(msgKey))
      throw std::runtime_error("Replayed message detected");

    if (const auto it = m_MKSKIPPED.find(msgKey); it != m_MKSKIPPED.end()) {
      auto mk = it->second;
      m_MKSKIPPED.erase(it);
      auto plain = aeadDecrypt(pkt, mk);
      OPENSSL_cleanse(mk.data(), mk.size());
      m_processed.insert(msgKey);
      const uint32_t epoch = m_dhPubToEpoch.contains(hdr.dhPub)
                                 ? m_dhPubToEpoch.at(hdr.dhPub)
                                 : m_epoch;
      return {std::move(plain), epoch, hdr.messageIndex};
    }

    if (hdr.dhPub != m_DHr) {
      skipMessageKeys(hdr.prevChainLen);
      dhRatchetStep(hdr.dhPub);
    }

    skipMessageKeys(hdr.messageIndex);
    auto [newCkr, mk] = kdfCk(m_CKr);
    m_CKr = std::move(newCkr);
    m_Nr++;

    auto plain = aeadDecrypt(pkt, mk);
    OPENSSL_cleanse(mk.data(), mk.size());
    m_processed.insert(msgKey);
    return {std::move(plain), m_epoch, hdr.messageIndex};
  }

private:
  X25519KeyPair m_DHs;
  std::vector<uint8_t> m_DHr;
  std::vector<uint8_t> m_RK;
  std::vector<uint8_t> m_HK; // shared header key
  std::vector<uint8_t> m_CKs;
  std::vector<uint8_t> m_CKr;
  uint32_t m_Ns{0};
  uint32_t m_Nr{0};
  uint32_t m_PN{0};
  uint32_t m_epoch{0};
  ~RatchetState() {
    for (auto &v : m_MKSKIPPED | std::views::values)
      OPENSSL_cleanse(v.data(), v.size());

    OPENSSL_cleanse(m_RK.data(), m_RK.size());
    OPENSSL_cleanse(m_HK.data(), m_HK.size());
    OPENSSL_cleanse(m_CKs.data(), m_CKs.size());
    OPENSSL_cleanse(m_CKr.data(), m_CKr.size());
  }

  std::map<std::pair<std::vector<uint8_t>, uint32_t>, std::vector<uint8_t>>
      m_MKSKIPPED;
  std::set<std::pair<std::vector<uint8_t>, uint32_t>> m_processed;
  std::map<std::vector<uint8_t>, uint32_t> m_dhPubToEpoch;

  void skipMessageKeys(uint32_t until) {
    if (m_Nr > until)
      return;
    if (until - m_Nr > RATCHET_MAX_SKIP) {
      for (auto &v : m_MKSKIPPED | std::views::values)
        OPENSSL_cleanse(v.data(), v.size());

      m_MKSKIPPED.clear();
      throw std::runtime_error("Too many skipped messages");
    }
    while (m_Nr < until) {
      auto [newCkr, mk] = kdfCk(m_CKr);
      m_MKSKIPPED[{m_DHr, m_Nr}] = mk;
      m_CKr = std::move(newCkr);
      m_Nr++;
    }
  }

  void dhRatchetStep(const std::vector<uint8_t> &newDHr) {
    m_PN = m_Ns;
    m_Ns = 0;
    m_Nr = 0;
    m_DHr = newDHr;
    m_dhPubToEpoch[newDHr] = ++m_epoch;
    auto [rk1, ckr] = kdfRk(m_RK, x25519DH(m_DHs.priv, newDHr));
    m_DHs = x25519Generate();
    auto [rk2, cks] = kdfRk(rk1, x25519DH(m_DHs.priv, newDHr));
    m_RK = std::move(rk2);
    m_CKr = std::move(ckr);
    m_CKs = std::move(cks);
    // m_HK stays fixed (derived from initial sk) for the session
  }

  static std::vector<uint8_t> serialiseHeader(const RatchetHeader &h) {
    std::vector<uint8_t> out(HEADER_BYTES);
    std::ranges::copy(h.dhPub, out.begin());
    std::memcpy(out.data() + X25519_KEY_BYTES, &h.prevChainLen,
                sizeof(uint32_t));
    std::memcpy(out.data() + X25519_KEY_BYTES + sizeof(uint32_t),
                &h.messageIndex, sizeof(uint32_t));
    return out;
  }

  RatchetHeader decryptHeader(const std::vector<uint8_t> &hdrCt) const {
    const auto pkt = unpackAead(hdrCt);
    auto bytes = aeadDecrypt(pkt, m_HK);
    if (bytes.size() < HEADER_BYTES)
      throw std::runtime_error("Header too short");
    RatchetHeader h;
    h.dhPub.assign(bytes.begin(), bytes.begin() + X25519_KEY_BYTES);
    std::memcpy(&h.prevChainLen, bytes.data() + X25519_KEY_BYTES,
                sizeof(uint32_t));
    std::memcpy(&h.messageIndex,
                bytes.data() + X25519_KEY_BYTES + sizeof(uint32_t),
                sizeof(uint32_t));
    return h;
  }
};
