module;
#include <cstdint>
#include <map>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.ratchet;
import securemsg.crypto.random;
import securemsg.crypto.x25519;
import securemsg.crypto.aead;
import securemsg.crypto.kdf;

export struct RatchetHeader {
  std::vector<uint8_t> dhPub;
  uint32_t pn{0};
  uint32_t n{0};
};

export struct RatchetMessage {
  std::vector<uint8_t> headerCiphertext;
  std::vector<uint8_t> ciphertext;
};

static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kdfCk(const std::vector<uint8_t> &ck) {
  auto newCk = hkdf(ck, {}, "ratchet-chain-key", 32);
  auto mk = hkdf(ck, {}, "ratchet-message-key", 32);
  return {std::move(newCk), std::move(mk)};
}

static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kdfRk(const std::vector<uint8_t> &rk, const std::vector<uint8_t> &dhOut) {
  auto newRk = hkdf(dhOut, rk, "ratchet-root-key", 32);
  auto newCk = hkdf(dhOut, rk, "ratchet-chain-init", 32);
  return {std::move(newRk), std::move(newCk)};
}

export class RatchetState {
public:
  static constexpr uint32_t MAX_SKIP = 1000;

  // Initialise as sender (Alice) after PQXDH.
  // sk is the shared session key; bobSpkPub is Bob's SPK public key.
  static RatchetState initSender(const std::vector<uint8_t> &sk,
                                 const std::vector<uint8_t> &bobSpkPub) {
    RatchetState s;
    s.m_DHs = x25519Generate();
    s.m_DHr = bobSpkPub;
    // Both parties derive the same initial header key from sk
    s.m_HK = hkdf(sk, {}, "ratchet-header-key", 32);
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
    s.m_HK = hkdf(sk, {}, "ratchet-header-key", 32);
    return s;
  }

  RatchetMessage encrypt(const std::vector<uint8_t> &plaintext) {
    auto [newCks, mk] = kdfCk(m_CKs);
    m_CKs = std::move(newCks);

    RatchetHeader hdr{m_DHs.pub, m_PN, m_Ns};
    m_Ns++;

    auto hdrBytes = serialiseHeader(hdr);
    auto hdrPkt = aeadEncrypt(hdrBytes, m_HK);

    auto bodyPkt = aeadEncrypt(plaintext, mk);
    OPENSSL_cleanse(mk.data(), mk.size());

    return {packAead(hdrPkt), packAead(bodyPkt)};
  }

  std::vector<uint8_t> decrypt(const RatchetMessage &msg) {
    auto hdr = decryptHeader(msg.headerCiphertext);
    auto pkt = unpackAead(msg.ciphertext);

    auto skippedKey = std::make_pair(hdr.dhPub, hdr.n);
    if (auto it = m_MKSKIPPED.find(skippedKey); it != m_MKSKIPPED.end()) {
      auto mk = it->second;
      m_MKSKIPPED.erase(it);
      auto plain = aeadDecrypt(pkt, mk);
      OPENSSL_cleanse(mk.data(), mk.size());
      return plain;
    }

    if (hdr.dhPub != m_DHr) {
      skipMessageKeys(hdr.pn);
      dhRatchetStep(hdr.dhPub);
    }

    skipMessageKeys(hdr.n);
    auto [newCkr, mk] = kdfCk(m_CKr);
    m_CKr = std::move(newCkr);
    m_Nr++;

    auto plain = aeadDecrypt(pkt, mk);
    OPENSSL_cleanse(mk.data(), mk.size());
    return plain;
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
  std::map<std::pair<std::vector<uint8_t>, uint32_t>, std::vector<uint8_t>>
      m_MKSKIPPED;

  void skipMessageKeys(uint32_t until) {
    if (m_Nr > until)
      return;
    if (until - m_Nr > MAX_SKIP)
      throw std::runtime_error("Too many skipped messages");
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
    auto [rk1, ckr] = kdfRk(m_RK, x25519DH(m_DHs.priv, newDHr));
    m_DHs = x25519Generate();
    auto [rk2, cks] = kdfRk(rk1, x25519DH(m_DHs.priv, newDHr));
    m_RK = std::move(rk2);
    m_CKr = std::move(ckr);
    m_CKs = std::move(cks);
    // m_HK stays fixed (derived from initial sk) for the session
  }

  static std::vector<uint8_t> serialiseHeader(const RatchetHeader &h) {
    std::vector<uint8_t> out;
    out.insert(out.end(), h.dhPub.begin(), h.dhPub.end());
    for (int i = 3; i >= 0; --i)
      out.push_back((h.pn >> (i * 8)) & 0xFF);
    for (int i = 3; i >= 0; --i)
      out.push_back((h.n >> (i * 8)) & 0xFF);
    return out;
  }

  RatchetHeader decryptHeader(const std::vector<uint8_t> &hdrCt) const {
    auto pkt = unpackAead(hdrCt);
    auto bytes = aeadDecrypt(pkt, m_HK);
    if (bytes.size() < 40)
      throw std::runtime_error("Header too short");
    RatchetHeader h;
    h.dhPub.assign(bytes.begin(), bytes.begin() + 32);
    h.pn = (uint32_t(bytes[32]) << 24) | (uint32_t(bytes[33]) << 16) |
           (uint32_t(bytes[34]) << 8) | uint32_t(bytes[35]);
    h.n = (uint32_t(bytes[36]) << 24) | (uint32_t(bytes[37]) << 16) |
          (uint32_t(bytes[38]) << 8) | uint32_t(bytes[39]);
    return h;
  }
};
