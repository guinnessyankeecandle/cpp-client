module;
#include <algorithm>
#include <cstdint>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <vector>
export module securemsg.crypto.pqxdh;
import securemsg.crypto.random;
import securemsg.crypto.x25519;
import securemsg.crypto.mlkem;
import securemsg.crypto.ed25519;
import securemsg.crypto.kdf;

export struct RemoteKeyBundle {
  // Ed25519 pub — used for signature verification
  std::vector<uint8_t> ikEdPub;
  std::vector<uint8_t> ikXPub; // X25519 IK pub — used for DH2
  std::vector<uint8_t> ikXSig;
  std::vector<uint8_t> spkPub;
  std::vector<uint8_t> spkSig;
  std::optional<std::vector<uint8_t>> opkPub;
  std::vector<uint8_t> pqPub;
  std::vector<uint8_t> pqSig;
};

export struct PqxdhSenderResult {
  std::vector<uint8_t> sessionKey;
  std::vector<uint8_t> ephemeralPub;
  std::vector<uint8_t> pqCiphertext;
};

export struct PqxdhInitialHeader {
  std::vector<uint8_t>
      senderIkXPub; // sender's long-term X25519 IK pub (for DH1)
  std::vector<uint8_t> ephemeralPub;
  std::vector<uint8_t> pqCiphertext;
  std::optional<std::vector<uint8_t>> usedOpkPub; // which OPK the sender used
};

// 32 x 0xFF prefix in IKM — prevents PQXDH keys being confused with X3DH keys
static const std::vector<uint8_t> PQXDH_BINDER(32, 0xFF);

export PqxdhSenderResult pqxdhSend(const RawKeyPair &senderIkX,
                                   const RemoteKeyBundle &remote) {

  if (!ed25519Verify(remote.ikEdPub, remote.ikXPub, remote.ikXSig))
    throw std::runtime_error("PQXDH: IK_x signature invalid");
  if (!ed25519Verify(remote.ikEdPub, remote.spkPub, remote.spkSig))
    throw std::runtime_error("PQXDH: SPK signature invalid");
  if (!ed25519Verify(remote.ikEdPub, remote.pqPub, remote.pqSig))
    throw std::runtime_error("PQXDH: PQ prekey signature invalid");

  auto ek = x25519Generate();
  auto dh1 =
      x25519DH(senderIkX.priv, remote.spkPub); // sender IK_x × receiver SPK
  auto dh2 = x25519DH(ek.priv, remote.ikXPub); // sender EK × receiver IK_x
  auto dh3 = x25519DH(ek.priv, remote.spkPub); // sender EK × receiver SPK
  auto [pqCt, pqSs] = mlkemEncap(remote.pqPub);

  std::vector<uint8_t> ikm;
  ikm.insert(ikm.end(), PQXDH_BINDER.begin(), PQXDH_BINDER.end());
  ikm.insert(ikm.end(), dh1.begin(), dh1.end());
  ikm.insert(ikm.end(), dh2.begin(), dh2.end());
  ikm.insert(ikm.end(), dh3.begin(), dh3.end());
  if (remote.opkPub) {
    auto dh4 = x25519DH(ek.priv, *remote.opkPub);
    ikm.insert(ikm.end(), dh4.begin(), dh4.end());
    OPENSSL_cleanse(dh4.data(), dh4.size());
  }
  ikm.insert(ikm.end(), pqSs.begin(), pqSs.end());

  auto shared_key = hkdf(ikm, {}, "PQXDH-v1", 32);

  // clear memory
  OPENSSL_cleanse(ikm.data(), ikm.size());
  OPENSSL_cleanse(dh1.data(), dh1.size());
  OPENSSL_cleanse(dh2.data(), dh2.size());
  OPENSSL_cleanse(dh3.data(), dh3.size());
  OPENSSL_cleanse(pqSs.data(), pqSs.size());

  return {std::move(shared_key), std::move(ek.pub), std::move(pqCt)};
}

export std::vector<uint8_t>
pqxdhReceive(const RawKeyPair &receiverIkX, const RawKeyPair &receiverSpk,
             const std::vector<RawKeyPair> &receiverOpks,
             const RawKeyPair &receiverPq, const PqxdhInitialHeader &header) {

  auto dh1 = x25519DH(receiverSpk.priv,
                      header.senderIkXPub); // receiver SPK × sender IK_x
  auto dh2 = x25519DH(receiverIkX.priv,
                      header.ephemeralPub); // receiver IK_x × sender EK
  auto dh3 = x25519DH(receiverSpk.priv,
                      header.ephemeralPub); // receiver SPK × sender EK
  auto pqSs = mlkemDecap(receiverPq.priv, header.pqCiphertext);

  std::vector<uint8_t> ikm;
  ikm.insert(ikm.end(), PQXDH_BINDER.begin(), PQXDH_BINDER.end());
  ikm.insert(ikm.end(), dh1.begin(), dh1.end());
  ikm.insert(ikm.end(), dh2.begin(), dh2.end());
  ikm.insert(ikm.end(), dh3.begin(), dh3.end());
  if (header.usedOpkPub) {
    const auto it = std::ranges::find_if(receiverOpks, [&](const auto &kp) {
      return kp.pub == *header.usedOpkPub;
    });
    if (it == receiverOpks.end())
      throw std::runtime_error("PQXDH: OPK used by sender not found in bundle");
    auto dh4 = x25519DH(it->priv, header.ephemeralPub);
    ikm.insert(ikm.end(), dh4.begin(), dh4.end());
    OPENSSL_cleanse(dh4.data(), dh4.size());
  }
  ikm.insert(ikm.end(), pqSs.begin(), pqSs.end());

  auto shared_key = hkdf(ikm, {}, "PQXDH-v1", 32);

  OPENSSL_cleanse(ikm.data(), ikm.size());
  OPENSSL_cleanse(dh1.data(), dh1.size());
  OPENSSL_cleanse(dh2.data(), dh2.size());
  OPENSSL_cleanse(dh3.data(), dh3.size());
  OPENSSL_cleanse(pqSs.data(), pqSs.size());

  return shared_key;
}
