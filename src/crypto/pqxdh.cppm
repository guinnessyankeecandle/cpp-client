module;
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
  std::vector<uint8_t>
      ikEdPub; // Ed25519 pub — used for SPK/PQ signature verification
  std::vector<uint8_t> ikXPub; // X25519 pub — used for DH2
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
  std::vector<uint8_t> senderIkXPub; // sender's X25519 IK pub (for DH1)
  std::vector<uint8_t> ephemeralPub;
  std::vector<uint8_t> pqCiphertext;
  bool hadOpk{false};
};

static const std::vector<uint8_t> PQXDH_BINDER(32, 0xFF);

export PqxdhSenderResult pqxdhSend(const X25519KeyPair &senderIk,
                                   const RemoteKeyBundle &remote) {
  if (!ed25519Verify(remote.ikEdPub, remote.spkPub, remote.spkSig))
    throw std::runtime_error("PQXDH: SPK signature invalid");
  if (!ed25519Verify(remote.ikEdPub, remote.pqPub, remote.pqSig))
    throw std::runtime_error("PQXDH: PQ prekey signature invalid");

  auto ek = x25519Generate();
  auto dh1 = x25519DH(senderIk.priv, remote.spkPub); // sender IK × receiver SPK
  auto dh2 =
      x25519DH(ek.priv, remote.ikXPub); // sender EK × receiver IK (X25519)
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

  auto sk = hkdf(ikm, {}, "PQXDH-v1", 32);

  OPENSSL_cleanse(ikm.data(), ikm.size());
  OPENSSL_cleanse(dh1.data(), dh1.size());
  OPENSSL_cleanse(dh2.data(), dh2.size());
  OPENSSL_cleanse(dh3.data(), dh3.size());
  OPENSSL_cleanse(pqSs.data(), pqSs.size());

  return {std::move(sk), std::move(ek.pub), std::move(pqCt)};
}

export std::vector<uint8_t>
pqxdhReceive(const X25519KeyPair &receiverIk, const X25519KeyPair &receiverSpk,
             const std::optional<X25519KeyPair> &receiverOpk,
             const MlKemKeyPair &receiverPq, const PqxdhInitialHeader &header) {

  auto dh1 = x25519DH(receiverSpk.priv,
                      header.senderIkXPub); // receiver SPK × sender IK
  auto dh2 =
      x25519DH(receiverIk.priv, header.ephemeralPub); // receiver IK × sender EK
  auto dh3 = x25519DH(receiverSpk.priv,
                      header.ephemeralPub); // receiver SPK × sender EK
  auto pqSs = mlkemDecap(receiverPq.priv, header.pqCiphertext);

  std::vector<uint8_t> ikm;
  ikm.insert(ikm.end(), PQXDH_BINDER.begin(), PQXDH_BINDER.end());
  ikm.insert(ikm.end(), dh1.begin(), dh1.end());
  ikm.insert(ikm.end(), dh2.begin(), dh2.end());
  ikm.insert(ikm.end(), dh3.begin(), dh3.end());
  if (receiverOpk && header.hadOpk) {
    auto dh4 = x25519DH(receiverOpk->priv, header.ephemeralPub);
    ikm.insert(ikm.end(), dh4.begin(), dh4.end());
    OPENSSL_cleanse(dh4.data(), dh4.size());
  }
  ikm.insert(ikm.end(), pqSs.begin(), pqSs.end());

  auto sk = hkdf(ikm, {}, "PQXDH-v1", 32);

  OPENSSL_cleanse(ikm.data(), ikm.size());
  OPENSSL_cleanse(dh1.data(), dh1.size());
  OPENSSL_cleanse(dh2.data(), dh2.size());
  OPENSSL_cleanse(dh3.data(), dh3.size());
  OPENSSL_cleanse(pqSs.data(), pqSs.size());

  return sk;
}
