#include <catch2/catch.hpp>
import securemsg.crypto.pqxdh;
import securemsg.crypto.random;
import securemsg.crypto.ed25519;
import securemsg.crypto.x25519;
import securemsg.crypto.mlkem;

// signingIk = Ed25519 (for signing SPK/PQ prekey)
// receiverIk = X25519 (for DH)
static RemoteKeyBundle
makeBundle(const RawKeyPair &receiverIk, const RawKeyPair &signingIk,
           const RawKeyPair &spk, const RawKeyPair &pqKp,
           std::optional<RawKeyPair> opk = std::nullopt) {
  RemoteKeyBundle b;
  b.ikEdPub = signingIk.pub;
  b.ikXPub = receiverIk.pub;
  b.spkPub = spk.pub;
  b.spkSig = ed25519Sign(signingIk.priv, spk.pub);
  b.pqPub = pqKp.pub;
  b.pqSig = ed25519Sign(signingIk.priv, pqKp.pub);
  if (opk)
    b.opkPub = opk->pub;
  return b;
}

TEST_CASE("PQXDH sender-receiver roundtrip produces identical SK", "[pqxdh]") {
  auto senderIk = x25519Generate();
  auto receiverIk = x25519Generate();
  auto receiverEd = ed25519Generate();
  auto receiverSpk = x25519Generate();
  auto receiverPq = mlkemGenerate();

  auto bundle = makeBundle(receiverIk, receiverEd, receiverSpk, receiverPq);
  auto senderResult = pqxdhSend(senderIk, bundle);

  PqxdhInitialHeader hdr;
  hdr.senderIkXPub = senderIk.pub;
  hdr.ephemeralPub = senderResult.ephemeralPub;
  hdr.pqCiphertext = senderResult.pqCiphertext;
  hdr.hadOpk = false;

  auto receiverSk =
      pqxdhReceive(receiverIk, receiverSpk, std::nullopt, receiverPq, hdr);
  REQUIRE(senderResult.sessionKey == receiverSk);
}

TEST_CASE("PQXDH with OPK produces identical SK", "[pqxdh]") {
  auto senderIk = x25519Generate();
  auto receiverIk = x25519Generate();
  auto receiverEd = ed25519Generate();
  auto receiverSpk = x25519Generate();
  auto receiverPq = mlkemGenerate();
  auto receiverOpk = x25519Generate();

  auto bundle =
      makeBundle(receiverIk, receiverEd, receiverSpk, receiverPq, receiverOpk);
  auto senderResult = pqxdhSend(senderIk, bundle);

  PqxdhInitialHeader hdr;
  hdr.senderIkXPub = senderIk.pub;
  hdr.ephemeralPub = senderResult.ephemeralPub;
  hdr.pqCiphertext = senderResult.pqCiphertext;
  hdr.hadOpk = true;

  auto receiverSk =
      pqxdhReceive(receiverIk, receiverSpk, receiverOpk, receiverPq, hdr);
  REQUIRE(senderResult.sessionKey == receiverSk);
}

TEST_CASE("PQXDH tampered SPK signature throws", "[pqxdh]") {
  auto senderIk = x25519Generate();
  auto receiverIk = x25519Generate();
  auto receiverEd = ed25519Generate();
  auto receiverSpk = x25519Generate();
  auto receiverPq = mlkemGenerate();

  auto bundle = makeBundle(receiverIk, receiverEd, receiverSpk, receiverPq);
  bundle.spkSig[0] ^= 0xFF;
  REQUIRE_THROWS_AS(pqxdhSend(senderIk, bundle), std::runtime_error);
}

TEST_CASE("PQXDH tampered PQ prekey signature throws", "[pqxdh]") {
  auto senderIk = x25519Generate();
  auto receiverIk = x25519Generate();
  auto receiverEd = ed25519Generate();
  auto receiverSpk = x25519Generate();
  auto receiverPq = mlkemGenerate();

  auto bundle = makeBundle(receiverIk, receiverEd, receiverSpk, receiverPq);
  bundle.pqSig[0] ^= 0xFF;
  REQUIRE_THROWS_AS(pqxdhSend(senderIk, bundle), std::runtime_error);
}

TEST_CASE("PQXDH session key is 32 bytes", "[pqxdh]") {
  auto senderIk = x25519Generate();
  auto receiverIk = x25519Generate();
  auto receiverEd = ed25519Generate();
  auto receiverSpk = x25519Generate();
  auto receiverPq = mlkemGenerate();

  auto bundle = makeBundle(receiverIk, receiverEd, receiverSpk, receiverPq);
  auto result = pqxdhSend(senderIk, bundle);
  REQUIRE(result.sessionKey.size() == 32);
}
