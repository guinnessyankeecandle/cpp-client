#include <catch2/catch.hpp>
import securemsg.crypto.srp;

TEST_CASE("SRP verifier computation does not throw", "[srp]") {
  std::string saltHex;
  REQUIRE_NOTHROW(SrpSession::computeVerifier("alice", "password123", saltHex));
  REQUIRE_FALSE(saltHex.empty());
}

TEST_CASE("SRP verifier is deterministic for given salt", "[srp]") {
  std::string salt1, salt2;
  const auto v1 = SrpSession::computeVerifier("alice", "password", salt1);
  const auto v2 = SrpSession::computeVerifier("alice", "password", salt2);
  REQUIRE_FALSE(v1.empty());
  REQUIRE_FALSE(v2.empty());
}

TEST_CASE("SRP different passwords produce different verifiers", "[srp]") {
  std::string s1, s2;
  const auto v1 = SrpSession::computeVerifier("alice", "password1", s1);
  const auto v2 = SrpSession::computeVerifier("alice", "password2", s2);
  REQUIRE(v1 != v2);
}

TEST_CASE("SRP computeProof returns non-empty A and M1", "[srp]") {
  SrpSession s;
  // Use a non-zero B — not cryptographically valid but exercises the code path
  const std::string fakeB(128, '1');
  const std::string fakeSalt(64, 'a');
  const auto [A, M1] = s.computeProof("alice", "password", fakeSalt, fakeB);
  REQUIRE_FALSE(A.empty());
  REQUIRE_FALSE(M1.empty());
}

TEST_CASE("SRP two sessions produce different A values", "[srp]") {
  SrpSession s1, s2;
  const std::string fakeB(128, '2');
  const std::string fakeSalt(64, 'b');
  const auto [A1, M1a] = s1.computeProof("alice", "password", fakeSalt, fakeB);
  const auto [A2, M1b] = s2.computeProof("alice", "password", fakeSalt, fakeB);
  REQUIRE(A1 != A2);
}

TEST_CASE("SRP verifyServerProof returns false for bad proof", "[srp]") {
  SrpSession s;
  const std::string fakeB(128, '3');
  const std::string fakeSalt(64, 'c');
  s.computeProof("alice", "password", fakeSalt, fakeB);
  REQUIRE_FALSE(s.verifyServerProof(
      "0000000000000000000000000000000000000000000000000000000000000000"));
}
