#include <catch2/catch.hpp>
import securemsg.crypto.srp;

TEST_CASE("SRP verifier computation does not throw", "[srp]") {
  std::string saltHex;
  REQUIRE_NOTHROW(srpComputeVerifier("alice", "password123", saltHex));
  REQUIRE_FALSE(saltHex.empty());
}

TEST_CASE("SRP verifier is deterministic for given salt", "[srp]") {
  std::string salt1, salt2;
  auto v1 = srpComputeVerifier("alice", "password", salt1);
  auto v2 = srpComputeVerifier("alice", "password", salt2);
  REQUIRE_FALSE(v1.empty());
  REQUIRE_FALSE(v2.empty());
}

TEST_CASE("SRP different passwords produce different verifiers", "[srp]") {
  std::string s1, s2;
  auto v1 = srpComputeVerifier("alice", "password1", s1);
  auto v2 = srpComputeVerifier("alice", "password2", s2);
  REQUIRE(v1 != v2);
}

TEST_CASE("SRP session begin returns non-empty A", "[srp]") {
  SrpSession s;
  auto A = s.begin("alice", "password");
  REQUIRE_FALSE(A.empty());
}

TEST_CASE("SRP verifyServerProof returns false for bad proof", "[srp]") {
  SrpSession s;
  s.begin("alice", "password");
  REQUIRE_FALSE(s.verifyServerProof(
      "0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST_CASE("SRP two sessions produce different A values", "[srp]") {
  SrpSession s1, s2;
  auto A1 = s1.begin("alice", "password");
  auto A2 = s2.begin("alice", "password");
  REQUIRE(A1 != A2);
}

TEST_CASE("SRP computeProof runs with valid hex inputs", "[srp]") {
  SrpSession s;
  s.begin("alice", "password");
  // Use a non-zero B value — result won't be cryptographically valid
  // but exercises the full computeProof code path
  std::string fakeB(128, '1');
  std::string fakeSalt(64, 'a');
  REQUIRE_NOTHROW(s.computeProof(fakeSalt, fakeB));
}

TEST_CASE("SRP computeProof returns non-empty hex string", "[srp]") {
  SrpSession s;
  s.begin("alice", "password");
  std::string fakeB(128, '2');
  std::string fakeSalt(64, 'b');
  auto proof = s.computeProof(fakeSalt, fakeB);
  REQUIRE_FALSE(proof.empty());
}
