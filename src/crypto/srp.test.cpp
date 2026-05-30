#include <catch2/catch.hpp>
import securemsg.crypto.srp;

TEST_CASE("SRP verifier computation does not throw", "[srp]") {
  std::string saltHex;
  REQUIRE_NOTHROW(srpComputeVerifier("alice", "password123", saltHex));
  REQUIRE_FALSE(saltHex.empty());
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
