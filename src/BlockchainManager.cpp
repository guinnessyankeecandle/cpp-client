#include "BlockchainManager.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <array>
#include <fstream>
#include <cstdio>
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <ctime>

// ── Keccak-256 ────────────────────────────────────────────────────────────────
//
// This is the original Keccak-256 used by Ethereum.  It differs from NIST
// SHA3-256 only in the padding byte: Keccak uses 0x01; SHA3 uses 0x06.
// OpenSSL's EVP_sha3_256() applies the NIST padding and therefore cannot be
// used here.

namespace {

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for Rho step (indexed by [x][y]).
static const int KECCAK_ROT[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

static inline uint64_t rol64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccakF1600(uint64_t A[25]) {
    for (int round = 0; round < 24; ++round) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x+4)%5] ^ rol64(C[(x+1)%5], 1);
        for (int i = 0; i < 25; ++i)
            A[i] ^= D[i % 5];

        // Rho + Pi
        uint64_t B[25];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                B[y*5 + (2*x+3*y)%5] = rol64(A[x + y*5], KECCAK_ROT[x][y]);

        // Chi
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                A[x + y*5] = B[x + y*5] ^ ((~B[(x+1)%5 + y*5]) & B[(x+2)%5 + y*5]);

        // Iota
        A[0] ^= KECCAK_RC[round];
    }
}

} // anonymous namespace

std::vector<uint8_t> BlockchainManager::keccak256(const std::vector<uint8_t>& data) {
    constexpr int RATE = 136; // (1600 - 2*256) / 8 bytes

    // Pad: append 0x01, then zeros, then set high bit of last byte.
    std::vector<uint8_t> padded = data;
    padded.push_back(0x01);
    while (static_cast<int>(padded.size()) % RATE != 0)
        padded.push_back(0x00);
    padded.back() |= 0x80;

    uint64_t state[25] = {};

    // Absorb
    for (std::size_t i = 0; i < padded.size(); i += RATE) {
        for (int j = 0; j < RATE / 8; ++j) {
            uint64_t word = 0;
            for (int k = 0; k < 8; ++k)
                word |= static_cast<uint64_t>(padded[i + j*8 + k]) << (k * 8);
            state[j] ^= word;
        }
        keccakF1600(state);
    }

    // Squeeze first 32 bytes
    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 8; ++k)
            hash[i*8 + k] = static_cast<uint8_t>((state[i] >> (k * 8)) & 0xFF);

    return hash;
}

std::vector<uint8_t> BlockchainManager::keccak256(const std::string& utf8) {
    return keccak256(std::vector<uint8_t>(utf8.begin(), utf8.end()));
}

// ── Envelope canonicalisation ─────────────────────────────────────────────────
//
// Rule (from blockchain design doc):
//   Sort keys alphabetically, no whitespace, IDs as strings, sent_at as number.

std::string BlockchainManager::canonicalise(const MessageEnvelope& env) {
    // 8-field alphabetical order matching digestUtils.js DIRECT_ENVELOPE_FIELDS.
    // IDs are stored as strings; schema_version and message_type are hardcoded.
    nlohmann::ordered_json oj;
    oj["ciphertext"]         = env.ciphertext;
    oj["conversation_id"]    = env.conversationId;
    oj["message_id"]         = env.messageId;
    oj["message_type"]       = env.messageType.empty() ? "direct" : env.messageType;
    oj["ratchet_header_enc"] = env.ratchetHeaderEnc;
    oj["recipient_id"]       = env.recipientId;
    oj["schema_version"]     = env.schemaVersion.empty() ? "securemsg-envelope-v1" : env.schemaVersion;
    oj["sender_id"]          = env.senderId;
    return oj.dump();
}

std::vector<uint8_t> BlockchainManager::leafHash(const MessageEnvelope& env) {
    return keccak256(canonicalise(env));
}

// ── Hex utilities ─────────────────────────────────────────────────────────────

std::string BlockchainManager::toHex0x(const std::vector<uint8_t>& data) {
    std::ostringstream ss;
    ss << "0x";
    for (uint8_t b : data)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::vector<uint8_t> BlockchainManager::fromHex0x(const std::string& hex) {
    std::string h = hex;
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        h = h.substr(2);
    if (h.size() % 2 != 0) throw std::invalid_argument("Odd-length hex string");
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

// ── Segment hash ──────────────────────────────────────────────────────────────
// keccak256(utf8("SecureMsgSegmentDigest:v1") || hash1_bytes || hash2_bytes || ...)

std::vector<uint8_t> BlockchainManager::segmentHash(const std::vector<std::vector<uint8_t>>& leafHashes) {
    if (leafHashes.empty()) throw std::invalid_argument("No leaf hashes");
    static const std::string DOMAIN = "SecureMsgSegmentDigest:v1";
    std::vector<uint8_t> data(DOMAIN.begin(), DOMAIN.end());
    for (const auto& h : leafHashes) {
        if (h.size() != 32) throw std::invalid_argument("Leaf hash must be 32 bytes");
        data.insert(data.end(), h.begin(), h.end());
    }
    return keccak256(data);
}

// ── Segment digest builder ────────────────────────────────────────────────────

SegmentDigest BlockchainManager::buildSegmentDigest(const std::vector<MessageEnvelope>& envs,
                                                     const std::string& conversationId,
                                                     int segmentIndex,
                                                     const std::string& senderPublicKeyB64)
{
    if (envs.empty()) throw std::invalid_argument("No envelopes");

    std::vector<std::vector<uint8_t>> leaves;
    for (const auto& env : envs)
        leaves.push_back(leafHash(env));

    auto seg = segmentHash(leaves);

    SegmentDigest d;
    d.segmentHash     = toHex0x(seg);
    d.conversationId  = conversationId;
    d.segmentId       = conversationId + "-seg-" + std::to_string(segmentIndex);
    d.senderPublicKey = senderPublicKeyB64;
    d.messageCount    = static_cast<int>(envs.size());
    for (const auto& h : leaves)
        d.envelopeHashes.push_back(toHex0x(h));
    return d;
}

// ── Segment file (for blockchain recording page) ──────────────────────────────
// Format matches what Waleed's verification page expects:
// { "sender_public_key": "...", "messages": [{ "index": 1, "ciphertext": "..." }, ...] }

std::string BlockchainManager::writeSegmentFile(const std::vector<MessageEnvelope>& envs,
                                                  const SegmentDigest& digest)
{
    nlohmann::json messages = nlohmann::json::array();
    for (int i = 0; i < static_cast<int>(envs.size()); ++i) {
        nlohmann::json m;
        m["index"]      = i + 1;
        m["ciphertext"] = envs[static_cast<std::size_t>(i)].ciphertext;
        messages.push_back(m);
    }

    nlohmann::json doc;
    doc["sender_public_key"] = digest.senderPublicKey;
    doc["messages"]          = messages;

    std::string path = digest.segmentId + ".json";
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write segment file: " + path);
    f << doc.dump(2);
    return path;
}

// ── Proof packages ────────────────────────────────────────────────────────────

std::vector<nlohmann::json> BlockchainManager::buildProofPackages(
    const std::vector<MessageEnvelope>& envs,
    const SegmentDigest& digest)
{
    std::vector<nlohmann::json> packages;
    packages.reserve(envs.size());

    for (int i = 0; i < static_cast<int>(envs.size()); ++i) {
        const auto& env = envs[i];

        nlohmann::json envelope;
        envelope["schema_version"]    = env.schemaVersion.empty() ? "securemsg-envelope-v1" : env.schemaVersion;
        envelope["message_type"]      = env.messageType.empty()   ? "direct"                 : env.messageType;
        envelope["conversation_id"]   = env.conversationId;
        envelope["message_id"]        = env.messageId;
        envelope["sender_id"]         = env.senderId;
        envelope["recipient_id"]      = env.recipientId;
        envelope["ciphertext"]        = env.ciphertext;
        envelope["ratchet_header_enc"] = env.ratchetHeaderEnc;

        nlohmann::json proof;
        proof["segment_index"]      = i;
        proof["transaction_hash"]   = digest.transactionHash;
        proof["contract_address"]   = digest.contractAddress;
        proof["chain_name"]         = digest.chainName;
        proof["chain_id"]           = digest.chainId;
        proof["segment_hash"]       = digest.segmentHash;
        proof["envelope_hash"]      = digest.envelopeHashes[static_cast<std::size_t>(i)];
        proof["segment_hashes"]     = digest.envelopeHashes;
        proof["recorded_timestamp"] = digest.recordedTimestamp;
        proof["recorder"]           = digest.recorder;

        nlohmann::json pkg;
        pkg["envelope"] = envelope;
        pkg["proof"]    = proof;
        packages.push_back(std::move(pkg));
    }
    return packages;
}

std::string BlockchainManager::writeProofPackagesFile(
    const std::vector<nlohmann::json>& packages,
    const std::string& segmentId)
{
    std::string path = segmentId + "-proofs.json";
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write proof file: " + path);
    nlohmann::json arr = packages;
    f << arr.dump(2);
    return path;
}

// ── Verification ──────────────────────────────────────────────────────────────

std::string BlockchainManager::verifyLocalHashes(const nlohmann::json& pkg) {
    try {
        const auto& env   = pkg.at("envelope");
        const auto& proof = pkg.at("proof");

        // Reconstruct the envelope struct for hashing.
        MessageEnvelope e;
        e.schemaVersion    = env.value("schema_version",    "securemsg-envelope-v1");
        e.messageType      = env.value("message_type",      "direct");
        e.conversationId   = env.value("conversation_id",   "");
        e.messageId        = env.value("message_id",        "");
        e.senderId         = env.value("sender_id",         "");
        e.recipientId      = env.value("recipient_id",      "");
        e.ciphertext       = env.value("ciphertext",        "");
        e.ratchetHeaderEnc = env.value("ratchet_header_enc","");

        std::string computedEnvHash = toHex0x(leafHash(e));
        std::string proofEnvHash    = proof.value("envelope_hash", "");

        if (!proofEnvHash.empty()) {
            std::string a = computedEnvHash, b = proofEnvHash;
            std::transform(a.begin(), a.end(), a.begin(), ::tolower);
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            if (a != b) return "FAIL: envelope hash mismatch";
        }

        // Check envelope hash is at segment_index in segment_hashes.
        int idx = proof.value("segment_index", -1);
        if (idx < 0) return "FAIL: missing segment_index";
        const auto& hashes = proof.at("segment_hashes");
        if (idx >= static_cast<int>(hashes.size()))
            return "FAIL: segment_index out of range";
        std::string listedHash = hashes[static_cast<std::size_t>(idx)].get<std::string>();
        {
            std::string a = computedEnvHash, b = listedHash;
            std::transform(a.begin(), a.end(), a.begin(), ::tolower);
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            if (a != b) return "FAIL: envelope hash not at segment_index in segment_hashes";
        }

        // Recompute segment hash from all envelope hashes in segment_hashes.
        std::vector<std::vector<uint8_t>> leaves;
        for (const auto& h : hashes)
            leaves.push_back(fromHex0x(h.get<std::string>()));
        std::string computedSegHash = toHex0x(segmentHash(leaves));
        std::string proofSegHash    = proof.value("segment_hash", "");
        {
            std::string a = computedSegHash, b = proofSegHash;
            std::transform(a.begin(), a.end(), a.begin(), ::tolower);
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            if (a != b) return "FAIL: segment hash mismatch";
        }

        return "OK";
    } catch (const std::exception& ex) {
        return std::string("FAIL: ") + ex.what();
    }
}

// ── On-chain verification via JSON-RPC eth_call ───────────────────────────────

namespace {
static std::size_t curlWriteStr(char* ptr, std::size_t, std::size_t n, void* ud) {
    static_cast<std::string*>(ud)->append(ptr, n);
    return n;
}
} // anonymous namespace

std::string BlockchainManager::verifyOnChain(const nlohmann::json& pkg,
                                              const std::string& rpcUrl)
{
    try {
        const auto& proof   = pkg.at("proof");
        std::string contractAddr = proof.value("contract_address", "");
        std::string segHash      = proof.value("segment_hash",     "");

        if (contractAddr.empty()) return "FAIL: missing contract_address in proof";
        if (segHash.empty())      return "FAIL: missing segment_hash in proof";

        // Function selector: keccak256("getRecord(bytes32)")[0:4]
        auto selBytes = keccak256(std::string("getRecord(bytes32)"));
        std::vector<uint8_t> callData(selBytes.begin(), selBytes.begin() + 4);

        // ABI-encode the bytes32 argument (already 32 bytes).
        auto hashBytes = fromHex0x(segHash);
        if (hashBytes.size() != 32) return "FAIL: segment_hash must be 32 bytes";
        callData.insert(callData.end(), hashBytes.begin(), hashBytes.end());

        // Build hex calldata string.
        std::ostringstream dataHex;
        dataHex << "0x";
        for (uint8_t b : callData)
            dataHex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);

        // Build JSON-RPC request.
        nlohmann::json rpcReq;
        rpcReq["jsonrpc"] = "2.0";
        rpcReq["method"]  = "eth_call";
        rpcReq["params"]  = nlohmann::json::array({
            nlohmann::json{{"to", contractAddr}, {"data", dataHex.str()}},
            "latest"
        });
        rpcReq["id"] = 1;
        std::string bodyStr = rpcReq.dump();

        // Send via libcurl.
        std::string response;
        CURL* curl = curl_easy_init();
        if (!curl) return "FAIL: curl_easy_init failed";

        curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL,           rpcUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POST,           1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     bodyStr.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  static_cast<long>(bodyStr.size()));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWriteStr);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,        15L);
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK)
            return std::string("FAIL: RPC request failed: ") + curl_easy_strerror(res);

        auto rpcResp = nlohmann::json::parse(response, nullptr, false);
        if (rpcResp.is_discarded()) return "FAIL: invalid JSON from RPC";
        if (rpcResp.contains("error"))
            return "FAIL: RPC error: " + rpcResp["error"].dump();

        std::string result = rpcResp.value("result", "");
        // result is 0x + 32-byte address + 32-byte timestamp (ABI-encoded)
        // Strip "0x" and check length.
        if (result.substr(0, 2) == "0x" || result.substr(0, 2) == "0X")
            result = result.substr(2);
        if (result.size() < 128) // 64 hex chars per 32-byte word, need 2 words
            return "FAIL: unexpected RPC response length";

        // Second word (bytes 32–63) is the timestamp (uint64, big-endian, zero-padded to 32 bytes).
        std::string tsHex = result.substr(64, 64); // second 32-byte word
        uint64_t ts = 0;
        for (std::size_t i = 0; i < 16; i += 2) // last 8 bytes of the 32-byte word
            ts = (ts << 8) | std::stoul(tsHex.substr(48 + i, 2), nullptr, 16);

        if (ts == 0) return "FAIL: not recorded on-chain (timestamp is zero)";

        // First word is address, zero-padded — extract last 20 bytes (40 hex chars).
        std::string addrHex = "0x" + result.substr(24, 40);

        uint64_t proofTs = proof.value("recorded_timestamp", uint64_t{0});
        if (proofTs && proofTs != ts)
            return "FAIL: timestamp mismatch (on-chain=" + std::to_string(ts) +
                   " proof=" + std::to_string(proofTs) + ")";

        return "OK: recorded by " + addrHex + " at " + std::to_string(ts);
    } catch (const std::exception& ex) {
        return std::string("FAIL: ") + ex.what();
    }
}

// ── Ethereum transaction signing & submission ─────────────────────────────────

namespace {

// Big-endian minimal byte encoding (0 → empty; strips leading zero bytes)
static std::vector<uint8_t> beMin(uint64_t v) {
    if (v == 0) return {};
    std::vector<uint8_t> out;
    while (v) { out.insert(out.begin(), static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    return out;
}
static std::vector<uint8_t> beMinBytes(std::vector<uint8_t> b) {
    while (!b.empty() && b.front() == 0) b.erase(b.begin());
    return b;
}

// RLP encode a byte string
static std::vector<uint8_t> rlpB(const std::vector<uint8_t>& d) {
    if (d.size() == 1 && d[0] < 0x80) return d;
    std::vector<uint8_t> out;
    if (d.size() <= 55) {
        out.push_back(static_cast<uint8_t>(0x80 + d.size()));
    } else {
        auto lb = beMin(d.size());
        out.push_back(static_cast<uint8_t>(0xb7 + lb.size()));
        out.insert(out.end(), lb.begin(), lb.end());
    }
    out.insert(out.end(), d.begin(), d.end());
    return out;
}
static std::vector<uint8_t> rlpU(uint64_t v)                      { return rlpB(beMin(v)); }
static std::vector<uint8_t> rlpI(const std::vector<uint8_t>& b32) { return rlpB(beMinBytes({b32.begin(), b32.end()})); }

// RLP encode a list of pre-encoded fields
static std::vector<uint8_t> rlpL(const std::vector<std::vector<uint8_t>>& items) {
    std::vector<uint8_t> payload;
    for (const auto& f : items) payload.insert(payload.end(), f.begin(), f.end());
    std::vector<uint8_t> out;
    if (payload.size() <= 55) {
        out.push_back(static_cast<uint8_t>(0xc0 + payload.size()));
    } else {
        auto lb = beMin(payload.size());
        out.push_back(static_cast<uint8_t>(0xf7 + lb.size()));
        out.insert(out.end(), lb.begin(), lb.end());
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Derive Ethereum address (20 bytes) from a 32-byte secp256k1 private key
static std::vector<uint8_t> ethAddr(const std::vector<uint8_t>& priv32) {
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv = BN_bin2bn(priv32.data(), 32, nullptr);
    EC_POINT* pub = EC_POINT_new(grp);
    EC_POINT_mul(grp, pub, priv, nullptr, nullptr, ctx);
    std::vector<uint8_t> raw(65);
    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, raw.data(), 65, ctx);
    EC_POINT_free(pub); EC_GROUP_free(grp); BN_free(priv); BN_CTX_free(ctx);
    auto h = BlockchainManager::keccak256(std::vector<uint8_t>(raw.begin() + 1, raw.end()));
    return {h.begin() + 12, h.end()};
}

// Recover uncompressed pub key (64 bytes, no 0x04) from (hash, r, s, recId)
static std::vector<uint8_t> ecRecover(
    const std::vector<uint8_t>& h32,
    const std::vector<uint8_t>& r32,
    const std::vector<uint8_t>& s32,
    int recId)
{
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const BIGNUM* n = EC_GROUP_get0_order(grp);

    BIGNUM* r = BN_bin2bn(r32.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(s32.data(), 32, nullptr);
    BIGNUM* e = BN_bin2bn(h32.data(), 32, nullptr);
    BIGNUM* x = BN_dup(r);
    if (recId >= 2) BN_add(x, x, n);

    // y² = x³ + 7 mod p  (secp256k1, a=0 b=7)
    BIGNUM* p = BN_new(); BIGNUM* a = BN_new(); BIGNUM* b = BN_new();
    EC_GROUP_get_curve(grp, p, a, b, ctx);
    BIGNUM* rhs = BN_new();
    BN_mod_sqr(rhs, x, p, ctx);
    BN_mod_mul(rhs, rhs, x, p, ctx);
    BN_add_word(rhs, 7);
    BN_nnmod(rhs, rhs, p, ctx);
    // sqrt: exp = (p+1)/4 (works because p ≡ 3 mod 4 for secp256k1)
    BIGNUM* exp2 = BN_dup(p); BN_add_word(exp2, 1);
    BN_rshift1(exp2, exp2); BN_rshift1(exp2, exp2);
    BIGNUM* y = BN_new();
    BN_mod_exp(y, rhs, exp2, p, ctx);
    if ((BN_is_odd(y) ? 1 : 0) != (recId & 1)) BN_sub(y, p, y);

    EC_POINT* R = EC_POINT_new(grp);
    EC_POINT_set_affine_coordinates(grp, R, x, y, ctx);

    BIGNUM* rinv = BN_mod_inverse(nullptr, r, n, ctx);
    BIGNUM* u1 = BN_new(); BIGNUM* u2 = BN_new();
    BN_mod_mul(u1, e, rinv, n, ctx);
    BN_sub(u1, n, u1); BN_nnmod(u1, u1, n, ctx); // u1 = -e*r^-1 mod n
    BN_mod_mul(u2, s, rinv, n, ctx);               // u2 =  s*r^-1 mod n

    EC_POINT* Q = EC_POINT_new(grp);
    EC_POINT_mul(grp, Q, u1, R, u2, ctx);
    std::vector<uint8_t> out(65);
    EC_POINT_point2oct(grp, Q, POINT_CONVERSION_UNCOMPRESSED, out.data(), 65, ctx);

    BN_free(r); BN_free(s); BN_free(e); BN_free(x);
    BN_free(p); BN_free(a); BN_free(b); BN_free(rhs); BN_free(exp2); BN_free(y);
    BN_free(rinv); BN_free(u1); BN_free(u2);
    EC_POINT_free(R); EC_POINT_free(Q); EC_GROUP_free(grp); BN_CTX_free(ctx);
    return {out.begin() + 1, out.end()};
}

// JSON-RPC POST helper (reuses curlWriteStr from above in this same anonymous namespace)
static nlohmann::json ethRpc(const std::string& url, const nlohmann::json& req) {
    std::string body = req.dump(), resp;
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    curl_slist* hdr = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteStr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    // Point curl at the system CA bundle (OpenSSL 3.5 custom prefix has no certs)
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdr); curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("RPC: ") + curl_easy_strerror(rc));
    auto j = nlohmann::json::parse(resp, nullptr, false);
    if (j.is_discarded())
        throw std::runtime_error("Invalid JSON from RPC (got: " +
            (resp.size() > 120 ? resp.substr(0, 120) + "..." : resp) + ")");
    if (j.contains("error")) throw std::runtime_error("RPC error: " + j["error"].dump());
    return j.at("result");
}

} // anonymous namespace

std::string BlockchainManager::recordOnChain(
    const std::string& segmentHashHex,
    const std::string& contractAddress,
    const std::string& privateKeyHex,
    const std::string& rpcUrl,
    int chainId)
{
    try {
        // Parse inputs
        auto privKey = fromHex0x(privateKeyHex);
        if (privKey.size() != 32) throw std::invalid_argument("Private key must be 32 bytes");
        auto toAddr = fromHex0x(contractAddress);
        if (toAddr.size() != 20) throw std::invalid_argument("Contract address must be 20 bytes");
        auto hashBytes = fromHex0x(segmentHashHex);
        if (hashBytes.size() != 32) throw std::invalid_argument("Segment hash must be 32 bytes");

        // Derive sender address for nonce lookup
        auto senderBytes = ethAddr(privKey);
        std::ostringstream senderSS;
        senderSS << "0x";
        for (uint8_t b : senderBytes)
            senderSS << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        const std::string senderHex = senderSS.str();

        // eth_getTransactionCount
        nlohmann::json nonceReq;
        nonceReq["jsonrpc"] = "2.0"; nonceReq["method"] = "eth_getTransactionCount";
        nonceReq["params"] = nlohmann::json::array({senderHex, "pending"});
        nonceReq["id"] = 1;
        const auto nonceHex = ethRpc(rpcUrl, nonceReq).get<std::string>();
        const uint64_t nonce = std::stoull(nonceHex.substr(2), nullptr, 16);

        // eth_gasPrice with 20% tip
        nlohmann::json gpReq;
        gpReq["jsonrpc"] = "2.0"; gpReq["method"] = "eth_gasPrice";
        gpReq["params"] = nlohmann::json::array(); gpReq["id"] = 2;
        const auto gpHex = ethRpc(rpcUrl, gpReq).get<std::string>();
        const uint64_t gasPrice = std::stoull(gpHex.substr(2), nullptr, 16) * 12 / 10;

        // Build EC key — used for both the message signature and the tx signature.
        BN_CTX* ctx = BN_CTX_new();
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
        EC_KEY* key = EC_KEY_new();
        EC_KEY_set_group(key, grp);
        BIGNUM* privBn = BN_bin2bn(privKey.data(), 32, nullptr);
        EC_KEY_set_private_key(key, privBn);
        EC_POINT* pubPt = EC_POINT_new(grp);
        EC_POINT_mul(grp, pubPt, privBn, nullptr, nullptr, ctx);
        EC_KEY_set_public_key(key, pubPt);

        // Sign the segment hash with the private key for the `bytes signature` parameter.
        // Format: r (32) || s (32) || v (1), v = recId + 27 (message-signing convention).
        std::vector<uint8_t> msgSig(65);
        {
            ECDSA_SIG* ms = ECDSA_do_sign(hashBytes.data(), 32, key);
            if (!ms) throw std::runtime_error("Message sign failed");
            const BIGNUM* mr = nullptr; const BIGNUM* mss = nullptr;
            ECDSA_SIG_get0(ms, &mr, &mss);
            std::vector<uint8_t> mr32(32), ms32(32);
            BN_bn2binpad(mr, mr32.data(), 32);
            BN_bn2binpad(mss, ms32.data(), 32);
            // Low-s normalisation
            {
                const BIGNUM* nord = EC_GROUP_get0_order(grp);
                BIGNUM* hn = BN_new(); BN_rshift1(hn, nord);
                if (BN_cmp(mss, hn) > 0) {
                    BIGNUM* ns = BN_new(); BN_sub(ns, nord, mss);
                    BN_bn2binpad(ns, ms32.data(), 32); BN_free(ns);
                }
                BN_free(hn);
            }
            int mrid = -1;
            for (int rid = 0; rid < 2; ++rid) {
                auto rp = ecRecover(hashBytes, mr32, ms32, rid);
                auto rh = keccak256(rp);
                if (std::equal(rh.begin() + 12, rh.end(), senderBytes.begin()))
                { mrid = rid; break; }
            }
            if (mrid < 0) throw std::runtime_error("Message recId failed");
            ECDSA_SIG_free(ms);
            std::copy(mr32.begin(), mr32.end(), msgSig.begin());
            std::copy(ms32.begin(), ms32.end(), msgSig.begin() + 32);
            msgSig[64] = static_cast<uint8_t>(mrid + 27);
        }

        // calldata: recordDigest(bytes32 hash, bytes signature, uint64 timestamp)
        // ABI encoding: (bytes32 static) (bytes dynamic offset=96) (uint64 static)
        //               then tail: length(65) + msgSig padded to 32-byte boundary
        const uint64_t ts = static_cast<uint64_t>(std::time(nullptr));
        auto sel = keccak256(std::string("recordDigest(bytes32,bytes,uint64)"));
        std::vector<uint8_t> calldata(sel.begin(), sel.begin() + 4);
        // Head slot 0: bytes32 hash
        calldata.insert(calldata.end(), hashBytes.begin(), hashBytes.end());
        // Head slot 1: offset to bytes data = 3*32 = 96
        std::vector<uint8_t> off(32, 0); off[31] = 96;
        calldata.insert(calldata.end(), off.begin(), off.end());
        // Head slot 2: uint64 timestamp left-padded to 32 bytes
        std::vector<uint8_t> tsSlot(32, 0);
        for (int i = 0; i < 8; ++i)
            tsSlot[31 - i] = static_cast<uint8_t>((ts >> (i * 8)) & 0xFF);
        calldata.insert(calldata.end(), tsSlot.begin(), tsSlot.end());
        // Tail: length of bytes (65)
        std::vector<uint8_t> sigLen(32, 0); sigLen[31] = 65;
        calldata.insert(calldata.end(), sigLen.begin(), sigLen.end());
        // Tail: signature bytes + zero-padding to next 32-byte boundary (65 + 31 = 96)
        calldata.insert(calldata.end(), msgSig.begin(), msgSig.end());
        calldata.insert(calldata.end(), 31, 0x00);

        constexpr uint64_t GAS_LIMIT = 120000; // slightly more for the larger calldata

        // EIP-155 unsigned tx: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        auto rlpUnsigned = rlpL({
            rlpU(nonce), rlpU(gasPrice), rlpU(GAS_LIMIT),
            rlpB(toAddr), rlpU(0), rlpB(calldata),
            rlpU(static_cast<uint64_t>(chainId)), rlpU(0), rlpU(0)
        });
        auto txHash = keccak256(rlpUnsigned);

        // Sign the transaction
        ECDSA_SIG* sig = ECDSA_do_sign(txHash.data(), 32, key);
        if (!sig) throw std::runtime_error("ECDSA_do_sign failed");

        const BIGNUM* sigR = nullptr; const BIGNUM* sigS = nullptr;
        ECDSA_SIG_get0(sig, &sigR, &sigS);
        std::vector<uint8_t> rBytes(32), sBytes(32);
        BN_bn2binpad(sigR, rBytes.data(), 32);
        BN_bn2binpad(sigS, sBytes.data(), 32);

        // EIP-2: low-s normalisation
        {
            const BIGNUM* n_ord = EC_GROUP_get0_order(grp);
            BIGNUM* half_n = BN_new();
            BN_rshift1(half_n, n_ord);
            if (BN_cmp(sigS, half_n) > 0) {
                BIGNUM* ns = BN_new();
                BN_sub(ns, n_ord, sigS);
                BN_bn2binpad(ns, sBytes.data(), 32);
                BN_free(ns);
            }
            BN_free(half_n);
        }

        // Determine recovery ID
        int recId = -1;
        for (int rid = 0; rid < 2; ++rid) {
            auto recPub = ecRecover(txHash, rBytes, sBytes, rid);
            auto recHash = keccak256(recPub);
            if (std::equal(recHash.begin() + 12, recHash.end(), senderBytes.begin()))
            { recId = rid; break; }
        }
        if (recId < 0) throw std::runtime_error("Recovery ID determination failed");

        ECDSA_SIG_free(sig); EC_KEY_free(key); EC_GROUP_free(grp);
        EC_POINT_free(pubPt); BN_free(privBn); BN_CTX_free(ctx);

        // EIP-155 v = recId + chainId*2 + 35
        const uint64_t v = static_cast<uint64_t>(recId) +
                           static_cast<uint64_t>(chainId) * 2 + 35;

        // Signed tx: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        auto rlpSigned = rlpL({
            rlpU(nonce), rlpU(gasPrice), rlpU(GAS_LIMIT),
            rlpB(toAddr), rlpU(0), rlpB(calldata),
            rlpU(v), rlpI(rBytes), rlpI(sBytes)
        });

        // Hex-encode
        std::ostringstream rawSS;
        rawSS << "0x";
        for (uint8_t b : rlpSigned)
            rawSS << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);

        // eth_sendRawTransaction
        nlohmann::json sendReq;
        sendReq["jsonrpc"] = "2.0"; sendReq["method"] = "eth_sendRawTransaction";
        sendReq["params"] = nlohmann::json::array({rawSS.str()});
        sendReq["id"] = 3;
        return ethRpc(rpcUrl, sendReq).get<std::string>(); // tx hash

    } catch (const std::exception& ex) {
        return std::string("FAIL: ") + ex.what();
    }
}
