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
