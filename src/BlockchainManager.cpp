#include "BlockchainManager.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <array>
#include <fstream>
#include <cstdio>

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
    // Build as nlohmann::json then dump with sorted keys.
    nlohmann::json j;
    j["ciphertext"]         = env.ciphertext;
    j["conversation_id"]    = env.conversationId;
    j["message_id"]         = env.messageId;          // string
    j["message_type"]       = env.messageType;
    j["ratchet_header_enc"] = env.ratchetHeaderEnc;
    j["recipient_id"]       = env.recipientId;        // string
    j["schema_version"]     = env.schemaVersion;
    j["sender_id"]          = env.senderId;           // string
    j["sent_at"]            = env.sentAt;             // number

    // nlohmann::json::dump() sorts keys when using json::object() and iterating
    // alphabetically — ensure by building a std::map-based JSON.
    // Actually nlohmann preserves insertion order for object by default.
    // Use the ordered_json variant or manually sort.
    // Simplest: build ordered map and dump.
    nlohmann::ordered_json oj;
    // Insert alphabetically (by hand since fields are known):
    oj["ciphertext"]         = env.ciphertext;
    oj["conversation_id"]    = env.conversationId;
    oj["message_id"]         = env.messageId;
    oj["message_type"]       = env.messageType;
    oj["ratchet_header_enc"] = env.ratchetHeaderEnc;
    oj["recipient_id"]       = env.recipientId;
    oj["schema_version"]     = env.schemaVersion;
    oj["sender_id"]          = env.senderId;
    oj["sent_at"]            = env.sentAt;

    return oj.dump(); // compact, no extra whitespace
}

std::vector<uint8_t> BlockchainManager::leafHash(const MessageEnvelope& env) {
    return keccak256(canonicalise(env));
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

std::vector<uint8_t> BlockchainManager::merkleRoot(std::vector<std::vector<uint8_t>> leaves) {
    if (leaves.empty()) throw std::invalid_argument("No leaves");
    if (leaves.size() == 1) return leaves[0];

    while (leaves.size() > 1) {
        // Duplicate last leaf if odd number (standard Ethereum Merkle convention).
        if (leaves.size() % 2 != 0)
            leaves.push_back(leaves.back());

        std::vector<std::vector<uint8_t>> next;
        for (std::size_t i = 0; i < leaves.size(); i += 2) {
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), leaves[i].begin(),   leaves[i].end());
            combined.insert(combined.end(), leaves[i+1].begin(), leaves[i+1].end());
            next.push_back(keccak256(combined));
        }
        leaves = std::move(next);
    }
    return leaves[0];
}

nlohmann::json BlockchainManager::merkleProof(std::vector<std::vector<uint8_t>> leaves,
                                               std::size_t index)
{
    if (leaves.empty() || index >= leaves.size())
        throw std::invalid_argument("Invalid leaf index");

    nlohmann::json siblings = nlohmann::json::array();

    while (leaves.size() > 1) {
        if (leaves.size() % 2 != 0)
            leaves.push_back(leaves.back());

        std::vector<std::vector<uint8_t>> next;
        for (std::size_t i = 0; i < leaves.size(); i += 2) {
            if (i == index || i + 1 == index) {
                // This pair contains our leaf.
                std::size_t siblingIdx = (i == index) ? i + 1 : i;
                nlohmann::json sib;
                sib["position"] = (i == index) ? "right" : "left";
                sib["hash"]     = toHex0x(leaves[siblingIdx]);
                siblings.push_back(sib);
                index = i / 2; // new index in next level
            }
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), leaves[i].begin(),   leaves[i].end());
            combined.insert(combined.end(), leaves[i+1].begin(), leaves[i+1].end());
            next.push_back(keccak256(combined));
        }
        leaves = std::move(next);
    }

    return siblings;
}

// ── Segment proof builder ─────────────────────────────────────────────────────

SegmentProof BlockchainManager::buildSegmentProof(const std::vector<MessageEnvelope>& envs,
                                                   const std::string& conversationId,
                                                   int segmentIndex)
{
    std::vector<std::vector<uint8_t>> leaves;
    for (const auto& env : envs)
        leaves.push_back(leafHash(env));

    auto root = merkleRoot(leaves);

    SegmentProof proof;
    proof.segmentRoot    = toHex0x(root);
    proof.conversationRef = conversationId;
    proof.segmentRef     = conversationId + "-seg-" + std::to_string(segmentIndex);
    proof.messageCount   = static_cast<int>(envs.size());
    return proof;
}

// ── Segment file (input to Node.js recording script) ─────────────────────────

std::string BlockchainManager::writeSegmentFile(const std::vector<MessageEnvelope>& envs,
                                                  const SegmentProof& proof)
{
    nlohmann::json messages = nlohmann::json::array();
    for (const auto& env : envs) {
        nlohmann::json m;
        m["schema_version"]    = env.schemaVersion;
        m["message_type"]      = env.messageType;
        m["conversation_id"]   = env.conversationId;
        m["message_id"]        = env.messageId;
        m["sender_id"]         = env.senderId;
        m["recipient_id"]      = env.recipientId;
        m["ciphertext"]        = env.ciphertext;
        m["ratchet_header_enc"] = env.ratchetHeaderEnc;
        m["sent_at"]           = env.sentAt;
        messages.push_back(m);
    }

    nlohmann::json seg;
    seg["conversation_id"] = proof.conversationRef;
    seg["segment_id"]      = proof.segmentRef;
    seg["messages"]        = messages;

    std::string path = proof.segmentRef + ".json";
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write segment file: " + path);
    f << seg.dump(2);
    return path;
}

// ── Run Node.js recording script ──────────────────────────────────────────────

SegmentProof BlockchainManager::runRecordingScript(const std::string& scriptPath,
                                                    const std::string& segmentFilePath)
{
    // node recordSegmentRoot.js segment.json  → prints JSON proof to stdout
    std::string cmd = "node " + scriptPath + " " + segmentFilePath;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("Failed to run recording script");

    std::string output;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe))
        output += buf;
    int rc = pclose(pipe);

    if (rc != 0)
        throw std::runtime_error("Recording script failed (exit " + std::to_string(rc) + "): " + output);

    auto j = nlohmann::json::parse(output, nullptr, false);
    if (j.is_discarded())
        throw std::runtime_error("Recording script returned invalid JSON: " + output);

    SegmentProof proof;
    proof.segmentRoot     = j.value("segment_root", "");
    proof.recordId        = j.value("record_id", 0);
    proof.txHash          = j.value("transaction_hash", "");
    proof.contractAddress = j.value("contract_address", "");
    proof.conversationRef = j.value("conversation_ref", "");
    proof.segmentRef      = j.value("segment_ref", "");
    proof.messageCount    = j.value("message_count", 0);
    return proof;
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
