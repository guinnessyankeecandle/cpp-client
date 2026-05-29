#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

// One encrypted message envelope, ready to be hashed and recorded on-chain.
struct MessageEnvelope {
    std::string schemaVersion{"securemsg-envelope-v1"};
    std::string messageType{"direct"};
    std::string conversationId;
    std::string messageId;      // stored as string
    std::string senderId;       // stored as string
    std::string recipientId;    // stored as string
    std::string ciphertext;
    std::string ratchetHeaderEnc;
    int64_t     sentAt{0};
};

// Segment digest computed locally before on-chain recording.
struct SegmentDigest {
    std::string              segmentHash;      // 0x-prefixed keccak256
    std::vector<std::string> envelopeHashes;   // per envelope, same order
    std::string              conversationId;
    std::string              segmentId;        // e.g. "direct-1-2-seg-1"
    int                      messageCount{0};

    // Filled in after the browser records on Sepolia:
    std::string  transactionHash;
    std::string  contractAddress;
    std::string  recorder;
    uint64_t     recordedTimestamp{0};
    int          chainId{11155111};
    std::string  chainName{"sepolia"};
};

class BlockchainManager {
public:
    // ── Keccak-256 ─────────────────────────────────────────────────────────────
    static std::vector<uint8_t> keccak256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> keccak256(const std::string& utf8);

    // ── Envelope canonicalisation ───────────────────────────────────────────────
    // Produces compact JSON with exactly the 8 fields in alphabetical order,
    // matching digestUtils.js DIRECT_ENVELOPE_FIELDS.
    static std::string canonicalise(const MessageEnvelope& env);

    // Leaf hash = keccak256(utf8(canonicalise(env))).
    static std::vector<uint8_t> leafHash(const MessageEnvelope& env);

    // ── Segment hash ────────────────────────────────────────────────────────────
    // keccak256(utf8("SecureMsgSegmentDigest:v1") || hash1_bytes || hash2_bytes || ...)
    static std::vector<uint8_t> segmentHash(const std::vector<std::vector<uint8_t>>& leafHashes);

    // ── Segment digest builder ──────────────────────────────────────────────────
    static SegmentDigest buildSegmentDigest(const std::vector<MessageEnvelope>& envs,
                                            const std::string& conversationId,
                                            int segmentIndex);

    // Export a segment JSON file for browser recording.
    // Returns the file path written.
    static std::string writeSegmentFile(const std::vector<MessageEnvelope>& envs,
                                        const SegmentDigest& digest);

    // ── Proof packages ──────────────────────────────────────────────────────────
    // Build one proof package JSON object per envelope.
    static std::vector<nlohmann::json> buildProofPackages(
        const std::vector<MessageEnvelope>& envs,
        const SegmentDigest& digest);

    // Write all proof packages to a single JSON array file.
    // Returns the file path written.
    static std::string writeProofPackagesFile(const std::vector<nlohmann::json>& packages,
                                              const std::string& segmentId);

    // ── Verification ────────────────────────────────────────────────────────────
    // Verify a proof package locally (no network).
    // Returns "OK" on success, or an error message.
    static std::string verifyLocalHashes(const nlohmann::json& package);

    // Query the Sepolia contract via JSON-RPC eth_call.
    // rpcUrl: e.g. "https://rpc.sepolia.org"
    // Returns "OK: recorded by 0x... at <ts>" on success, or an error message.
    static std::string verifyOnChain(const nlohmann::json& package,
                                     const std::string& rpcUrl);

    // ── Hex helpers ─────────────────────────────────────────────────────────────
    static std::string              toHex0x(const std::vector<uint8_t>& data);
    static std::vector<uint8_t>     fromHex0x(const std::string& hex);

    // ── Legacy (kept for build compat, unused) ──────────────────────────────────
    static std::vector<uint8_t>  merkleRoot(std::vector<std::vector<uint8_t>> leaves);
    static nlohmann::json        merkleProof(std::vector<std::vector<uint8_t>> leaves,
                                             std::size_t index);
};
