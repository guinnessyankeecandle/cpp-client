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
    std::string messageId;
    std::string senderId;
    std::string recipientId;
    std::string ciphertext;
    std::string ratchetHeaderEnc;
    int64_t     sentAt{0};
};

// Local record of a recorded blockchain segment.
struct SegmentProof {
    std::string segmentRoot;        // 0x-prefixed hex
    std::string conversationRef;
    std::string segmentRef;
    int         messageCount{0};
    std::string txHash;             // empty until recorded
    int         recordId{0};        // 0 until recorded
    std::string contractAddress;
};

class BlockchainManager {
public:
    // keccak256 (Ethereum-compatible, NOT SHA3-256).
    static std::vector<uint8_t> keccak256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> keccak256(const std::string& utf8);

    // Canonical JSON for an envelope (keys sorted, IDs as strings).
    static std::string canonicalise(const MessageEnvelope& env);

    // Leaf hash = keccak256(utf8 bytes of canonical JSON).
    static std::vector<uint8_t> leafHash(const MessageEnvelope& env);

    // Merkle root from ordered leaf hashes.
    // Odd levels duplicate the last node; order is preserved (left || right).
    static std::vector<uint8_t> merkleRoot(std::vector<std::vector<uint8_t>> leaves);

    // Merkle proof for a single leaf at position `index`.
    // Returns list of {position:"left"|"right", hash:hexString}.
    static nlohmann::json merkleProof(std::vector<std::vector<uint8_t>> leaves,
                                       std::size_t index);

    // Build and return a segment proof object from a list of envelopes.
    // Does NOT submit to the blockchain — call recordScript() for that.
    static SegmentProof buildSegmentProof(const std::vector<MessageEnvelope>& envelopes,
                                           const std::string& conversationId,
                                           int segmentIndex);

    // Write a segment JSON file suitable for the Node.js recording script.
    // Returns the path written.
    static std::string writeSegmentFile(const std::vector<MessageEnvelope>& envelopes,
                                         const SegmentProof& proof);

    // Invoke the Node.js recording script and parse the returned proof.
    // recordScriptPath: path to recordSegmentRoot.js
    // segmentFilePath:  path written by writeSegmentFile()
    // Returns updated proof with txHash, recordId, contractAddress filled in.
    static SegmentProof runRecordingScript(const std::string& recordScriptPath,
                                            const std::string& segmentFilePath);

    // Hex helpers
    static std::string toHex0x(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fromHex0x(const std::string& hex);
};
