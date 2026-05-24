#include "User.hpp"
#include "Message.hpp"
#include "MessageStore.hpp"
#include "ApiClient.hpp"
#include "CryptoManager.hpp"

#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <ctime>
#include <filesystem>

namespace fs = std::filesystem;

// ── Constants ─────────────────────────────────────────────────────────────────

static const std::string BASE_URL    = "https://drop-table.theburkenator.com";
static const std::string KEY_FILE    = "identity.key";

// ── I/O helpers ───────────────────────────────────────────────────────────────

static std::string prompt(const std::string& msg) {
    std::cout << msg;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

static std::string promptHidden(const std::string& msg) {
    // Simple hidden input — on real Linux terminals use termios to disable echo.
    std::cout << msg;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

static void printSeparator() { std::cout << std::string(50, '-') << '\n'; }

static std::string formatTimestamp(int64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

// ── Key management ────────────────────────────────────────────────────────────

// Load existing identity key or generate and save a new one.
static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
ensureIdentityKey(const std::string& passphrase) {
    if (fs::exists(KEY_FILE)) {
        std::cout << "Loading existing identity key...\n";
        auto priv = CryptoManager::loadPrivateKey(KEY_FILE, passphrase);
        // Re-derive the public key from the private key via a throwaway keygen.
        // OpenSSL: restore EVP_PKEY from private bytes, extract public bytes.
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
        std::vector<uint8_t> pub(32);
        std::size_t pubLen = 32;
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen);
        EVP_PKEY_free(pkey);
        return {priv, pub};
    }

    std::cout << "Generating new X25519 identity key pair...\n";
    auto [priv, pub] = CryptoManager::generateX25519KeyPair();
    CryptoManager::savePrivateKey(KEY_FILE, priv, passphrase);
    std::cout << "Identity key saved to " << KEY_FILE << '\n';
    return {priv, pub};
}

// ── Registration flow ─────────────────────────────────────────────────────────

static void doRegister(ApiClient& api) {
    printSeparator();
    std::string username = prompt("Username: ");
    std::string password = promptHidden("Password: ");

    std::cout << "Computing SRP-6a verifier...\n";
    std::string saltHex;
    std::string verifierHex = CryptoManager::computeSrpVerifier(username, password, saltHex);

    auto result = api.registerUser(username, saltHex, verifierHex);
    std::cout << "Registered!  User ID: " << result["user_id"] << '\n';

    if (result.contains("totp_provisioning_uri")) {
        std::cout << "\nScan this TOTP URI in your authenticator app:\n"
                  << result["totp_provisioning_uri"].get<std::string>() << '\n';
    }
}

// ── Login flow (SRP-6a + TOTP 2FA) ───────────────────────────────────────────

static User doLogin(ApiClient& api) {
    printSeparator();
    std::string username = prompt("Username: ");
    std::string password = promptHidden("Password: ");

    SrpSession session;
    std::string clientPublicHex = session.begin(username, password);

    std::cout << "SRP step 1: sending client public...\n";
    auto initResp = api.srpInit(username, clientPublicHex);
    std::string sessionId  = initResp["session_id"];
    std::string srpSalt    = initResp["srp_salt"];
    std::string serverPub  = initResp["server_public"];

    std::cout << "SRP step 2: computing proof...\n";
    std::string clientProof = session.computeProof(srpSalt, serverPub);

    auto verifyResp = api.srpVerify(sessionId, clientProof);

    if (!session.verifyServerProof(verifyResp["server_proof"].get<std::string>())) {
        throw std::runtime_error("Server proof invalid — possible MITM attack!");
    }
    std::cout << "Server authenticated.\n";

    std::string preAuthToken = verifyResp["pre_auth_token"];
    std::string totpCode     = prompt("TOTP code: ");

    auto tokenResp = api.verify2FA(preAuthToken, totpCode);
    std::string accessToken  = tokenResp["access_token"];
    std::string refreshToken = tokenResp["refresh_token"];

    std::cout << "Login successful.\n";
    // We don't have the user_id here; the server could return it.
    // For now we store 0 and update it after fetching the key bundle.
    return User(0, username, accessToken, refreshToken);
}

// ── Publish public key ────────────────────────────────────────────────────────

static void publishPublicKey(ApiClient& api, const User& user,
                              const std::vector<uint8_t>& pubKey)
{
    std::string pubB64 = CryptoManager::base64Encode(pubKey);
    // Minimal key bundle: identity_pub only (others are placeholders for demo).
    nlohmann::json bundle = {
        {"identity_pub",      pubB64},
        {"signed_prekey_pub", pubB64},
        {"signed_prekey_sig", pubB64},         // placeholder
        {"one_time_prekeys",  nlohmann::json::array()},
        {"pq_prekey_pub",     pubB64},          // placeholder
        {"pq_prekey_sig",     pubB64}           // placeholder
    };
    api.publishKeyBundle(user.getAccessToken(), bundle);
    std::cout << "Public key published to server.\n";
}

// ── Send a message ─────────────────────────────────────────────────────────────

static void doSendMessage(ApiClient& api, const User& user,
                           const std::vector<uint8_t>& myPriv,
                           const std::vector<uint8_t>& myPub)
{
    printSeparator();
    int recipientId = std::stoi(prompt("Recipient user ID: "));
    std::string plaintext = prompt("Message: ");

    // Fetch recipient's identity public key from server.
    std::cout << "Fetching recipient's key bundle...\n";
    auto bundle       = api.getKeyBundle(user.getAccessToken(), recipientId);
    auto recipPubB64  = bundle["identity_pub"].get<std::string>();
    auto recipPub     = CryptoManager::base64Decode(recipPubB64);

    // Derive per-message key via simplified HPKE Mode_Auth.
    auto [msgKey, ephemPub] = CryptoManager::deriveMessageKey(myPriv, myPub, recipPub);

    // Encrypt with AES-256-GCM.
    auto pkt           = CryptoManager::aeadEncrypt(plaintext, msgKey);
    auto packed        = CryptoManager::packAead(pkt);
    auto ciphertextB64 = CryptoManager::base64Encode(packed);
    auto headerEncB64  = CryptoManager::base64Encode(ephemPub);  // ephemeral pub in header

    auto resp = api.sendMessage(user.getAccessToken(), recipientId, ciphertextB64, headerEncB64);
    std::cout << "Message sent.  ID: " << resp["id"]
              << "  Revocation token: " << resp["revocation_token"].get<std::string>() << '\n';
}

// ── Receive / decrypt messages ────────────────────────────────────────────────

static void doListMessages(ApiClient& api, const User& user, MessageStore& store,
                            const std::vector<uint8_t>& myPriv,
                            const std::vector<uint8_t>& myPub)
{
    printSeparator();
    auto messages = api.listMessages(user.getAccessToken());

    if (messages.empty()) {
        std::cout << "No messages.\n";
        return;
    }

    // Cache of sender public keys: sender_id → public_key_bytes
    std::map<int, std::vector<uint8_t>> pubKeyCache;

    for (const auto& m : messages) {
        int      id         = m["id"];
        int      senderId   = m["sender_id"];
        int64_t  sentAt     = m["sent_at"];
        auto     ctB64      = m["ciphertext"].get<std::string>();
        auto     hdrB64     = m["ratchet_header_enc"].get<std::string>();

        std::string plaintext;
        try {
            // Fetch sender's public key if not cached.
            if (!pubKeyCache.count(senderId)) {
                auto bundle = api.getKeyBundle(user.getAccessToken(), senderId);
                pubKeyCache[senderId] = CryptoManager::base64Decode(
                    bundle["identity_pub"].get<std::string>());
            }
            const auto& senderPub = pubKeyCache[senderId];
            auto ephemPub         = CryptoManager::base64Decode(hdrB64);
            auto msgKey           = CryptoManager::recoverMessageKey(myPriv, myPub, senderPub, ephemPub);

            auto packed = CryptoManager::base64Decode(ctB64);
            auto pkt    = CryptoManager::unpackAead(packed);
            plaintext   = CryptoManager::aeadDecrypt(pkt, msgKey);
        } catch (const std::exception& e) {
            plaintext = "[decryption failed: " + std::string(e.what()) + "]";
        }

        Message msg(id, senderId, user.getId(), ctB64, hdrB64, sentAt, Message::Direction::Received);
        msg.setPlaintext(plaintext);
        store.addMessage(msg);

        std::cout << "[" << id << "] from uid:" << senderId
                  << "  at " << formatTimestamp(sentAt) << '\n'
                  << "  " << plaintext << '\n';
    }
}

// ── Acknowledge receipt ───────────────────────────────────────────────────────

static void doAcknowledge(ApiClient& api, const User& user, MessageStore& store) {
    printSeparator();
    int id = std::stoi(prompt("Message ID to acknowledge (deletes from server): "));
    api.acknowledgeReceipt(user.getAccessToken(), id);
    store.removeById(id);
    std::cout << "Receipt sent.  Message removed from server.\n";
}

// ── Revoke a sent message ─────────────────────────────────────────────────────

static void doRevoke(ApiClient& api, const User& user) {
    printSeparator();
    int         id    = std::stoi(prompt("Message ID to revoke: "));
    std::string token = prompt("Revocation token: ");
    api.revokeMessage(user.getAccessToken(), id, token);
    std::cout << "Message revoked.\n";
}

// ── Main menu loop ────────────────────────────────────────────────────────────

static void mainMenu(ApiClient& api, User user,
                     const std::vector<uint8_t>& myPriv,
                     const std::vector<uint8_t>& myPub)
{
    MessageStore store;

    while (true) {
        printSeparator();
        std::cout << "Logged in as: " << user.getUsername() << '\n'
                  << "  1) Send message\n"
                  << "  2) Fetch & decrypt messages\n"
                  << "  3) Acknowledge receipt (remove from server)\n"
                  << "  4) Revoke a sent message\n"
                  << "  5) Show local message store (" << store.size() << " cached)\n"
                  << "  6) Publish my public key\n"
                  << "  0) Logout\n";

        std::string choice = prompt("> ");

        try {
            if      (choice == "1") doSendMessage(api, user, myPriv, myPub);
            else if (choice == "2") doListMessages(api, user, store, myPriv, myPub);
            else if (choice == "3") doAcknowledge(api, user, store);
            else if (choice == "4") doRevoke(api, user);
            else if (choice == "5") {
                auto all = store.getAll();
                if (all.empty()) { std::cout << "Store is empty.\n"; continue; }
                for (const auto& m : all) {
                    std::cout << "[" << m.getId() << "] "
                              << (m.getDirection() == Message::Direction::Sent ? "SENT" : "RECV")
                              << "  " << formatTimestamp(m.getSentAt())
                              << "  " << m.getPlaintext() << '\n';
                }
            }
            else if (choice == "6") publishPublicKey(api, user, myPub);
            else if (choice == "0") {
                api.logout(user.getRefreshToken());
                std::cout << "Logged out.\n";
                return;
            }
            else std::cout << "Unknown option.\n";
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << '\n';
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== SecureMsg C++ Client ===\n";
    std::cout << "Backend: " << BASE_URL << "\n\n";

    // Determine TLS verification: disable only for local dev with self-signed certs.
    bool verifyTls = true;
    ApiClient api(BASE_URL, verifyTls);

    while (true) {
        std::cout << "  1) Register\n"
                  << "  2) Login\n"
                  << "  0) Quit\n";
        std::string choice = prompt("> ");

        if (choice == "0") break;

        try {
            if (choice == "1") {
                doRegister(api);
            } else if (choice == "2") {
                User user = doLogin(api);

                std::string passphrase = promptHidden("Key passphrase (protects local identity key): ");
                auto [myPriv, myPub]   = ensureIdentityKey(passphrase);

                mainMenu(api, user, myPriv, myPub);
            }
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << "\n\n";
        }
    }
    return 0;
}
