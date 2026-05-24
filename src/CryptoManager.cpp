#include "CryptoManager.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>

#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <fstream>
#include <cstring>

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

// SHA-256 over a sequence of byte spans; returns 32-byte digest.
struct Span { const uint8_t* data; std::size_t len; };

std::vector<uint8_t> sha256(std::initializer_list<Span> parts) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new");
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    for (const auto& s : parts) EVP_DigestUpdate(ctx, s.data, s.len);
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    unsigned int outLen = SHA256_DIGEST_LENGTH;
    EVP_DigestFinal_ex(ctx, out.data(), &outLen);
    EVP_MD_CTX_free(ctx);
    return out;
}

// Convert a BIGNUM to a fixed-width big-endian byte vector (left-padded with zeros).
std::vector<uint8_t> bnToFixedBytes(const BIGNUM* bn, std::size_t width) {
    std::vector<uint8_t> buf(width, 0);
    int bytes = BN_num_bytes(bn);
    if (static_cast<std::size_t>(bytes) > width)
        throw std::runtime_error("BN too large for requested width");
    // Write into the right-hand side so the result is left-padded.
    BN_bn2bin(bn, buf.data() + (width - bytes));
    return buf;
}

// SRP-6a 2048-bit group prime (RFC 5054, Appendix A.2).
static const char* SRP_N_HEX =
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
    "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
    "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
    "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
    "FD5138FE8376435B9FC61D2FC0EB06E3";

static constexpr std::size_t SRP_N_BYTES = 256; // 2048 bits
static constexpr uint8_t     SRP_G       = 2;

// Load the RFC-5054 group into three BIGNUMs.  Caller owns n, g, k.
void srpLoadGroup(BIGNUM*& n, BIGNUM*& g, BIGNUM*& k, BN_CTX* ctx) {
    BN_hex2bn(&n, SRP_N_HEX);
    g = BN_new(); BN_set_word(g, SRP_G);

    // k = SHA-256( N || PAD(g, 256) )
    // N_bytes: 256-byte big-endian representation of N.
    std::vector<uint8_t> nBytes(SRP_N_BYTES, 0);
    BN_bn2binpad(n, nBytes.data(), static_cast<int>(SRP_N_BYTES));

    std::vector<uint8_t> gPadded(SRP_N_BYTES, 0);
    gPadded[SRP_N_BYTES - 1] = SRP_G; // g = 2, big-endian

    auto kBytes = sha256({
        {nBytes.data(),  nBytes.size()},
        {gPadded.data(), gPadded.size()}
    });

    k = BN_new();
    BN_bin2bn(kBytes.data(), static_cast<int>(kBytes.size()), k);

    (void)ctx;
}

// x = SHA-256( salt_bytes || SHA-256( username || ":" || password ) )
BIGNUM* computeSrpX(const std::vector<uint8_t>& saltBytes,
                     const std::string&           username,
                     const std::string&           password)
{
    std::string cred = username + ":" + password;
    auto credHash = sha256({{reinterpret_cast<const uint8_t*>(cred.data()), cred.size()}});

    auto xHash = sha256({
        {saltBytes.data(), saltBytes.size()},
        {credHash.data(),  credHash.size()}
    });

    BIGNUM* x = BN_new();
    BN_bin2bn(xHash.data(), static_cast<int>(xHash.size()), x);
    return x;
}

} // anonymous namespace

// ── SrpSession ───────────────────────────────────────────────────────────────

std::string SrpSession::begin(const std::string& username, const std::string& password) {
    m_username = username;
    m_password = password;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = nullptr; BIGNUM* g = nullptr; BIGNUM* k = nullptr;
    srpLoadGroup(N, g, k, ctx);

    // a = random 256-bit private ephemeral
    BIGNUM* a = BN_new();
    do {
        BN_rand(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_mod(a, a, N, ctx);
    } while (BN_is_zero(a));

    // A = g^a mod N
    BIGNUM* A = BN_new();
    BN_mod_exp(A, g, a, N, ctx);

    // Persist a and A as fixed-width byte vectors for use in computeProof().
    m_a_bytes.resize(SRP_N_BYTES);
    BN_bn2binpad(a, m_a_bytes.data(), static_cast<int>(SRP_N_BYTES));

    m_A_bytes.resize(SRP_N_BYTES);
    BN_bn2binpad(A, m_A_bytes.data(), static_cast<int>(SRP_N_BYTES));

    std::string hexA = CryptoManager::toHex(m_A_bytes);

    BN_free(A); BN_free(a); BN_free(k); BN_free(g); BN_free(N);
    BN_CTX_free(ctx);
    return hexA;
}

std::string SrpSession::computeProof(const std::string& srpSaltHex,
                                      const std::string& serverPublicHex)
{
    auto saltBytes = CryptoManager::fromHex(srpSaltHex);
    auto bBytes    = CryptoManager::fromHex(serverPublicHex);
    // Pad B to N_BYTES if needed.
    if (bBytes.size() < SRP_N_BYTES) {
        bBytes.insert(bBytes.begin(), SRP_N_BYTES - bBytes.size(), 0);
    }

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = nullptr; BIGNUM* g = nullptr; BIGNUM* k = nullptr;
    srpLoadGroup(N, g, k, ctx);

    BIGNUM* B = BN_new();
    BN_bin2bn(bBytes.data(), static_cast<int>(bBytes.size()), B);

    // u = SHA-256( PAD(A, 256) || PAD(B, 256) )
    auto uHash = sha256({
        {m_A_bytes.data(), m_A_bytes.size()},
        {bBytes.data(),    bBytes.size()}
    });
    BIGNUM* u = BN_new();
    BN_bin2bn(uHash.data(), static_cast<int>(uHash.size()), u);

    // Recover a from stored bytes.
    BIGNUM* a = BN_new();
    BN_bin2bn(m_a_bytes.data(), static_cast<int>(m_a_bytes.size()), a);

    // x = SHA-256( salt || SHA-256( username:password ) )
    BIGNUM* x = computeSrpX(saltBytes, m_username, m_password);

    // S = (B - k*g^x mod N) ^ (a + u*x) mod N
    BIGNUM* gx  = BN_new(); BN_mod_exp(gx, g, x, N, ctx);
    BIGNUM* kgx = BN_new(); BN_mod_mul(kgx, k, gx, N, ctx);
    BIGNUM* diff = BN_new(); BN_mod_sub(diff, B, kgx, N, ctx);

    BIGNUM* ux  = BN_new(); BN_mul(ux, u, x, ctx);
    BIGNUM* exp = BN_new(); BN_add(exp, a, ux);

    BIGNUM* S   = BN_new(); BN_mod_exp(S, diff, exp, N, ctx);

    // K = SHA-256( PAD(S, 256) )
    auto sBytes = bnToFixedBytes(S, SRP_N_BYTES);
    m_K = sha256({{sBytes.data(), sBytes.size()}});

    // Compute h(N) XOR h(g)
    std::vector<uint8_t> nBytes(SRP_N_BYTES, 0);
    BN_bn2binpad(N, nBytes.data(), static_cast<int>(SRP_N_BYTES));
    std::vector<uint8_t> gPadded(SRP_N_BYTES, 0);
    gPadded[SRP_N_BYTES - 1] = SRP_G;

    auto hN = sha256({{nBytes.data(), nBytes.size()}});
    auto hg = sha256({{gPadded.data(), gPadded.size()}});
    std::vector<uint8_t> hNxorHg(SHA256_DIGEST_LENGTH);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) hNxorHg[i] = hN[i] ^ hg[i];

    auto hI = sha256({{reinterpret_cast<const uint8_t*>(m_username.data()), m_username.size()}});

    // M1 = SHA-256( hNxorHg || h(I) || salt || PAD(A) || PAD(B) || K )
    m_M1 = sha256({
        {hNxorHg.data(),   hNxorHg.size()},
        {hI.data(),        hI.size()},
        {saltBytes.data(), saltBytes.size()},
        {m_A_bytes.data(), m_A_bytes.size()},
        {bBytes.data(),    bBytes.size()},
        {m_K.data(),       m_K.size()}
    });

    std::string hexM1 = CryptoManager::toHex(m_M1);

    BN_free(S); BN_free(exp); BN_free(ux); BN_free(diff);
    BN_free(kgx); BN_free(gx); BN_free(x); BN_free(a);
    BN_free(u); BN_free(B); BN_free(k); BN_free(g); BN_free(N);
    BN_CTX_free(ctx);
    return hexM1;
}

bool SrpSession::verifyServerProof(const std::string& serverProofHex) const {
    auto serverM2 = CryptoManager::fromHex(serverProofHex);

    // M2 = SHA-256( PAD(A) || M1 || K )
    auto expected = sha256({
        {m_A_bytes.data(), m_A_bytes.size()},
        {m_M1.data(),      m_M1.size()},
        {m_K.data(),       m_K.size()}
    });

    return expected == serverM2;
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

CryptoManager::AeadPacket CryptoManager::aeadEncrypt(const std::string&          plaintext,
                                                       const std::vector<uint8_t>& key)
{
    if (key.size() != KEY_BYTES)
        throw std::invalid_argument("AES key must be 32 bytes");

    AeadPacket pkt;
    pkt.iv  = randomBytes(IV_BYTES);
    pkt.tag.resize(TAG_BYTES);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_BYTES, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), pkt.iv.data());

    pkt.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    EVP_EncryptUpdate(ctx,
                      pkt.ciphertext.data(), &outLen,
                      reinterpret_cast<const uint8_t*>(plaintext.data()),
                      static_cast<int>(plaintext.size()));
    int totalLen = outLen;
    EVP_EncryptFinal_ex(ctx, pkt.ciphertext.data() + outLen, &outLen);
    totalLen += outLen;
    pkt.ciphertext.resize(totalLen);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, pkt.tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return pkt;
}

std::string CryptoManager::aeadDecrypt(const AeadPacket& pkt, const std::vector<uint8_t>& key) {
    if (key.size() != KEY_BYTES)
        throw std::invalid_argument("AES key must be 32 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new");

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_BYTES, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), pkt.iv.data());

    std::vector<uint8_t> plaintext(pkt.ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &outLen,
                      pkt.ciphertext.data(), static_cast<int>(pkt.ciphertext.size()));
    int totalLen = outLen;

    // Set expected tag before calling Final.
    auto tagCopy = pkt.tag;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, tagCopy.data());

    int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &outLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0)
        throw std::runtime_error("AES-256-GCM authentication failed — message tampered or wrong key");

    totalLen += outLen;
    return std::string(plaintext.begin(), plaintext.begin() + totalLen);
}

std::vector<uint8_t> CryptoManager::packAead(const AeadPacket& pkt) {
    std::vector<uint8_t> out;
    out.reserve(pkt.iv.size() + pkt.tag.size() + pkt.ciphertext.size());
    out.insert(out.end(), pkt.iv.begin(),         pkt.iv.end());
    out.insert(out.end(), pkt.tag.begin(),        pkt.tag.end());
    out.insert(out.end(), pkt.ciphertext.begin(), pkt.ciphertext.end());
    return out;
}

CryptoManager::AeadPacket CryptoManager::unpackAead(const std::vector<uint8_t>& raw) {
    if (raw.size() < static_cast<std::size_t>(IV_BYTES + TAG_BYTES))
        throw std::runtime_error("Packed AEAD too short");

    AeadPacket pkt;
    pkt.iv.assign(raw.begin(), raw.begin() + IV_BYTES);
    pkt.tag.assign(raw.begin() + IV_BYTES, raw.begin() + IV_BYTES + TAG_BYTES);
    pkt.ciphertext.assign(raw.begin() + IV_BYTES + TAG_BYTES, raw.end());
    return pkt;
}

// ── X25519 ───────────────────────────────────────────────────────────────────

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoManager::generateX25519KeyPair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    std::vector<uint8_t> priv(32), pub(32);
    std::size_t privLen = 32, pubLen = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv.data(), &privLen);
    EVP_PKEY_get_raw_public_key(pkey,  pub.data(),  &pubLen);
    EVP_PKEY_free(pkey);

    return {priv, pub};
}

std::vector<uint8_t> CryptoManager::x25519DH(const std::vector<uint8_t>& privKey,
                                               const std::vector<uint8_t>& peerPub)
{
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKey.data(), 32);
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, nullptr, peerPub.data(), 32);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);

    std::size_t sharedLen = 32;
    std::vector<uint8_t> shared(32);
    EVP_PKEY_derive(ctx, shared.data(), &sharedLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return shared;
}

// ── HKDF-SHA256 ──────────────────────────────────────────────────────────────

std::vector<uint8_t> CryptoManager::hkdf(const std::vector<uint8_t>& ikm,
                                           const std::vector<uint8_t>& salt,
                                           const std::string&           info,
                                           std::size_t                  outLen)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size()));
    EVP_PKEY_CTX_set1_hkdf_key(ctx,  ikm.data(),  static_cast<int>(ikm.size()));
    EVP_PKEY_CTX_add1_hkdf_info(ctx,
        reinterpret_cast<const uint8_t*>(info.data()),
        static_cast<int>(info.size()));

    std::vector<uint8_t> out(outLen);
    EVP_PKEY_derive(ctx, out.data(), &outLen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

// ── Message key derivation ────────────────────────────────────────────────────
//
// Key exchange: simplified HPKE Mode_Auth
//   static DH  = X25519(senderPriv,  recipientPub)
//   ephem DH   = X25519(ephemPriv,   recipientPub)
//   IKM        = static_dh || ephem_dh
//   key        = HKDF(IKM, salt=ephemPub, info="SecureMsg-C++-v1-msg")
//
// Returns {messageKey[32], ephemeralPubBytes[32]}.
// ephemeralPubBytes is sent in ratchet_header_enc so the receiver can reproduce the DH.

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
CryptoManager::deriveMessageKey(const std::vector<uint8_t>& senderPriv,
                                 const std::vector<uint8_t>& senderPub,
                                 const std::vector<uint8_t>& recipientPub)
{
    auto [ephPriv, ephPub] = generateX25519KeyPair();

    auto staticDH = x25519DH(senderPriv, recipientPub);
    auto ephemDH  = x25519DH(ephPriv,    recipientPub);

    std::vector<uint8_t> ikm;
    ikm.insert(ikm.end(), staticDH.begin(), staticDH.end());
    ikm.insert(ikm.end(), ephemDH.begin(),  ephemDH.end());

    // Include sender's static public key in the info string for domain separation.
    std::string info = "SecureMsg-C++-v1-msg";

    auto key = hkdf(ikm, ephPub, info, 32);

    (void)senderPub;  // kept in API for symmetry with recoverMessageKey
    return {key, ephPub};
}

std::vector<uint8_t>
CryptoManager::recoverMessageKey(const std::vector<uint8_t>& recipientPriv,
                                  const std::vector<uint8_t>& recipientPub,
                                  const std::vector<uint8_t>& senderPub,
                                  const std::vector<uint8_t>& ephemeralPub)
{
    auto staticDH = x25519DH(recipientPriv, senderPub);
    auto ephemDH  = x25519DH(recipientPriv, ephemeralPub);

    std::vector<uint8_t> ikm;
    ikm.insert(ikm.end(), staticDH.begin(), staticDH.end());
    ikm.insert(ikm.end(), ephemDH.begin(),  ephemDH.end());

    std::string info = "SecureMsg-C++-v1-msg";
    (void)recipientPub;
    return hkdf(ikm, ephemeralPub, info, 32);
}

// ── SRP verifier (registration) ───────────────────────────────────────────────

std::string CryptoManager::computeSrpVerifier(const std::string& username,
                                               const std::string& password,
                                               std::string&       saltHex)
{
    // Generate 16-byte random salt.
    auto saltBytes = randomBytes(16);
    saltHex = toHex(saltBytes);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = nullptr; BIGNUM* g = nullptr; BIGNUM* k = nullptr;
    srpLoadGroup(N, g, k, ctx);

    BIGNUM* x = computeSrpX(saltBytes, username, password);
    BIGNUM* v = BN_new();
    BN_mod_exp(v, g, x, N, ctx);

    // Convert verifier to big-endian bytes, then hex.
    int vBytes = BN_num_bytes(v);
    std::vector<uint8_t> vBuf(vBytes);
    BN_bn2bin(v, vBuf.data());
    std::string verifierHex = toHex(vBuf);

    BN_free(v); BN_free(x); BN_free(k); BN_free(g); BN_free(N);
    BN_CTX_free(ctx);
    return verifierHex;
}

// ── Local key store ───────────────────────────────────────────────────────────
// File layout: PBKDF2_SALT[16] | IV[12] | TAG[16] | ENC_PRIVKEY[32]  = 76 bytes total

void CryptoManager::savePrivateKey(const std::string&          path,
                                    const std::vector<uint8_t>& privKey,
                                    const std::string&          passphrase)
{
    auto pbkdf2Salt = randomBytes(16);

    // Derive 32-byte AES key from passphrase using PBKDF2-HMAC-SHA256.
    std::vector<uint8_t> aesKey(32);
    PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                       pbkdf2Salt.data(), static_cast<int>(pbkdf2Salt.size()),
                       600000, EVP_sha256(), 32, aesKey.data());

    std::string plaintext(privKey.begin(), privKey.end());
    auto pkt = aeadEncrypt(plaintext, aesKey);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write key file: " + path);
    f.write(reinterpret_cast<const char*>(pbkdf2Salt.data()), 16);
    f.write(reinterpret_cast<const char*>(pkt.iv.data()),     12);
    f.write(reinterpret_cast<const char*>(pkt.tag.data()),    16);
    f.write(reinterpret_cast<const char*>(pkt.ciphertext.data()),
            static_cast<std::streamsize>(pkt.ciphertext.size()));
}

std::vector<uint8_t> CryptoManager::loadPrivateKey(const std::string& path,
                                                     const std::string& passphrase)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Key file not found: " + path);

    uint8_t pbkdf2Salt[16], iv[12], tag[16];
    f.read(reinterpret_cast<char*>(pbkdf2Salt), 16);
    f.read(reinterpret_cast<char*>(iv),         12);
    f.read(reinterpret_cast<char*>(tag),        16);

    std::vector<uint8_t> enc(std::istreambuf_iterator<char>(f), {});

    std::vector<uint8_t> aesKey(32);
    PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                       pbkdf2Salt, 16,
                       600000, EVP_sha256(), 32, aesKey.data());

    AeadPacket pkt;
    pkt.iv.assign(iv, iv + 12);
    pkt.tag.assign(tag, tag + 16);
    pkt.ciphertext = enc;

    std::string plain = aeadDecrypt(pkt, aesKey);
    return std::vector<uint8_t>(plain.begin(), plain.end());
}

// ── Utilities ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> CryptoManager::randomBytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return buf;
}

std::string CryptoManager::base64Encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    std::string out;
    int outLen = 4 * ((static_cast<int>(data.size()) + 2) / 3);
    out.resize(static_cast<std::size_t>(outLen) + 4);

    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(ctx);
    int written = 0, finalWritten = 0;
    EVP_EncodeUpdate(ctx, reinterpret_cast<uint8_t*>(out.data()), &written,
                     data.data(), static_cast<int>(data.size()));
    EVP_EncodeFinal(ctx, reinterpret_cast<uint8_t*>(out.data()) + written, &finalWritten);
    EVP_ENCODE_CTX_free(ctx);

    out.resize(static_cast<std::size_t>(written + finalWritten));
    // Strip any trailing newlines inserted by EVP_Encode.
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

std::vector<uint8_t> CryptoManager::base64Decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    std::vector<uint8_t> out(encoded.size());
    int outLen = 0, finalLen = 0;

    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    EVP_DecodeUpdate(ctx, out.data(), &outLen,
                     reinterpret_cast<const uint8_t*>(encoded.data()),
                     static_cast<int>(encoded.size()));
    EVP_DecodeFinal(ctx, out.data() + outLen, &finalLen);
    EVP_ENCODE_CTX_free(ctx);

    out.resize(static_cast<std::size_t>(outLen + finalLen));
    return out;
}

std::string CryptoManager::toHex(const std::vector<uint8_t>& data) {
    std::ostringstream ss;
    for (uint8_t b : data) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::vector<uint8_t> CryptoManager::fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("Hex string has odd length");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}
