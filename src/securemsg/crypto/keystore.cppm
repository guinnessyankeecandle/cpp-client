module;
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <cstdint>
#include <string>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <unordered_map>
#include <array>
export module securemsg.crypto.keystore;
import securemsg.crypto.random;
import securemsg.crypto.aead;
import securemsg.crypto.kdf;
import securemsg.crypto.ed25519;
import securemsg.crypto.x25519;
import securemsg.crypto.mlkem;

export struct KeyBundle {
    Ed25519KeyPair             ik;
    X25519KeyPair              spk;
    std::vector<uint8_t>       spkSig;
    MlKemKeyPair               pq;
    std::vector<uint8_t>       pqSig;
    std::vector<X25519KeyPair> opks;
};

export struct Identity {
    std::string          username;
    std::vector<uint8_t> identityPub;
    bool                 verified{false};
};

static constexpr int     PBKDF2_ITERATIONS        = 600000;
static constexpr int     PBKDF2_SALT_BYTES         = 16;
static constexpr int     OPK_BATCH_SIZE            = 20;

export KeyBundle keystoreGenerate() {
    KeyBundle kb;
    kb.ik     = ed25519Generate();
    kb.spk    = x25519Generate();
    kb.spkSig = ed25519Sign(kb.ik.priv, kb.spk.pub);
    kb.pq     = mlkemGenerate();
    kb.pqSig  = ed25519Sign(kb.ik.priv, kb.pq.pub);
    kb.opks.reserve(OPK_BATCH_SIZE);
    for (int i = 0; i < OPK_BATCH_SIZE; ++i)
        kb.opks.push_back(x25519Generate());
    return kb;
}

export void keystoreSave(const std::string& path,
                          const KeyBundle&   kb,
                          const std::string& password) {
    std::vector<uint8_t> payload;
    auto append = [&](const std::vector<uint8_t>& v) {
        payload.insert(payload.end(), v.begin(), v.end());
    };
    append(kb.ik.priv); append(kb.ik.pub);
    append(kb.spk.priv); append(kb.spk.pub); append(kb.spkSig);
    append(kb.pq.priv);  append(kb.pq.pub);  append(kb.pqSig);

    uint32_t opkCount = static_cast<uint32_t>(kb.opks.size());
    for (int i = 3; i >= 0; --i)
        payload.push_back((opkCount >> (i*8)) & 0xFF);
    for (const auto& opk : kb.opks) { append(opk.priv); append(opk.pub); }

    auto salt   = randomBytes(PBKDF2_SALT_BYTES);
    auto encKey = pbkdf2(password, salt, PBKDF2_ITERATIONS, KEY_BYTES);
    auto pkt    = aeadEncrypt(payload, encKey);
    OPENSSL_cleanse(encKey.data(), encKey.size());
    OPENSSL_cleanse(payload.data(), payload.size());

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot open key file for writing: " + path);
    f.write(reinterpret_cast<const char*>(salt.data()), PBKDF2_SALT_BYTES);
    auto packed = packAead(pkt);
    f.write(reinterpret_cast<const char*>(packed.data()),
            static_cast<std::streamsize>(packed.size()));
}

export KeyBundle keystoreLoad(const std::string& path,
                               const std::string& password) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Key file not found: " + path);

    std::array<uint8_t, PBKDF2_SALT_BYTES> salt{};
    f.read(reinterpret_cast<char*>(salt.data()), PBKDF2_SALT_BYTES);

    std::vector<uint8_t> rest((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());

    auto encKey  = pbkdf2(password, {salt.begin(), salt.end()},
                          PBKDF2_ITERATIONS, KEY_BYTES);
    auto pkt     = unpackAead(rest);
    auto payload = aeadDecrypt(pkt, encKey);
    OPENSSL_cleanse(encKey.data(), encKey.size());

    std::size_t off = 0;
    auto read = [&](std::size_t n) {
        if (off + n > payload.size())
            throw std::runtime_error("Key file truncated");
        std::vector<uint8_t> v(payload.begin() + off, payload.begin() + off + n);
        off += n;
        return v;
    };

    KeyBundle kb;
    kb.ik.priv  = read(32); kb.ik.pub  = read(32);
    kb.spk.priv = read(32); kb.spk.pub = read(32); kb.spkSig = read(64);

    // ML-KEM-1024 FIPS 203: decapsulation key 3168 bytes, encapsulation key 1568 bytes
    kb.pq.priv  = read(3168); kb.pq.pub = read(1568); kb.pqSig = read(64);

    uint32_t opkCount = 0;
    auto countBytes = read(4);
    for (int i = 0; i < 4; ++i)
        opkCount = (opkCount << 8) | countBytes[i];
    kb.opks.reserve(opkCount);
    for (uint32_t i = 0; i < opkCount; ++i) {
        X25519KeyPair opk;
        opk.priv = read(32); opk.pub = read(32);
        kb.opks.push_back(std::move(opk));
    }

    OPENSSL_cleanse(payload.data(), payload.size());
    return kb;
}

export void identityCacheSave(
        const std::string&                            path,
        const std::unordered_map<int32_t, Identity>& cache) {
    nlohmann::json j;
    for (const auto& [id, identity] : cache) {
        j[std::to_string(id)] = {
            {"username",     identity.username},
            {"identity_pub", base64Encode(identity.identityPub)},
            {"verified",     identity.verified}
        };
    }
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write identity cache: " + path);
    f << j.dump(2);
}

export std::unordered_map<int32_t, Identity> identityCacheLoad(const std::string& path) {
    std::unordered_map<int32_t, Identity> cache;
    if (!std::filesystem::exists(path)) return cache;
    std::ifstream f(path);
    auto j = nlohmann::json::parse(f);
    for (auto& [key, val] : j.items()) {
        int32_t id = std::stoi(key);
        Identity ident;
        ident.username    = val.value("username", "");
        ident.identityPub = base64Decode(val.value("identity_pub", ""));
        ident.verified    = val.value("verified", false);
        cache[id]         = std::move(ident);
    }
    return cache;
}
