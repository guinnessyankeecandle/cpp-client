#include "User.hpp"
#include "Message.hpp"
#include "MessageStore.hpp"
#include "ApiClient.hpp"
#include "CryptoManager.hpp"
#include "Group.hpp"
#include "BlockchainManager.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <openssl/evp.h>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <ctime>
#include <filesystem>
#include <sstream>

using namespace ftxui;
namespace fs = std::filesystem;

static const std::string BASE_URL          = "https://BobbyTables.theburkenator.com";
static const std::string KEY_FILE          = "identity.key";
static const std::string BLOCKCHAIN_SCRIPT = "../blockchain/scripts/recordSegmentRoot.js";
static constexpr int     SEGMENT_SIZE      = 5;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string fmtTs(int64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%m-%d %H:%M", std::localtime(&t));
    return buf;
}

static std::string convId(int a, int b) {
    return "direct-" + std::to_string(std::min(a,b)) + "-" + std::to_string(std::max(a,b));
}

static std::vector<uint8_t> loadOrCreateKey(const std::string& pass,
                                             std::vector<uint8_t>& pubOut) {
    std::vector<uint8_t> priv;
    if (fs::exists(KEY_FILE)) {
        priv = CryptoManager::loadPrivateKey(KEY_FILE, pass);
    } else {
        auto [p, q] = CryptoManager::generateX25519KeyPair();
        priv = p; pubOut = q;
        CryptoManager::savePrivateKey(KEY_FILE, priv, pass);
        return priv;
    }
    EVP_PKEY* pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    std::size_t n = 32;
    pubOut.resize(32);
    EVP_PKEY_get_raw_public_key(pk, pubOut.data(), &n);
    EVP_PKEY_free(pk);
    return priv;
}

// ── Screen indices ────────────────────────────────────────────────────────────

static constexpr int SCR_WELCOME    = 0;
static constexpr int SCR_REGISTER   = 1;
static constexpr int SCR_LOGIN      = 2;
static constexpr int SCR_TOTP       = 3;
static constexpr int SCR_PASSPHRASE = 4;
static constexpr int SCR_MAIN       = 5;

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    auto screen = ScreenInteractive::Fullscreen();
    ApiClient api(BASE_URL, /*verifyTls=*/true);

    // ── Shared state ──────────────────────────────────────────────────────────
    int scr = SCR_WELCOME;

    // Auth inputs
    std::string regUser, regPass, regStatus;
    std::string loginUser, loginPass, loginStatus;
    std::string totpCode, totpStatus;
    std::string passStr, passStatus;
    std::string preAuthToken;
    SrpSession  srpSession;

    // Session
    std::string sessionUser, accessToken, refreshToken;
    int myUserId = 0;
    std::vector<uint8_t> myPriv, myPub;

    // Messages
    MessageStore store;
    std::vector<std::string> msgLines;
    std::string sendTo, sendText;
    std::string ackIdStr, revIdStr;

    // Groups
    int grpSubTab = 0;
    std::vector<std::string> grpListLines, grpMsgLines;
    std::string newGrpName, addGrpId, addMemId;
    std::string sndGrpId, sndGrpText;
    std::string fetchGrpId;
    std::string grpStatus;
    std::map<int, std::vector<uint8_t>> groupKeys;

    // Blockchain
    std::map<std::string, std::vector<MessageEnvelope>> segBuf;
    std::map<std::string, int> segIdx;
    std::vector<std::string> chainLines;
    std::string chainConvInput, chainStatus;

    // Main tab
    int mainTab = 0;
    const std::vector<std::string> mainTabNames = {
        " Messages ", " Groups ", " Blockchain ", " Account "
    };

    // Status bar
    std::string statusMsg;
    bool statusErr = false;

    // ── Lambda helpers ────────────────────────────────────────────────────────

    auto setStatus = [&](std::string msg, bool err = false) {
        statusMsg = std::move(msg); statusErr = err;
    };

    auto grpKey = [&](int gid) -> std::vector<uint8_t>& {
        if (!groupKeys.count(gid)) groupKeys[gid] = CryptoManager::randomBytes(32);
        return groupKeys[gid];
    };

    // ── Welcome ───────────────────────────────────────────────────────────────

    auto wBtn_login    = Button("  Login  ",    [&]{ scr = SCR_LOGIN; });
    auto wBtn_register = Button("  Register  ", [&]{ scr = SCR_REGISTER; });
    auto wBtn_quit     = Button("  Quit  ",     screen.ExitLoopClosure());

    auto welcome_comp = Renderer(
        Container::Vertical({wBtn_login, wBtn_register, wBtn_quit}),
        [&]{
            return vbox({
                filler(),
                hbox({filler(),
                    vbox({
                        text("  SecureMsg  ") | bold | center,
                        text(" End-to-end encrypted messaging ") | dim | center,
                        text(" " + BASE_URL + " ") | dim | center,
                        separator(),
                        text(""),
                        hbox({filler(),
                            wBtn_login->Render(),
                            text("  "),
                            wBtn_register->Render(),
                            filler()}),
                        text(""),
                        hbox({filler(), wBtn_quit->Render() | dim, filler()}),
                        text(""),
                    }) | border | size(WIDTH, GREATER_THAN, 48),
                filler()}),
                filler(),
            });
        }
    );

    // ── Register ──────────────────────────────────────────────────────────────

    auto rUser  = Input(&regUser, "username");
    InputOption rPassOpt; rPassOpt.password = true;
    auto rPass  = Input(&regPass, "password", rPassOpt);

    auto rBtn_submit = Button(" Register ", [&]{
        if (regUser.empty() || regPass.empty()) {
            regStatus = "Username and password required."; return;
        }
        try {
            regStatus = "Computing SRP verifier…";
            std::string saltHex;
            auto verifier = CryptoManager::computeSrpVerifier(regUser, regPass, saltHex);
            auto res = api.registerUser(regUser, saltHex, verifier);
            std::string msg = "Registered! User ID: " + std::to_string(res["user_id"].get<int>());
            if (res.contains("totp_provisioning_uri"))
                msg += "\n\nScan TOTP URI in authenticator:\n" +
                       res["totp_provisioning_uri"].get<std::string>();
            regStatus = msg;
        } catch (const std::exception& e) { regStatus = "Error: " + std::string(e.what()); }
    });
    auto rBtn_back = Button(" Back ", [&]{ scr = SCR_WELCOME; regStatus.clear(); });

    auto register_comp = Renderer(
        Container::Vertical({rUser, rPass, rBtn_submit, rBtn_back}),
        [&]{
            return vbox({filler(),
                hbox({filler(),
                    vbox({
                        text(" Register ") | bold | center,
                        separator(),
                        hbox({text(" Username : "), rUser->Render() | flex}),
                        separator(),
                        hbox({text(" Password : "), rPass->Render() | flex}),
                        separator(),
                        hbox({filler(), rBtn_submit->Render(), text("  "), rBtn_back->Render(), filler()}),
                        regStatus.empty() ? text("") :
                            paragraph(" " + regStatus) | color(
                                regStatus.rfind("Error", 0) == 0 ? Color::Red : Color::Green),
                    }) | border | size(WIDTH, GREATER_THAN, 52),
                filler()}),
            filler()});
        }
    );

    // ── Login ─────────────────────────────────────────────────────────────────

    auto lUser = Input(&loginUser, "username");
    InputOption lPassOpt; lPassOpt.password = true;
    auto lPass = Input(&loginPass, "password", lPassOpt);

    auto lBtn_submit = Button(" Login ", [&]{
        if (loginUser.empty() || loginPass.empty()) {
            loginStatus = "Username and password required."; return;
        }
        try {
            loginStatus = "Authenticating…";
            srpSession = SrpSession{};
            auto A = srpSession.begin(loginUser, loginPass);
            auto init   = api.srpInit(loginUser, A);
            auto verify = api.srpVerify(init["session_id"],
                srpSession.computeProof(init["srp_salt"], init["server_public"]));
            if (!srpSession.verifyServerProof(verify["server_proof"].get<std::string>())) {
                loginStatus = "ERROR: Server proof invalid — possible MITM!"; return;
            }
            preAuthToken = verify["pre_auth_token"].get<std::string>();
            sessionUser  = loginUser;
            loginStatus.clear();
            scr = SCR_TOTP;
        } catch (const std::exception& e) { loginStatus = "Error: " + std::string(e.what()); }
    });
    auto lBtn_back = Button(" Back ", [&]{ scr = SCR_WELCOME; loginStatus.clear(); });

    auto login_comp = Renderer(
        Container::Vertical({lUser, lPass, lBtn_submit, lBtn_back}),
        [&]{
            return vbox({filler(),
                hbox({filler(),
                    vbox({
                        text(" Login ") | bold | center,
                        separator(),
                        hbox({text(" Username : "), lUser->Render() | flex}),
                        separator(),
                        hbox({text(" Password : "), lPass->Render() | flex}),
                        separator(),
                        hbox({filler(), lBtn_submit->Render(), text("  "), lBtn_back->Render(), filler()}),
                        loginStatus.empty() ? text("") :
                            text(" " + loginStatus) | color(Color::Red),
                    }) | border | size(WIDTH, GREATER_THAN, 52),
                filler()}),
            filler()});
        }
    );

    // ── TOTP ──────────────────────────────────────────────────────────────────

    auto tCode = Input(&totpCode, "6-digit code");

    auto tBtn_verify = Button(" Verify ", [&]{
        if (totpCode.empty()) { totpStatus = "Enter your TOTP code."; return; }
        try {
            auto tokens  = api.verify2FA(preAuthToken, totpCode);
            accessToken  = tokens["access_token"].get<std::string>();
            refreshToken = tokens["refresh_token"].get<std::string>();
            totpCode.clear(); totpStatus.clear();
            scr = SCR_PASSPHRASE;
        } catch (const std::exception& e) { totpStatus = "Error: " + std::string(e.what()); }
    });

    auto totp_comp = Renderer(
        Container::Vertical({tCode, tBtn_verify}),
        [&]{
            return vbox({filler(),
                hbox({filler(),
                    vbox({
                        text(" Two-Factor Authentication ") | bold | center,
                        text(" Enter the 6-digit code from your authenticator app. ") | dim | center,
                        separator(),
                        hbox({text(" Code : "), tCode->Render() | flex}),
                        separator(),
                        hbox({filler(), tBtn_verify->Render(), filler()}),
                        totpStatus.empty() ? text("") :
                            text(" " + totpStatus) | color(Color::Red),
                    }) | border | size(WIDTH, GREATER_THAN, 48),
                filler()}),
            filler()});
        }
    );

    // ── Passphrase ────────────────────────────────────────────────────────────

    InputOption ppOpt; ppOpt.password = true;
    auto ppInput = Input(&passStr, "key passphrase", ppOpt);

    auto ppBtn = Button(" Continue ", [&]{
        if (passStr.empty()) { passStatus = "Passphrase required."; return; }
        try {
            myPriv = loadOrCreateKey(passStr, myPub);
            passStr.clear(); passStatus.clear();
            // Best-effort: look up our user ID if we already have a key bundle published.
            try {
                auto me = api.lookupByUsername(accessToken, sessionUser);
                myUserId = me["user_id"].get<int>();
            } catch (...) {}
            scr = SCR_MAIN;
            setStatus("Welcome, " + sessionUser + "!");
        } catch (const std::exception& e) { passStatus = "Error: " + std::string(e.what()); }
    });

    auto passphrase_comp = Renderer(
        Container::Vertical({ppInput, ppBtn}),
        [&]{
            return vbox({filler(),
                hbox({filler(),
                    vbox({
                        text(" Identity Key ") | bold | center,
                        text(" Enter your passphrase to unlock or create your identity key. ") | dim | center,
                        separator(),
                        hbox({text(" Passphrase : "), ppInput->Render() | flex}),
                        separator(),
                        hbox({filler(), ppBtn->Render(), filler()}),
                        passStatus.empty() ? text("") :
                            text(" " + passStatus) | color(Color::Red),
                    }) | border | size(WIDTH, GREATER_THAN, 52),
                filler()}),
            filler()});
        }
    );

    // ── Main — Messages tab ───────────────────────────────────────────────────

    auto mSendTo  = Input(&sendTo,  "user ID");
    auto mSendTxt = Input(&sendText, "type message here");
    auto mAckId   = Input(&ackIdStr, "msg ID");
    auto mRevId   = Input(&revIdStr, "msg ID");

    auto mBtn_fetch = Button(" Fetch ", [&]{
        try {
            setStatus("Fetching…");
            auto msgs = api.listMessages(accessToken);
            if (msgs.empty()) { setStatus("No new messages."); return; }
            std::unordered_map<int, std::vector<uint8_t>> keyCache;
            for (const auto& m : msgs) {
                int     id    = m["id"];
                int     sid   = m["sender_id"];
                int64_t ts    = m.value("sent_at", int64_t(0));
                auto    ct    = m["ciphertext"].get<std::string>();
                auto    hdr   = m["ratchet_header_enc"].get<std::string>();
                std::string plain;
                try {
                    if (!keyCache.count(sid)) {
                        auto kb = api.getKeyBundle(accessToken, sid);
                        keyCache[sid] = CryptoManager::base64Decode(
                            kb["identity_pub"].get<std::string>());
                    }
                    auto ep  = CryptoManager::base64Decode(hdr);
                    auto key = CryptoManager::recoverMessageKey(myPriv, myPub, keyCache[sid], ep);
                    auto pkt = CryptoManager::unpackAead(CryptoManager::base64Decode(ct));
                    plain    = CryptoManager::aeadDecrypt(pkt, key);
                } catch (const std::exception& e) {
                    plain = "[decrypt failed: " + std::string(e.what()) + "]";
                }
                Message msg(id, sid, 0, ct, hdr, ts, Message::Direction::Received);
                msg.setPlaintext(plain);
                store.addMessage(msg);
                std::ostringstream line;
                line << "[" << id << "] uid:" << sid << "  " << fmtTs(ts) << "  " << plain;
                msgLines.push_back(line.str());
                // Buffer for blockchain
                std::string cid = convId(sid, myUserId);
                MessageEnvelope env;
                env.conversationId   = cid;
                env.messageId        = std::to_string(id);
                env.senderId         = std::to_string(sid);
                env.recipientId      = std::to_string(myUserId);
                env.ciphertext       = ct;
                env.ratchetHeaderEnc = hdr;
                env.sentAt           = ts;
                segBuf[cid].push_back(env);
            }
            setStatus("Fetched " + std::to_string(msgs.size()) + " message(s).");
        } catch (const std::exception& e) { setStatus("Fetch error: " + std::string(e.what()), true); }
    });

    auto mBtn_send = Button(" Send ", [&]{
        if (sendTo.empty() || sendText.empty()) {
            setStatus("Enter recipient ID and message.", true); return;
        }
        try {
            int rid      = std::stoi(sendTo);
            auto bundle  = api.getKeyBundle(accessToken, rid);
            auto rPub    = CryptoManager::base64Decode(bundle["identity_pub"].get<std::string>());
            auto [mk,ep] = CryptoManager::deriveMessageKey(myPriv, myPub, rPub);
            auto pkt     = CryptoManager::aeadEncrypt(sendText, mk);
            auto packed  = CryptoManager::packAead(pkt);
            auto resp    = api.sendMessage(accessToken, rid,
                               CryptoManager::base64Encode(packed),
                               CryptoManager::base64Encode(ep));
            int rid2 = resp["id"].get<int>();
            msgLines.push_back("[" + std::to_string(rid2) + "] SENT → uid:" +
                               sendTo + "  " + sendText);
            sendText.clear();
            setStatus("Sent (ID: " + std::to_string(rid2) + ").");
        } catch (const std::exception& e) { setStatus("Send error: " + std::string(e.what()), true); }
    });

    auto mBtn_ack = Button(" Ack ", [&]{
        try {
            api.acknowledgeReceipt(accessToken, std::stoi(ackIdStr));
            store.removeById(std::stoi(ackIdStr));
            setStatus("Acknowledged " + ackIdStr + ".");
            ackIdStr.clear();
        } catch (const std::exception& e) { setStatus("Ack error: " + std::string(e.what()), true); }
    });

    auto mBtn_revoke = Button(" Revoke ", [&]{
        try {
            api.revokeMessage(accessToken, std::stoi(revIdStr), "");
            setStatus("Revoked " + revIdStr + ".");
            revIdStr.clear();
        } catch (const std::exception& e) { setStatus("Revoke error: " + std::string(e.what()), true); }
    });

    auto messages_tab = Renderer(
        Container::Vertical({mSendTo, mSendTxt, mBtn_fetch, mBtn_send,
                             mAckId, mBtn_ack, mRevId, mBtn_revoke}),
        [&]{
            Elements lines;
            for (const auto& l : msgLines) lines.push_back(text(l));
            if (lines.empty())
                lines.push_back(text("No messages — press Fetch to load.") | dim);
            return vbox({
                vbox(std::move(lines)) | yframe | flex,
                separator(),
                hbox({text(" To: "), mSendTo->Render() | size(WIDTH, EQUAL, 8),
                      text("  "), mSendTxt->Render() | flex,
                      text("  "), mBtn_send->Render(),
                      text("  "), mBtn_fetch->Render()}),
                hbox({text(" Ack: "),    mAckId->Render()  | size(WIDTH, EQUAL, 6),
                      text("  "), mBtn_ack->Render(),
                      text("    Revoke: "), mRevId->Render() | size(WIDTH, EQUAL, 6),
                      text("  "), mBtn_revoke->Render(), filler()}),
            });
        }
    );

    // ── Main — Groups tab ─────────────────────────────────────────────────────

    const std::vector<std::string> grpSubNames = {
        " List ", " Create ", " Add Member ", " Send ", " Fetch Msgs "
    };
    auto grpToggle = Toggle(&grpSubNames, &grpSubTab);

    auto gNameIn   = Input(&newGrpName, "group name");
    auto gGrpIdIn  = Input(&addGrpId,   "group ID");
    auto gMemIdIn  = Input(&addMemId,   "user ID");
    auto gSndGrpIn = Input(&sndGrpId,   "group ID");
    auto gSndTxtIn = Input(&sndGrpText, "message");
    auto gFetchIn  = Input(&fetchGrpId, "group ID");

    auto gBtn_list = Button(" Refresh ", [&]{
        try {
            auto resp = api.listGroups(accessToken);
            auto gs   = resp.value("groups", nlohmann::json::array());
            grpListLines.clear();
            for (const auto& g : gs)
                grpListLines.push_back(
                    "[" + std::to_string(g["id"].get<int>()) + "] " +
                    g["name"].get<std::string>() +
                    "  members:" + std::to_string(g["members"].size()) +
                    "  epoch:"   + std::to_string(g.value("epoch", 0)));
            grpStatus = "Loaded " + std::to_string(gs.size()) + " group(s).";
        } catch (const std::exception& e) { grpStatus = "Error: " + std::string(e.what()); }
    });

    auto gBtn_create = Button(" Create ", [&]{
        try {
            auto r = api.createGroup(accessToken, newGrpName);
            grpStatus = "Created group ID: " + std::to_string(r["id"].get<int>());
            newGrpName.clear();
        } catch (const std::exception& e) { grpStatus = "Error: " + std::string(e.what()); }
    });

    auto gBtn_addMem = Button(" Add Member ", [&]{
        try {
            int gid = std::stoi(addGrpId), uid = std::stoi(addMemId);
            auto bundle  = api.getKeyBundle(accessToken, uid);
            auto mPub    = CryptoManager::base64Decode(bundle["identity_pub"].get<std::string>());
            auto& sk     = grpKey(gid);
            auto [mk,ep] = CryptoManager::deriveMessageKey(myPriv, myPub, mPub);
            auto pkt     = CryptoManager::aeadEncrypt(std::string(sk.begin(), sk.end()), mk);
            auto packed  = CryptoManager::packAead(pkt);
            std::vector<uint8_t> payload;
            payload.insert(payload.end(), ep.begin(), ep.end());
            payload.insert(payload.end(), packed.begin(), packed.end());
            api.addGroupMember(accessToken, gid, uid, CryptoManager::base64Encode(payload));
            grpStatus = "Added user " + addMemId + " to group " + addGrpId;
            addMemId.clear();
        } catch (const std::exception& e) { grpStatus = "Error: " + std::string(e.what()); }
    });

    auto gBtn_send = Button(" Send ", [&]{
        try {
            int gid   = std::stoi(sndGrpId);
            auto& sk  = grpKey(gid);
            auto pkt  = CryptoManager::aeadEncrypt(sndGrpText, sk);
            auto gi   = api.getGroup(accessToken, gid);
            auto resp = api.sendGroupMessage(accessToken, gid, gi.value("epoch", 0),
                            CryptoManager::base64Encode(CryptoManager::packAead(pkt)));
            grpStatus = "Group message sent (ID: " + std::to_string(resp["id"].get<int>()) + ")";
            sndGrpText.clear();
        } catch (const std::exception& e) { grpStatus = "Error: " + std::string(e.what()); }
    });

    auto gBtn_fetch = Button(" Fetch ", [&]{
        try {
            int gid   = std::stoi(fetchGrpId);
            auto msgs = api.listGroupMessages(accessToken, gid);
            auto& sk  = grpKey(gid);
            grpMsgLines.clear();
            for (const auto& m : msgs) {
                std::string plain;
                try {
                    auto pkt = CryptoManager::unpackAead(
                        CryptoManager::base64Decode(m["ciphertext"].get<std::string>()));
                    plain = CryptoManager::aeadDecrypt(pkt, sk);
                } catch (...) { plain = "[decrypt failed]"; }
                grpMsgLines.push_back("[" + std::to_string(m["id"].get<int>()) + "] " + plain);
            }
            grpStatus = "Fetched " + std::to_string(msgs.size()) + " message(s).";
        } catch (const std::exception& e) { grpStatus = "Error: " + std::string(e.what()); }
    });

    auto grpListTab   = Renderer(Container::Vertical({gBtn_list}), [&]{
        Elements ls; for (auto& l : grpListLines) ls.push_back(text(l));
        if (ls.empty()) ls.push_back(text("No groups — press Refresh.") | dim);
        return vbox({vbox(std::move(ls)) | flex, separator(), hbox({gBtn_list->Render(), filler()})});
    });
    auto grpCreateTab = Renderer(Container::Vertical({gNameIn, gBtn_create}), [&]{
        return vbox({hbox({text(" Name: "), gNameIn->Render() | flex}), separator(),
                     hbox({filler(), gBtn_create->Render(), filler()})});
    });
    auto grpAddTab    = Renderer(Container::Vertical({gGrpIdIn, gMemIdIn, gBtn_addMem}), [&]{
        return vbox({hbox({text(" Group ID : "), gGrpIdIn->Render() | size(WIDTH, EQUAL, 6)}),
                     hbox({text(" User ID  : "), gMemIdIn->Render() | size(WIDTH, EQUAL, 6)}),
                     separator(), hbox({filler(), gBtn_addMem->Render(), filler()})});
    });
    auto grpSendTab   = Renderer(Container::Vertical({gSndGrpIn, gSndTxtIn, gBtn_send}), [&]{
        return vbox({hbox({text(" Group ID : "), gSndGrpIn->Render() | size(WIDTH, EQUAL, 6)}),
                     hbox({text(" Message  : "), gSndTxtIn->Render() | flex}),
                     separator(), hbox({filler(), gBtn_send->Render(), filler()})});
    });
    auto grpFetchTab  = Renderer(Container::Vertical({gFetchIn, gBtn_fetch}), [&]{
        Elements ls; for (auto& l : grpMsgLines) ls.push_back(text(l));
        if (ls.empty()) ls.push_back(text("No messages fetched.") | dim);
        return vbox({vbox(std::move(ls)) | flex, separator(),
                     hbox({text(" Group ID: "), gFetchIn->Render() | size(WIDTH, EQUAL, 6),
                           text("  "), gBtn_fetch->Render()})});
    });

    auto grpSubContent = Container::Tab(
        {grpListTab, grpCreateTab, grpAddTab, grpSendTab, grpFetchTab}, &grpSubTab);

    auto groups_tab = Renderer(Container::Vertical({grpToggle, grpSubContent}), [&]{
        return vbox({grpToggle->Render(), separator(), grpSubContent->Render() | flex, separator(),
                     text(" " + grpStatus) | color(Color::Yellow)});
    });

    // ── Main — Blockchain tab ─────────────────────────────────────────────────

    auto cConvIn = Input(&chainConvInput, "e.g. direct-1-2");

    auto cBtn_refresh = Button(" Refresh ", [&]{
        chainLines.clear();
        if (segBuf.empty()) { chainStatus = "No segments buffered — fetch messages first."; return; }
        for (const auto& [cid, msgs] : segBuf) {
            int cnt = static_cast<int>(msgs.size());
            std::string tag = (cnt >= SEGMENT_SIZE) ? " ● READY" : "";
            chainLines.push_back(cid + "  " + std::to_string(cnt) + " msg(s)" + tag);
        }
        chainStatus = std::to_string(segBuf.size()) + " conversation(s) buffered.";
    });

    auto cBtn_record = Button(" Record Segment ", [&]{
        if (chainConvInput.empty()) { chainStatus = "Enter a conversation ID."; return; }
        auto it = segBuf.find(chainConvInput);
        if (it == segBuf.end()) { chainStatus = "Conversation not in buffer."; return; }
        auto& buf = it->second;
        std::vector<MessageEnvelope> seg(buf.begin(),
            buf.begin() + std::min((int)buf.size(), SEGMENT_SIZE));
        std::sort(seg.begin(), seg.end(), [](const auto& a, const auto& b){
            return a.sentAt != b.sentAt ? a.sentAt < b.sentAt : a.messageId < b.messageId;
        });
        int idx   = ++segIdx[chainConvInput];
        auto proof = BlockchainManager::buildSegmentProof(seg, chainConvInput, idx);
        try {
            auto f = BlockchainManager::writeSegmentFile(seg, proof);
            chainStatus = "Root: " + proof.segmentRoot.substr(0, 22) + "…";
            chainLines.push_back("Segment: " + proof.segmentRef +
                                 "  msgs: " + std::to_string(proof.messageCount));
            chainLines.push_back("Run to record: node " + std::string(BLOCKCHAIN_SCRIPT) + " " + f);
            buf.erase(buf.begin(), buf.begin() + (ptrdiff_t)seg.size());
        } catch (const std::exception& e) { chainStatus = "Error: " + std::string(e.what()); }
    });

    auto blockchain_tab = Renderer(
        Container::Vertical({cConvIn, cBtn_refresh, cBtn_record}),
        [&]{
            Elements ls; for (auto& l : chainLines) ls.push_back(text(l));
            if (ls.empty()) ls.push_back(text("Press Refresh to see buffered conversations.") | dim);
            return vbox({
                vbox(std::move(ls)) | flex,
                separator(),
                hbox({cBtn_refresh->Render(), filler()}),
                separator(),
                hbox({text(" Conv: "), cConvIn->Render() | flex,
                      text("  "), cBtn_record->Render()}),
                text(" " + chainStatus) | color(Color::Cyan),
            });
        }
    );

    // ── Main — Account tab ────────────────────────────────────────────────────

    auto aBtn_pubKey = Button(" Publish Key ", [&]{
        try {
            std::string b64 = CryptoManager::base64Encode(myPub);
            api.publishKeyBundle(accessToken, {
                {"identity_pub",      b64}, {"signed_prekey_pub", b64},
                {"signed_prekey_sig", b64}, {"one_time_prekeys",  nlohmann::json::array()},
                {"pq_prekey_pub",     b64}, {"pq_prekey_sig",     b64}
            });
            auto me = api.lookupByUsername(accessToken, sessionUser);
            myUserId = me["user_id"].get<int>();
            setStatus("Public key published. User ID: " + std::to_string(myUserId));
        } catch (const std::exception& e) { setStatus("Error: " + std::string(e.what()), true); }
    });

    auto aBtn_logout = Button(" Logout ", [&]{
        try { api.logout(refreshToken); } catch (...) {}
        accessToken.clear(); refreshToken.clear(); myPriv.clear(); myPub.clear(); myUserId = 0;
        msgLines.clear(); grpListLines.clear(); grpMsgLines.clear();
        chainLines.clear(); segBuf.clear(); store.clear();
        scr = SCR_WELCOME;
        setStatus("Logged out.");
    });

    auto account_tab = Renderer(Container::Vertical({aBtn_pubKey, aBtn_logout}), [&]{
        std::string fp = myPub.empty() ? "—" : CryptoManager::toHex(myPub).substr(0, 16) + "…";
        return vbox({
            text(""),
            hbox({text("  Username  : "), text(sessionUser) | bold}),
            hbox({text("  User ID   : "), text(myUserId ? std::to_string(myUserId) : "— (publish key to resolve)") | dim}),
            hbox({text("  Key ID    : "), text(fp) | dim}),
            hbox({text("  Cached    : "), text(std::to_string(store.size()) + " messages") | dim}),
            text(""),
            separator(),
            text(""),
            hbox({text("  "), aBtn_pubKey->Render()}),
            text(""),
            hbox({text("  "), aBtn_logout->Render() | color(Color::Red)}),
            filler(),
        });
    });

    // ── Main (tabbed) ─────────────────────────────────────────────────────────

    auto mainToggle  = Toggle(&mainTabNames, &mainTab);
    auto mainContent = Container::Tab(
        {messages_tab, groups_tab, blockchain_tab, account_tab}, &mainTab);

    auto main_comp = Renderer(
        Container::Vertical({mainToggle, mainContent}),
        [&]{
            return vbox({
                hbox({
                    text(" SecureMsg ") | bold | color(Color::Cyan),
                    text("· "),
                    text(sessionUser) | bold,
                    text("  "),
                    text(std::to_string(store.size()) + " msgs cached") | dim,
                    filler(),
                }),
                separator(),
                mainToggle->Render(),
                separator(),
                mainContent->Render() | flex,
                separator(),
                hbox({text("  "),
                      text(statusMsg) | (statusErr ? color(Color::Red) : color(Color::Green))}),
            });
        }
    );

    // ── Root container ────────────────────────────────────────────────────────

    auto root = Container::Tab({
        welcome_comp,
        register_comp,
        login_comp,
        totp_comp,
        passphrase_comp,
        main_comp
    }, &scr);

    screen.Loop(root);
    return 0;
}
