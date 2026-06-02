#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <mutex>
#include <openssl/crypto.h>
#include <ranges>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "BlockchainManager.hpp"
import securemsg.models;
import securemsg.crypto;
import securemsg.messaging;
import securemsg.network;
import securemsg.main_logic;

using namespace ftxui;

static constexpr int DIALOG_MIN_WIDTH = 52;
static constexpr const char *DELETE_LABEL = " \U0001f5d1 ";
static constexpr int MAIN_PANEL_MIN_WIDTH = 60;
static constexpr int INPUT_LINE_HEIGHT = 1;

enum class AppScreen { Welcome, Register, Login, Main };

struct AppState {
  AppScreen screen{AppScreen::Welcome};

  std::string regUsername, regPassword, regStatus;
  bool regShowTotp{false};
  std::string regTotpUri, regTotpCode, regTotpStatus;

  std::string loginUsername, loginPassword, loginStatus;
  bool loginShowTotp{false};
  std::string loginPreAuthToken, loginTotpCode, loginTotpStatus;
  int32_t pendingUserId{-1};

  std::optional<LocalUser> localUser;

  RatchetMap ratchets;
  GroupRatchetMap groupRatchets;
  GroupSenderKeys groupSenderKeys;
  SkdmEpochTracker skdmTracker;

  std::vector<Contact> contactCache;
  std::vector<Contact> contacts;
  std::vector<Group> groups;
  int32_t selectedContactId{-1};
  int32_t selectedGroupId{-1};
  bool viewingGroup{false};
  std::optional<MessageStore> messageStore;
  std::string composeText;

  int32_t selectedMsgId{-1};
  std::string statusMsg;
  bool msgsDirty{false};

  std::unordered_map<int32_t, int32_t> knownGroupEpochs;

  bool showIdentityOverlay{false};
  std::string overlayTargetName;
  std::string overlayKeyB64;
  bool overlayVerified{false};

  // Blockchain
  bool showBlockchainOverlay{false};
  std::string chainStatus;
  std::string chainVerifyInput;
  std::string chainVerifyResult;
  std::vector<MessageEnvelope> chainLastEnvs;
  SegmentDigest chainDigest;
  int chainSegIdx{0};

  std::unique_ptr<struct Poller> poller;
  std::mutex stateMutex;        // guards Poller→UI writes: contacts and groups
  std::mutex messageMutex;      // guards ratchets, groupRatchets, messageStore
  std::mutex usernameCacheMutex; // guards usernameCache — never held while acquiring the above
  std::unordered_map<int32_t, std::string> usernameCache; // id → username, safe for all threads

  std::shared_ptr<std::vector<std::string>> allLabels =
      std::make_shared<std::vector<std::string>>();
  std::shared_ptr<std::vector<std::string>> msgLabels =
      std::make_shared<std::vector<std::string>>();
  std::shared_ptr<std::vector<int32_t>> msgIds =
      std::make_shared<std::vector<int32_t>>();
  std::shared_ptr<std::vector<bool>> msgSent =
      std::make_shared<std::vector<bool>>();
  std::string addContactUsername;
  std::string newGroupName;
  bool creatingGroup{false};
  std::set<int32_t> selectedGroupMembers;
  std::string addGroupMemberUsername;
  int32_t selectedMemberIndex{-1};
  int menuSelected{-1}; // -1 = nothing selected; first click always fires on_change
  int msgSelected{0};
  int splitPos{32};
  int tabIdx{0};
};

// ── Shared helpers ────────────────────────────────────────────────────────────

static void appendLog(const std::string &msg) {
  std::ofstream("securemsg.log", std::ios::app) << msg;
}

// Input that strips newlines on every event.
static Component noNewlineInput(std::string *str, const std::string &placeholder,
                                InputOption opts = {}) {
  auto inp = Input(str, placeholder, opts);
  inp |= CatchEvent([str](const Event &) { std::erase(*str, '\n'); return false; });
  return inp;
}

// Input that keeps only digit characters.
static Component digitOnlyInput(std::string *str, const std::string &placeholder) {
  auto inp = Input(str, placeholder);
  inp |= CatchEvent([str](const Event &) {
    std::erase_if(*str, [](const char c) { return !std::isdigit(c); });
    return false;
  });
  return inp;
}

// Centers a dialog box with a border and minimum width.
static Element centeredDialog(Elements body, const int minWidth = DIALOG_MIN_WIDTH) {
  return vbox({filler(),
               hbox({filler(),
                     vbox(std::move(body)) | border | size(WIDTH, GREATER_THAN, minWidth),
                     filler()}),
               filler()});
}

// Horizontally centered row of rendered buttons separated by spaces.
static Element btnRow(std::vector<Element> btns) {
  Elements elems{filler()};
  for (std::size_t i = 0; i < btns.size(); ++i) {
    if (i > 0) elems.push_back(text("  "));
    elems.push_back(std::move(btns[i]));
  }
  elems.push_back(filler());
  return hbox(std::move(elems));
}

// Labeled single-line input row.
static Element labeledInput(const std::string &label, const Component &inp) {
  return hbox({text(label),
               inp->Render() | flex | size(HEIGHT, EQUAL, INPUT_LINE_HEIGHT)});
}

// ── QR / key bundle helpers ───────────────────────────────────────────────────

struct PipeDeleter {
  void operator()(FILE *f) const { pclose(f); }
};
using PipePtr = std::unique_ptr<FILE, PipeDeleter>;

static Element qrElement(const std::string &uri) {
  const auto pipe =
      PipePtr(popen(("qrencode -t UTF8 -o - -- '" + uri + "'").c_str(), "r"));
  if (!pipe)
    return paragraph(" Install qrencode: sudo dnf install qrencode ") |
           color(Color::Red);

  std::string out;
  std::array<char, 256> buf{};
  while (fgets(buf.data(), buf.size(), pipe.get()))
    out += buf.data();

  if (out.empty())
    return paragraph(" qrencode failed ") | color(Color::Red);

  Elements rows;
  std::istringstream ss(out);
  std::string line;
  while (std::getline(ss, line))
    rows.push_back(text(line));
  return vbox(std::move(rows));
}

static void publishBundle(const ApiClient &api, const LocalUser &user) {
  const auto &kb = user.getKeyBundle();
  std::vector<std::string> opkPubs;
  opkPubs.reserve(kb.opks.size());
  std::ranges::transform(kb.opks, std::back_inserter(opkPubs),
                         [](const auto &k) { return base64Encode(k.pub); });
  api.publishKeyBundle(user.getAccessToken(), base64Encode(kb.ik.pub),
                       base64Encode(kb.ikX.pub), base64Encode(kb.ikXSig),
                       base64Encode(kb.spk.pub), base64Encode(kb.spkSig),
                       opkPubs, base64Encode(kb.pq.pub),
                       base64Encode(kb.pqSig));
}

// ── Welcome screen ────────────────────────────────────────────────────────────

Component makeWelcomeScreen(AppState &state, ScreenInteractive &scr) {
  auto btnRegister = Button(" Register ", [&] {
    state.screen = AppScreen::Register;
    scr.PostEvent(Event::Custom);
  });
  auto btnLogin = Button(" Login ", [&] {
    state.screen = AppScreen::Login;
    scr.PostEvent(Event::Custom);
  });

  return Renderer(
      Container::Horizontal({btnRegister, btnLogin}),
      [&, btnRegister, btnLogin] {
        return centeredDialog({
            text(" SecureMsg ") | bold | center,
            text(" Signal Protocol + Post-Quantum E2E Encryption ") | dim | center,
            separator(),
            btnRow({btnRegister->Render(), btnLogin->Render()}),
        });
      });
}

// ── Register screen ───────────────────────────────────────────────────────────

Component makeRegisterScreen(AppState &state, ScreenInteractive &scr,
                             const ApiClient &api) {
  auto rUser = noNewlineInput(&state.regUsername, "username");
  auto rPass = noNewlineInput(&state.regPassword, "password",
                              InputOption{.transform = {}, .password = true});
  auto tCode = digitOnlyInput(&state.regTotpCode, "6-digit code");

  auto btnSubmit = Button(" Register ", [&] {
    if (state.regUsername.empty() || state.regPassword.empty()) {
      state.regStatus = "Username and password required.";
      return;
    }
    try {
      state.regStatus = "Computing SRP verifier...";
      std::string saltHex;
      const auto verifier = SrpSession::computeVerifier(
          state.regUsername, state.regPassword, saltHex);
      auto res = api.registerUser(state.regUsername, saltHex, verifier);
      state.pendingUserId = res.at("user_id").get<int32_t>();
      if (res.contains("totp_provisioning_uri"))
        state.regTotpUri = res["totp_provisioning_uri"].get<std::string>();

      SrpSession srp;
      auto init = api.srpInit(state.regUsername);
      const auto [clientPublic, clientProof] =
          srp.computeProof(state.regUsername, state.regPassword,
                           init["srp_salt"], init["server_public"]);
      auto verify =
          api.srpVerify(init["session_id"], clientPublic, clientProof);
      if (!srp.verifyServerProof(verify["server_proof"].get<std::string>())) {
        state.regStatus = "Server proof invalid.";
        return;
      }
      state.loginPreAuthToken = verify["pre_auth_token"].get<std::string>();
      state.regStatus = "Registered! Scan the QR code with your authenticator.";
      state.regShowTotp = true;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.regStatus = std::string("Error: ") + e.what();
    }
  });

  auto btnVerifyTotp = Button(" Verify ", [&] {
    if (state.regTotpCode.empty()) {
      state.regTotpStatus = "Enter the 6-digit code.";
      return;
    }
    if (state.regTotpStatus == "Verifying...")
      return;
    state.regTotpStatus = "Verifying...";
    scr.PostEvent(Event::Custom);
    std::thread([&] {
      try {
        appendLog("[reg] verify2FA start\n");
        auto tokens = api.verify2FA(state.loginPreAuthToken, state.regTotpCode);
        appendLog("[reg] LocalUser start\n");
        state.localUser.emplace(state.pendingUserId, state.regUsername,
                                tokens["access_token"].get<std::string>(),
                                tokens["refresh_token"].get<std::string>(),
                                ("identity_" + state.regUsername + ".key"),
                                state.regPassword);
        appendLog("[reg] publishBundle start\n");
        publishBundle(api, *state.localUser);
        appendLog("[reg] MessageStore start\n");
        std::filesystem::remove("messages.db");
        state.messageStore =
            MessageStore("messages_" + state.loginUsername + ".db",
                         state.localUser->getDbKey());
        state.regShowTotp = false;
        state.regTotpUri.clear();
        state.screen = AppScreen::Main;
        appendLog("[reg] done\n");
      } catch (const std::exception &e) {
        state.regTotpStatus = std::string("Error: ") + e.what();
        appendLog("[reg] exception: " + std::string(e.what()) + "\n");
      }
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  auto btnBack = Button(" Back ", [&] {
    state.screen = AppScreen::Welcome;
    state.regStatus.clear();
    state.regTotpUri.clear();
    state.regShowTotp = false;
    scr.PostEvent(Event::Custom);
  });

  return Renderer(
      Container::Vertical(
          {rUser, rPass, tCode, btnSubmit, btnVerifyTotp, btnBack}),
      [&, rUser, rPass, tCode, btnSubmit, btnVerifyTotp, btnBack] {
        Elements body = {
            text(" Register ") | bold | center,
            separator(),
            labeledInput(" Username : ", rUser),
            separator(),
            labeledInput(" Password : ", rPass),
        };
        if (!state.regShowTotp) {
          body.push_back(separator());
          body.push_back(btnRow({btnSubmit->Render(), btnBack->Render()}));
        }
        if (!state.regStatus.empty())
          body.push_back(paragraph(" " + state.regStatus) |
                         color(state.regStatus.starts_with("Error")
                                   ? Color::Red
                                   : Color::Green));
        if (state.regShowTotp) {
          body.push_back(separator());
          if (!state.regTotpUri.empty())
            body.push_back(qrElement(state.regTotpUri) | center);
          body.push_back(separator());
          body.push_back(labeledInput(" TOTP Code : ", tCode));
          body.push_back(separator());
          body.push_back(btnRow({btnVerifyTotp->Render(), btnBack->Render()}));
          if (!state.regTotpStatus.empty())
            body.push_back(text(" " + state.regTotpStatus) | color(Color::Red));
        }
        return centeredDialog(std::move(body));
      });
}

// ── Login screen ──────────────────────────────────────────────────────────────

Component makeLoginScreen(AppState &state, ScreenInteractive &scr,
                          const ApiClient &api) {
  auto lUser = noNewlineInput(&state.loginUsername, "username");
  auto lPass = noNewlineInput(&state.loginPassword, "password",
                              InputOption{.transform = {}, .password = true});
  auto tCode = digitOnlyInput(&state.loginTotpCode, "6-digit code");

  auto btnLogin = Button(" Login ", [&] {
    if (state.loginUsername.empty() || state.loginPassword.empty()) {
      state.loginStatus = "Username and password required.";
      return;
    }
    try {
      state.loginStatus = "Authenticating...";
      SrpSession srp;
      auto init = api.srpInit(state.loginUsername);
      const auto [clientPublic, clientProof] =
          srp.computeProof(state.loginUsername, state.loginPassword,
                           init["srp_salt"], init["server_public"]);
      auto verify =
          api.srpVerify(init["session_id"], clientPublic, clientProof);
      if (!srp.verifyServerProof(verify["server_proof"].get<std::string>())) {
        state.loginStatus = "ERROR: Server proof invalid -- possible MITM!";
        return;
      }
      state.loginPreAuthToken = verify["pre_auth_token"].get<std::string>();
      state.loginStatus.clear();
      state.loginShowTotp = true;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.loginStatus = std::string("Error: ") + e.what();
    }
  });

  auto btnVerify = Button(" Verify ", [&] {
    if (state.loginTotpCode.empty()) {
      state.loginTotpStatus = "Enter the 6-digit code.";
      return;
    }
    if (state.loginTotpStatus == "Verifying...")
      return;
    state.loginTotpStatus = "Verifying...";
    scr.PostEvent(Event::Custom);
    std::thread([&] {
      try {
        auto tokens = api.verify2FA(state.loginPreAuthToken, state.loginTotpCode);
        const std::string keyFile = "identity_" + state.loginUsername + ".key";
        const bool isNewDevice = !std::filesystem::exists(keyFile);
        const std::string accessToken = tokens.at("access_token").get<std::string>();
        const auto dot1 = accessToken.find('.');
        const auto dot2 = accessToken.find('.', dot1 + 1);
        std::string payload = accessToken.substr(dot1 + 1, dot2 - dot1 - 1);
        while (payload.size() % 4) payload += '=';
        std::ranges::replace(payload, '-', '+');
        std::ranges::replace(payload, '_', '/');
        const auto decoded = base64Decode(payload);
        const auto claims = nlohmann::json::parse(
            std::string(decoded.begin(), decoded.end()));
        state.pendingUserId = std::stoi(claims.at("sub").get<std::string>());
        state.localUser.emplace(state.pendingUserId, state.loginUsername,
                                tokens["access_token"].get<std::string>(),
                                tokens["refresh_token"].get<std::string>(),
                                keyFile, state.loginPassword);
        if (isNewDevice)
          publishBundle(api, *state.localUser);

        const auto countRes =
            api.getPrekeysCount(state.localUser->getAccessToken());
        if (countRes.at("count").get<int32_t>() < 10) {
          const auto newOpkPubs =
              state.localUser->replenishOneTimePrekeys(20U, state.loginPassword);
          std::vector<std::string> newOpkPubsB64;
          std::ranges::transform(newOpkPubs, std::back_inserter(newOpkPubsB64),
                                 [](const auto &p) { return base64Encode(p); });
          api.uploadPrekeys(state.localUser->getAccessToken(), newOpkPubsB64);
        }

        state.contactCache = contactCacheLoad("known_identities.json");
        {
          std::lock_guard<std::mutex> lk(state.usernameCacheMutex);
          for (const auto &c : state.contactCache)
            state.usernameCache[c.getId()] = c.getUsername();
        }
        state.messageStore =
            MessageStore("messages_" + state.loginUsername + ".db",
                         state.localUser->getDbKey());
        state.screen = AppScreen::Main;
      } catch (const std::exception &e) {
        state.loginTotpStatus = std::string("Error: ") + e.what();
      }
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  auto btnBack = Button(" Back ", [&] {
    state.screen = AppScreen::Welcome;
    state.loginStatus.clear();
    state.loginShowTotp = false;
    scr.PostEvent(Event::Custom);
  });

  return Renderer(
      Container::Vertical({lUser, lPass, tCode, btnLogin, btnVerify, btnBack}),
      [&, lUser, lPass, tCode, btnLogin, btnVerify, btnBack] {
        Elements body = {
            text(" Login ") | bold | center,
            separator(),
            labeledInput(" Username : ", lUser),
            separator(),
            labeledInput(" Password : ", lPass),
        };
        if (!state.loginShowTotp) {
          body.push_back(separator());
          body.push_back(btnRow({btnLogin->Render(), btnBack->Render()}));
          if (!state.loginStatus.empty())
            body.push_back(text(" " + state.loginStatus) | color(Color::Red));
        } else {
          body.push_back(separator());
          body.push_back(labeledInput(" TOTP Code : ", tCode));
          body.push_back(separator());
          body.push_back(btnRow({btnVerify->Render(), btnBack->Render()}));
          if (!state.loginTotpStatus.empty())
            body.push_back(text(" " + state.loginTotpStatus) | color(Color::Red));
        }
        return centeredDialog(std::move(body));
      });
}

// ── Poller ────────────────────────────────────────────────────────────────────

struct Poller {
  Poller(AppState &state, ScreenInteractive &scr, const ApiClient &api)
      : m_thread([&] {
          static constexpr int SPK_ROTATE_INTERVAL = 2016; // ~7 days at 5s poll
          int contactTick = 1; // fetch groups on first poll (5 s after login)
          int spkRotateTick = SPK_ROTATE_INTERVAL;

          std::unique_lock<std::mutex> lock(m_mutex);
          while (!m_cv.wait_for(lock, std::chrono::seconds(5),
                                [&] { return m_stop; })) {
            try {
              // Both must be set before we can do any work.
              if (!state.localUser || !state.messageStore)
                continue;

              const auto &lu = *state.localUser;

              std::vector<int32_t> pollGroupIds;
              {
                std::lock_guard<std::mutex> sl(state.stateMutex);
                for (const auto &g : state.groups)
                  pollGroupIds.push_back(g.getId());
              }

              // ── Direct messages: fetch then process ────────────────────
              appendLog("[poller] fetching direct messages (no lock)\n");
              const auto directMsgsJson = api.listMessages(lu.getAccessToken());
              {
                std::lock_guard<std::mutex> msgLock(state.messageMutex);
                const auto &kb = lu.getKeyBundle();
                const auto dmAckIds = processDirectMessages(
                    directMsgsJson, state.ratchets, *state.messageStore,
                    kb.ikX, kb.spk, kb.opks, kb.pq,
                    *state.localUser, state.loginPassword);
                for (const int32_t id : dmAckIds)
                  api.acknowledgeReceipt(lu.getAccessToken(), id);
              }
              state.msgsDirty = true;
              scr.PostEvent(Event::Custom);

              // ── Groups: fetch-then-process ONE AT A TIME ───────────────
              // Posting an event after each group lets the render thread
              // update the display between groups rather than waiting for
              // all N groups to complete (which could take 30+ seconds).
              const auto &kb = lu.getKeyBundle();
              for (const int32_t gid : pollGroupIds) {
                appendLog("[poller] fetching group " + std::to_string(gid) + " (no lock)\n");
                const auto skdmJson = api.fetchSkdm(lu.getAccessToken(), gid);
                const auto msgJson  = api.listGroupMessages(lu.getAccessToken(), gid);

                std::vector<std::pair<int32_t,int32_t>> gmAckIds;
                {
                  std::lock_guard<std::mutex> msgLock(state.messageMutex);
                  applySkdms(skdmJson, gid,
                             kb.ikX, kb.spk, kb.opks, kb.pq,
                             state.groupRatchets, state.skdmTracker);
                  gmAckIds = processGroupMessages(msgJson, state.groupRatchets,
                                                  *state.messageStore,
                                                  lu.getId(), gid);
                }
                for (const auto &[g, id] : gmAckIds)
                  api.acknowledgeGroupReceipt(lu.getAccessToken(), g, id);

                if (!gmAckIds.empty()) {
                  state.msgsDirty = true;
                  scr.PostEvent(Event::Custom);
                }
              }

              for (const int32_t senderId : state.messageStore->getDirectSenderIds()) {
                if (senderId == lu.getId()) continue;
                const bool known = std::ranges::any_of(state.contacts,
                    [senderId](const auto &c) { return c.getId() == senderId; });
                if (!known) {
                  try {
                    const auto res  = api.lookupById(lu.getAccessToken(), senderId);
                    const auto name = res.at("username").get<std::string>();
                    const auto ikRes = api.lookupByUsername(lu.getAccessToken(), name);
                    const auto ikPub = base64Decode(
                        ikRes.at("identity_pub").get<std::string>());
                    {
                      std::lock_guard<std::mutex> lk(state.stateMutex);
                      state.contacts.emplace_back(senderId, name, ikPub);
                      state.labelsDirty = true;
                    }
                    {
                      std::lock_guard<std::mutex> lk(state.usernameCacheMutex);
                      state.usernameCache[senderId] = name;
                    }
                  } catch (...) {}
                }
              }

              // ── Group list refresh ─────────────────────────────────────
              appendLog("[poller] listGroups start\n");
              auto groupsJson = api.listGroups(lu.getAccessToken());
              appendLog("[poller] listGroups done, count=" +
                        std::to_string(groupsJson.contains("groups")
                            ? groupsJson["groups"].size() : 0) + "\n");

              if (groupsJson.contains("groups")) {
                std::vector<Group> freshGroups;

                for (const auto &g : groupsJson["groups"]) {
                  std::vector<int32_t> members;
                  if (g.contains("members")) {
                    const auto &arr = g["members"];
                    std::ranges::transform(arr, std::back_inserter(members),
                                           [](const auto &m) {
                                             return m.template get<int32_t>();
                                           });
                  }

                  const int32_t gid   = g.at("id").get<int32_t>();
                  const int32_t epoch = g.at("epoch").get<int32_t>();
                  appendLog("[poller] group " + std::to_string(gid) +
                            " epoch=" + std::to_string(epoch) +
                            " members=" + std::to_string(members.size()) + "\n");

                  if (state.knownGroupEpochs.contains(gid) &&
                      state.knownGroupEpochs.at(gid) != epoch &&
                      !state.skdmTracker.weCausedEpoch(gid, epoch)) {
                    state.statusMsg =
                        "⚠ Group " + g.at("name").get<std::string>() +
                        " membership changed — re-keying";
                    appendLog("[poller] rekeying group " + std::to_string(gid) + "\n");
                    std::lock_guard<std::mutex> msgLk(state.messageMutex);
                    if (state.groupSenderKeys.contains(gid)) {
                      auto &sk = state.groupSenderKeys.at(gid);
                      OPENSSL_cleanse(sk.data(), sk.size());
                      state.groupSenderKeys.erase(gid);
                    }
                    state.groupRatchets.erase(gid);
                  }
                  state.knownGroupEpochs[gid] = epoch;
                  freshGroups.emplace_back(gid,
                                           g.at("name").get<std::string>(),
                                           members, epoch);

                  // Pre-cache usernames for uncached members
                  for (const int32_t mid : freshGroups.back().getMembers()) {
                    if (mid == lu.getId()) continue;
                    const bool cached =
                        std::ranges::any_of(state.contacts,
                            [mid](const auto &c) { return c.getId() == mid; }) ||
                        std::ranges::any_of(state.contactCache,
                            [mid](const auto &c) { return c.getId() == mid; });
                    if (!cached) {
                      appendLog("[poller] caching username for member " +
                                std::to_string(mid) + "\n");
                      try {
                        const auto r    = api.lookupById(lu.getAccessToken(), mid);
                        const auto name = r.at("username").get<std::string>();
                        const auto ikRes =
                            api.lookupByUsername(lu.getAccessToken(), name);
                        const auto ikPub =
                            base64Decode(ikRes.at("identity_pub").get<std::string>());
                        {
                          std::lock_guard<std::mutex> lk(state.stateMutex);
                          state.contactCache.emplace_back(mid, name, ikPub);
                        }
                        {
                          std::lock_guard<std::mutex> lk(state.usernameCacheMutex);
                          state.usernameCache[mid] = name;
                        }
                        appendLog("[poller] cached " + name + " id=" +
                                  std::to_string(mid) + "\n");
                      } catch (...) {}
                    }
                  }

                  // Re-post sender key if missing (post-rekey recovery only;
                  // brand-new groups are handled by createGroup thread)
                  const bool alreadyKnown = state.knownGroupEpochs.contains(gid);
                  bool needsPost = false;
                  {
                    std::lock_guard<std::mutex> msgLk(state.messageMutex);
                    needsPost = alreadyKnown &&
                                !state.groupSenderKeys.contains(gid);
                  }
                  if (needsPost) {
                    appendLog("[poller] posting sender key for group " +
                              std::to_string(gid) + "\n");
                    try {
                      const auto &kb2 = lu.getKeyBundle();
                      const auto groupInfo = api.getGroup(lu.getAccessToken(), gid);
                      const int32_t sEpoch = groupInfo.at("epoch").get<int32_t>();
                      auto newKey = randomBytes(KEY_BYTES);
                      std::map<int32_t, std::string> skdms;
                      for (const int32_t mid : freshGroups.back().getMembers())
                        skdms[mid] = encryptSkdmForMember(
                            api, lu.getAccessToken(), mid, kb2.ikX, newKey);
                      api.postSkdm(lu.getAccessToken(), gid, skdms);
                      state.skdmTracker.recordPosted(gid, sEpoch);
                      {
                        std::lock_guard<std::mutex> msgLk(state.messageMutex);
                        state.groupSenderKeys[gid] = newKey;
                      }
                      OPENSSL_cleanse(newKey.data(), newKey.size());
                      appendLog("[poller] sender key posted for group " +
                                std::to_string(gid) + "\n");
                    } catch (...) {}
                  }

                  // Post an event after each group so the render can update
                  // the sidebar and message list without waiting for the full loop.
                  state.msgsDirty = true;
                  scr.PostEvent(Event::Custom);
                }
                {
                  std::lock_guard<std::mutex> groupsLock(state.stateMutex);
                  state.groups = std::move(freshGroups);
                  state.labelsDirty = true;
                }
                appendLog("[poller] group list committed\n");
              }

              state.msgsDirty = true;
              if (--spkRotateTick == 0 && state.localUser) {
                spkRotateTick = SPK_ROTATE_INTERVAL;
                state.localUser->rotateSPK(state.loginPassword);
                publishBundle(api, *state.localUser);
              }
            } catch (const std::exception &e) {
              const std::string msg = e.what();
              appendLog("[poller] exception: " + msg + "\n");
              if (msg.find("401") != std::string::npos && state.localUser) {
                try {
                  const auto tokens = api.refreshTokens(
                      state.localUser->getRefreshToken());
                  state.localUser->setAccessToken(
                      tokens.at("access_token").get<std::string>());
                  state.localUser->setRefreshToken(
                      tokens.at("refresh_token").get<std::string>());
                  appendLog("[poller] token refreshed\n");
                } catch (...) {
                  appendLog("[poller] token refresh failed\n");
                }
              }
            }
            scr.PostEvent(Event::Custom);
          }
        }) {}

  ~Poller() {
    {
      std::lock_guard lock(m_mutex);
      m_stop = true;
    }
    m_cv.notify_one();
    if (m_thread.joinable())
      m_thread.join();
  }

private:
  std::thread m_thread;
  std::mutex m_mutex;
  std::condition_variable m_cv;
  bool m_stop{false};
};

// ── Identity overlay helper ───────────────────────────────────────────────────

static void openIdentityOverlay(AppState &state) {
  const int32_t targetId = state.viewingGroup ? -1 : state.selectedContactId;
  if (targetId < 0)
    return;
  const auto it = std::ranges::find_if(
      state.contacts, [&](const auto &c) { return c.getId() == targetId; });
  if (it == state.contacts.end()) {
    const auto cit = std::ranges::find_if(
        state.contactCache, [&](const auto &c) { return c.getId() == targetId; });
    if (cit == state.contactCache.end()) return;
    state.overlayTargetName = cit->getUsername();
    state.overlayKeyB64 = base64Encode(cit->getIdentityPub());
    state.overlayVerified = cit->isVerified();
    state.showIdentityOverlay = true;
    return;
  }
  state.overlayTargetName = it->getUsername();
  state.overlayKeyB64 = base64Encode(it->getIdentityPub());
  state.overlayVerified = it->isVerified();
  state.showIdentityOverlay = true;
}

// ── Main screen ───────────────────────────────────────────────────────────────

Component makeMainScreen(AppState &state, ScreenInteractive &scr,
                         const ApiClient &api) {
  if (!state.poller)
    state.poller = std::make_unique<Poller>(state, scr, api);

  auto composeInput = noNewlineInput(&state.composeText, "Type a message...");

  // Lock-free lookup via usernameCache — never touches contacts/contactCache directly
  // (avoids data race with the poller which writes those vectors under stateMutex)
  auto usernameById = [&](const int32_t id) -> std::string {
    if (state.localUser && id == state.localUser->getId())
      return state.localUser->getUsername();
    std::lock_guard<std::mutex> lk(state.usernameCacheMutex);
    const auto it = state.usernameCache.find(id);
    return it != state.usernameCache.end() ? it->second
                                           : "user:" + std::to_string(id);
  };

  auto rebuildMsgLabels = [msgLabels = state.msgLabels, msgIds = state.msgIds,
                           msgSent = state.msgSent, &state, usernameById] {
    msgLabels->clear();
    msgIds->clear();
    msgSent->clear();
    if (!state.localUser || !state.messageStore) {
      appendLog("[rebuild] skipped: localUser=" +
                std::to_string(static_cast<bool>(state.localUser)) +
                " store=" + std::to_string(static_cast<bool>(state.messageStore)) + "\n");
      return;
    }

    if (state.viewingGroup && state.selectedGroupId >= 0) {
      const auto _rb0 = std::chrono::steady_clock::now();
      const auto groupMsgs = state.messageStore->getByGroup(state.selectedGroupId);
      const auto _rb1 = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - _rb0).count();
      if (_rb1 > 50)
        appendLog("[rebuildMsgLabels] getByGroup took " + std::to_string(_rb1) + "ms\n");
      for (const auto &m : groupMsgs) {
        const bool mine = m.getDirection() == BaseMessage::Direction::Sent;
        const std::string senderName =
            mine ? state.localUser->getUsername() : usernameById(m.getUserId());
        msgLabels->emplace_back(" " + senderName + ": " + m.getPlaintext());
        msgIds->emplace_back(m.getId());
        msgSent->emplace_back(mine);
      }
    } else if (!state.viewingGroup && state.selectedContactId >= 0) {
      const std::string myName = state.localUser->getUsername();
      const std::string theirName = usernameById(state.selectedContactId);
      for (const auto &m :
           state.messageStore->getByUser(state.selectedContactId)) {
        const bool mine = m.getDirection() == BaseMessage::Direction::Sent;
        msgLabels->emplace_back(" " + (mine ? myName : theirName) + ": " +
                             m.getPlaintext());
        msgIds->emplace_back(m.getId());
        msgSent->emplace_back(mine);
      }
    } else {
      appendLog("[rebuild] no chat selected: contactId=" +
                std::to_string(state.selectedContactId) +
                " groupId=" + std::to_string(state.selectedGroupId) + "\n");
      return;
    }
    appendLog("[rebuild] labels=" + std::to_string(msgLabels->size()) + "\n");
    if (state.msgIds->empty()) {
      state.msgSelected = 0;
      state.selectedMsgId = -1;
    } else {
      state.msgSelected = std::clamp(state.msgSelected, 0,
                                     static_cast<int>(state.msgIds->size()) - 1);
      state.selectedMsgId = (*state.msgIds)[state.msgSelected];
    }
  };

  auto btnSend = Button(" Send ", [&] {
    if (state.composeText.empty() || !state.localUser)
      return;

    const bool isGroup        = state.viewingGroup;
    const int32_t contactId   = state.selectedContactId;
    const int32_t groupId     = state.selectedGroupId;
    const std::string text    = state.composeText;
    const std::string token   = state.localUser->getAccessToken();
    const int32_t myId        = state.localUser->getId();
    const RawKeyPair ikX      = state.localUser->getKeyBundle().ikX;
    std::vector<Contact> allContacts = state.contacts;
    for (const auto &c : state.contactCache)
      if (std::ranges::none_of(allContacts,
            [&](const auto &e) { return e.getId() == c.getId(); }))
        allContacts.push_back(c);

    state.composeText.clear();
    scr.PostEvent(Event::Custom);

    std::thread([&state, &api, &scr, isGroup, contactId, groupId,
                 text, token, myId, ikX,
                 allContacts = std::move(allContacts)]() mutable {
      try {
        std::lock_guard<std::mutex> msgLock(state.messageMutex);
        if (!isGroup && contactId >= 0) {
          sendDirectMessage(api, state.ratchets, *state.messageStore,
                            token, contactId, text, ikX, allContacts);
        } else if (isGroup && groupId >= 0) {
          sendGroupMessage(api, state.groupSenderKeys, state.groupRatchets,
                           *state.messageStore, token, groupId, myId, text);
        } else {
          throw std::runtime_error("No contact or group selected");
        }
      } catch (const std::exception &e) {
        state.statusMsg = "Send error: " + std::string(e.what());
        appendLog("[send] error: " + std::string(e.what()) + "\n");
      }
      state.msgsDirty = true;
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  MenuOption msgMenuOpt;
  msgMenuOpt.on_change = [&state] {
    if (state.msgSelected >= 0 &&
        state.msgSelected < static_cast<int>(state.msgIds->size()))
      state.selectedMsgId = (*state.msgIds)[state.msgSelected];
  };
  auto msgMenu = Menu(state.msgLabels.get(), &state.msgSelected, msgMenuOpt);

  auto btnDelete = Button(DELETE_LABEL, [&] {
    if (!state.localUser || state.selectedMsgId < 0)
      return;

    const bool sent = state.msgSelected >= 0 &&
                      state.msgSelected < static_cast<int>(state.msgSent->size()) &&
                      (*state.msgSent)[state.msgSelected];
    const int32_t msgId      = state.selectedMsgId;
    const bool isGroup       = state.viewingGroup;
    const int32_t groupId    = state.selectedGroupId;
    const int32_t contactId  = state.selectedContactId;
    const std::string token  = state.localUser->getAccessToken();

    state.selectedMsgId = -1;
    state.msgsDirty = true;

    std::thread([&state, &api, &scr, sent, msgId, isGroup, groupId,
                 contactId, token] {
      try {
        if (sent)
          api.revokeMessage(token, msgId);
        std::lock_guard<std::mutex> lk(state.messageMutex);
        if (isGroup)
          state.messageStore->removeGroupMessage(groupId, msgId);
        else
          state.messageStore->removeDirectMessage(contactId, msgId);
        state.statusMsg = sent ? "Message revoked." : "Message deleted.";
      } catch (const std::exception &e) {
        state.statusMsg = "Delete error: " + std::string(e.what());
      }
      state.msgsDirty = true;
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  auto addMemberInput = noNewlineInput(&state.addGroupMemberUsername, "add member...");

  auto btnAddMember = Button(" + ", [&] {
    if (!state.localUser || state.selectedGroupId < 0 ||
        state.addGroupMemberUsername.empty())
      return;
    std::thread([&] {
      try {
        const auto res = api.lookupByUsername(
            state.localUser->getAccessToken(), state.addGroupMemberUsername);
        const int32_t uid = res.at("user_id").get<int32_t>();
        const auto senderKey = state.groupSenderKeys.at(state.selectedGroupId);
        const auto skdm = encryptSkdmForMember(
            api, state.localUser->getAccessToken(), uid,
            state.localUser->getKeyBundle().ikX, senderKey);
        api.addGroupMember(state.localUser->getAccessToken(),
                           state.selectedGroupId, uid, skdm);
        state.addGroupMemberUsername.clear();
        state.statusMsg = "Member added.";
      } catch (const std::exception &e) {
        state.statusMsg = std::string("Add member failed: ") + e.what();
      }
      state.msgsDirty = true;
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  auto btnRemoveMember = Button(" Remove ", [&] {
    if (!state.localUser || state.selectedGroupId < 0 ||
        state.selectedMemberIndex < 0)
      return;
    const auto git = std::ranges::find_if(
        state.groups,
        [&](const auto &g) { return g.getId() == state.selectedGroupId; });
    if (git == state.groups.end() ||
        state.selectedMemberIndex >= static_cast<int>(git->getMembers().size()))
      return;
    const int32_t targetId = git->getMembers()[state.selectedMemberIndex];
    std::thread([&, targetId] {
      try {
        const auto &members = [&] {
          const auto g = std::ranges::find_if(state.groups, [&](const auto &gr) {
            return gr.getId() == state.selectedGroupId;
          });
          return g != state.groups.end() ? g->getMembers() : std::vector<int32_t>{};
        }();
        std::map<int32_t, std::string> freshSkdms;
        {
          std::lock_guard<std::mutex> lk(state.messageMutex);
          if (state.groupSenderKeys.contains(state.selectedGroupId)) {
            auto newKey = randomBytes(KEY_BYTES);
            for (const int32_t mid : members) {
              if (mid == targetId || mid == state.localUser->getId()) continue;
              freshSkdms[mid] = encryptSkdmForMember(
                  api, state.localUser->getAccessToken(), mid,
                  state.localUser->getKeyBundle().ikX, newKey);
            }
            state.groupSenderKeys[state.selectedGroupId] = newKey;
            OPENSSL_cleanse(newKey.data(), newKey.size());
          }
        }
        api.removeGroupMember(state.localUser->getAccessToken(),
                              state.selectedGroupId, targetId, freshSkdms);
        state.selectedMemberIndex = -1;
        state.statusMsg = "Member removed.";
      } catch (const std::exception &e) {
        state.statusMsg = std::string("Remove failed: ") + e.what();
      }
      state.msgsDirty = true;
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  state.allLabels->clear();

  auto rebuildLabels = [allLabels = state.allLabels, &state] {
    std::unique_lock<std::mutex> lk(state.stateMutex, std::try_to_lock);
    if (!lk) {
      appendLog("[rebuildLabels] skipped: stateMutex held by poller\n");
      return;
    }
    allLabels->clear();
    std::ranges::transform(
        state.contacts, std::back_inserter(*allLabels), [&state](const auto &c) {
          return buildContactLabel(c.getUsername(), c.isVerified(),
                                   state.creatingGroup,
                                   state.selectedGroupMembers.contains(c.getId()));
        });
    if (!state.creatingGroup)
      std::ranges::transform(state.groups, std::back_inserter(*allLabels),
                             [](const auto &g) { return "  " + g.getName(); });

    // Re-sync menuSelected to the current selection BY ID so that when the
    // poller refreshes/reorders state.groups the index stays correct.
    // Without this, menuSelected points to a different item after each poll
    // tick and on_change fires, resetting viewingGroup back to false.
    const int cCount = static_cast<int>(state.contacts.size());
    if (state.viewingGroup && state.selectedGroupId >= 0) {
      for (int i = 0; i < static_cast<int>(state.groups.size()); ++i) {
        if (state.groups[i].getId() == state.selectedGroupId) {
          state.menuSelected = cCount + i;
          break;
        }
      }
    } else if (!state.viewingGroup && state.selectedContactId >= 0) {
      for (int i = 0; i < cCount; ++i) {
        if (state.contacts[i].getId() == state.selectedContactId) {
          state.menuSelected = i;
          break;
        }
      }
    }
  };
  rebuildLabels();

  // Snapshot contact/group IDs under stateMutex to avoid data race with poller.
  // Uses try_to_lock so it NEVER blocks the FTXUI event loop thread.
  auto selectItem = [&state, &scr] {
    std::vector<int32_t> cIds, gIds;
    {
      std::unique_lock<std::mutex> lk(state.stateMutex, std::try_to_lock);
      if (!lk)
        return; // Poller holds the lock; next click will succeed
      std::ranges::transform(state.contacts, std::back_inserter(cIds),
                             [](const auto &c) { return c.getId(); });
      std::ranges::transform(state.groups, std::back_inserter(gIds),
                             [](const auto &g) { return g.getId(); });
    }
    appendLog("[select] menuSelected=" + std::to_string(state.menuSelected) +
              " contacts=" + std::to_string(cIds.size()) +
              " groups=" + std::to_string(gIds.size()) + "\n");
    const auto sel = resolveMenuSelection(cIds, gIds, state.menuSelected);
    if (state.creatingGroup) {
      if (sel.isContact) {
        if (state.selectedGroupMembers.contains(sel.id))
          state.selectedGroupMembers.erase(sel.id);
        else
          state.selectedGroupMembers.insert(sel.id);
        state.labelsDirty = true;
        scr.PostEvent(Event::Custom);
      }
      return;
    }
    if (sel.isContact) {
      appendLog("[select] -> contact id=" + std::to_string(sel.id) + "\n");
      state.selectedContactId = sel.id;
      state.viewingGroup = false;
    } else if (sel.isGroup) {
      appendLog("[select] -> group id=" + std::to_string(sel.id) + "\n");
      state.selectedGroupId = sel.id;
      state.viewingGroup = true;
    } else {
      appendLog("[select] -> out of range, ignored\n");
      return;
    }
    state.msgsDirty = true;
    scr.PostEvent(Event::Custom);
  };

  MenuOption menuOpt;
  menuOpt.on_change = selectItem;
  menuOpt.on_enter  = selectItem;
  auto leftMenu = Menu(state.allLabels.get(), &state.menuSelected, menuOpt);

  auto groupNameInput = noNewlineInput(&state.newGroupName, "group name");

  auto btnCreateGroup = Button(" Create ", [&, rebuildLabels] {
    if (state.newGroupName.empty() || !state.localUser || !state.messageStore)
      return;
    // Snapshot mutable state before threading
    const std::string name   = state.newGroupName;
    const std::set<int32_t> members = state.selectedGroupMembers;
    state.newGroupName.clear();
    state.selectedGroupMembers.clear();
    state.creatingGroup = false;
    rebuildLabels();
    scr.PostEvent(Event::Custom);

    std::thread([&state, &api, &scr, name, members, rebuildLabels] {
      try {
        auto senderKey = randomBytes(KEY_BYTES);
        appendLog("[createGroup] name=" + name +
                  " members=" + std::to_string(members.size()) + "\n");

        std::map<int32_t, std::string> initialMembers;
        for (const int32_t memberId : members) {
          appendLog("[createGroup] encrypting SKDM for member=" +
                    std::to_string(memberId) + "\n");
          initialMembers[memberId] = encryptSkdmForMember(
              api, state.localUser->getAccessToken(), memberId,
              state.localUser->getKeyBundle().ikX, senderKey);
          appendLog("[createGroup] SKDM ok for member=" +
                    std::to_string(memberId) + "\n");
        }

        appendLog("[createGroup] calling createGroup API\n");
        const auto res = api.createGroup(
            state.localUser->getAccessToken(), name, initialMembers);
        appendLog("[createGroup] API response: " + res.dump() + "\n");
        const int32_t gid = res.at("id").get<int32_t>();
        {
          std::lock_guard<std::mutex> lk(state.messageMutex);
          state.groupSenderKeys[gid] = senderKey;
        }
        OPENSSL_cleanse(senderKey.data(), senderKey.size());
        appendLog("[createGroup] done gid=" + std::to_string(gid) + "\n");
      } catch (const std::exception &e) {
        appendLog("[createGroup] FAILED: " + std::string(e.what()) + "\n");
        state.statusMsg = std::string("Create group failed: ") + e.what();
      }
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  auto btnNewGroup = Button(" + Group ", [&, rebuildLabels] {
    state.creatingGroup = !state.creatingGroup;
    if (!state.creatingGroup)
      state.selectedGroupMembers.clear();
    state.labelsDirty = true;
    scr.PostEvent(Event::Custom);
  });

  auto addInput = noNewlineInput(&state.addContactUsername, "add contact...");

  // Moved API call off the UI thread to prevent freezing.
  auto btnAdd = Button(" + ", [&, rebuildLabels] {
    if (state.addContactUsername.empty() || !state.localUser)
      return;
    const std::string username = state.addContactUsername;
    state.addContactUsername.clear();
    std::thread([&state, &api, &scr, username, rebuildLabels] {
      try {
        const auto res = api.lookupByUsername(state.localUser->getAccessToken(),
                                              username);
        const int32_t uid = res.at("user_id").get<int32_t>();
        const auto ikPub = base64Decode(res.at("identity_pub").get<std::string>());
        if (state.localUser && uid == state.localUser->getId()) {
          state.statusMsg = "Cannot add yourself as a contact.";
        } else {
          {
            std::lock_guard<std::mutex> lk(state.stateMutex);
            if (std::ranges::none_of(state.contacts,
                                     [uid](const auto &c) { return c.getId() == uid; }))
              state.contacts.emplace_back(uid, username, ikPub);
            // Auto-select the new contact so the chat loads immediately.
            state.selectedContactId = uid;
            state.viewingGroup = false;
            state.msgsDirty = true;
            // Sync menuSelected so the highlight matches.
            for (int i = 0; i < static_cast<int>(state.contacts.size()); ++i) {
              if (state.contacts[static_cast<std::size_t>(i)].getId() == uid) {
                state.menuSelected = i;
                break;
              }
            }
          }
          {
            std::lock_guard<std::mutex> lk(state.usernameCacheMutex);
            state.usernameCache[uid] = username;
          }
          rebuildLabels();
        }
      } catch (const std::exception &e) {
        state.statusMsg = std::string("Add failed: ") + e.what();
      }
      scr.PostEvent(Event::Custom);
    }).detach();
  });

  const auto leftPanel = Renderer(
      Container::Vertical(
          {groupNameInput, btnCreateGroup, btnNewGroup, addInput, btnAdd, leftMenu}),
      [&, leftMenu, rebuildLabels, addInput, btnAdd,
       groupNameInput, btnCreateGroup, btnNewGroup] {
        if (state.labelsDirty) {
          rebuildLabels();
          state.labelsDirty = false;
        }
        const int cCount = static_cast<int>(state.contacts.size());
        const int gCount = static_cast<int>(state.groups.size());
        Elements left;
        if (cCount > 0) {
          left.emplace_back(text(" Contacts ") | bold | center);
          left.emplace_back(separator());
        }
        if (state.allLabels->empty()) {
          left.emplace_back(text(" No contacts yet ") | dim | center | flex);
        } else {
          left.emplace_back(leftMenu->Render() | flex);
        }
        if (gCount > 0 && cCount > 0)
          left.emplace_back(separator());
        if (gCount > 0)
          left.emplace_back(text(" Groups ") | bold | center);
        left.emplace_back(separator());
        if (state.creatingGroup) {
          left.emplace_back(text(" New Group ") | bold | center);
          left.emplace_back(
              hbox({groupNameInput->Render() | flex |
                        size(HEIGHT, EQUAL, INPUT_LINE_HEIGHT),
                    btnCreateGroup->Render()}));
          left.emplace_back(text(" Select members (Enter to toggle):") | dim);
          left.emplace_back(separator());
        }
        left.emplace_back(hbox({addInput->Render() | flex |
                                    size(HEIGHT, EQUAL, INPUT_LINE_HEIGHT),
                                btnAdd->Render(), btnNewGroup->Render()}));
        return vbox(std::move(left)) | border | size(WIDTH, GREATER_THAN, 28);
      });

  // Wrap group-management components with Maybe so they are invisible to
  // FTXUI's focus chain when not viewing a group.  Without this, FTXUI moves
  // focus to addMemberInput when a group is selected, which swallows all
  // keyboard input and makes the UI appear frozen.
  auto addMemberMaybe   = Maybe(addMemberInput,   [&] { return state.viewingGroup; });
  auto btnAddMemberMaybe   = Maybe(btnAddMember,  [&] { return state.viewingGroup; });
  auto btnRemoveMemberMaybe = Maybe(btnRemoveMember, [&] { return state.viewingGroup; });

  const auto rightPanel = Renderer(
      Container::Vertical({msgMenu, composeInput, btnSend, btnDelete,
                           addMemberMaybe, btnAddMemberMaybe,
                           btnRemoveMemberMaybe}),
      [&, msgMenu, composeInput, btnSend, btnDelete, rebuildMsgLabels,
       addMemberInput, btnAddMember, btnRemoveMember] {
        const auto _t0 = std::chrono::steady_clock::now();
        auto _log = [&](const char *tag) {
          const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - _t0).count();
          appendLog("[render][" + std::string(tag) + "] " +
                    std::to_string(ms) + "ms\n");
        };
        // Log every render so we can see if the event loop is alive even
        // when msgsDirty is false (e.g. user keypresses between poll ticks).
        appendLog("[render] frame viewingGroup=" +
                  std::to_string(state.viewingGroup) +
                  " groupId=" + std::to_string(state.selectedGroupId) +
                  " dirty=" + std::to_string(state.msgsDirty) +
                  " labels=" + std::to_string(state.msgLabels->size()) + "\n");
        if (state.msgsDirty) {
          std::unique_lock<std::mutex> msgTry(state.messageMutex,
                                              std::try_to_lock);
          _log("after-try-lock");
          if (msgTry) {
            appendLog("[render] got messageMutex, rebuilding\n");
            rebuildMsgLabels();
            _log("after-rebuildMsgLabels");
            state.msgsDirty = false;
            appendLog("[render] rebuild done, labels=" +
                      std::to_string(state.msgLabels->size()) + "\n");
          } else {
            appendLog("[render] messageMutex busy, skipping rebuild\n");
          }
        }
        const bool inChat =
            state.selectedContactId >= 0 || state.viewingGroup;
        const Element msgArea =
            !inChat ? (text(" Select a contact or group to start chatting ") |
                       dim | center | flex)
            : state.msgLabels->empty()
                ? (text(" No messages ") | dim | center | flex)
                : (msgMenu->Render() | flex | frame);
        Elements rows{msgArea};
        if (inChat) {
          rows.emplace_back(separator());
          if (state.selectedMsgId >= 0)
            rows.emplace_back(hbox({composeInput->Render() | flex,
                                    btnSend->Render(), btnDelete->Render()}));
          else
            rows.emplace_back(
                hbox({composeInput->Render() | flex, btnSend->Render()}));
        }
        if (state.viewingGroup && state.selectedGroupId >= 0) {
          static std::vector<int32_t> memberSnapshot;
          static int32_t snapshotGroupId = -1;
          std::unique_lock<std::mutex> stateTry(state.stateMutex,
                                                    std::try_to_lock);
          if (stateTry) {
            if (snapshotGroupId != state.selectedGroupId || state.msgsDirty) {
              snapshotGroupId = state.selectedGroupId;
              memberSnapshot.clear();
              const auto git = std::ranges::find_if(
                  state.groups, [&](const auto &g) {
                    return g.getId() == state.selectedGroupId;
                  });
              if (git != state.groups.end())
                memberSnapshot = git->getMembers();
            }
          }
          if (!memberSnapshot.empty()) {
            rows.emplace_back(separator());
            rows.emplace_back(text(" Members:") | dim);
            for (int i = 0; i < static_cast<int>(memberSnapshot.size()); ++i) {
              const int32_t mid = memberSnapshot[i];
              const bool selected = (state.selectedMemberIndex == i);
              // Cache-only lookup — never blocks or spawns threads from renderer.
              auto nameIt = std::ranges::find_if(state.contacts,
                  [mid](const auto &c) { return c.getId() == mid; });
              const std::string mname = (nameIt != state.contacts.end())
                  ? nameIt->getUsername()
                  : [&] {
                      auto cit = std::ranges::find_if(state.contactCache,
                          [mid](const auto &c) { return c.getId() == mid; });
                      return cit != state.contactCache.end()
                          ? cit->getUsername() : "user:" + std::to_string(mid);
                    }();
              auto label = text("  " + mname);
              if (selected) label = label | inverted;
              if (mid == state.localUser->getId()) label = label | dim;
              rows.emplace_back(
                  hbox({std::move(label) | flex,
                        selected ? btnRemoveMember->Render() : text("") }));
            }
            rows.emplace_back(
                hbox({addMemberInput->Render() | flex |
                          size(HEIGHT, EQUAL, INPUT_LINE_HEIGHT),
                      btnAddMember->Render()}));
          }
        }
        if (!state.statusMsg.empty())
          rows.emplace_back(text(" " + state.statusMsg) | dim);
        return vbox(std::move(rows)) | border;
      });

  auto split = ResizableSplitLeft(leftPanel, rightPanel, &state.splitPos);

  auto btnCloseOverlay = Button(" Close ", [&] {
    state.showIdentityOverlay = false;
    scr.PostEvent(Event::Custom);
  });

  auto btnMarkVerified = Button(" Mark as verified ", [&] {
    if (state.selectedContactId >= 0) {
      const auto it = std::ranges::find_if(
          state.contacts,
          [&](const auto &c) { return c.getId() == state.selectedContactId; });
      if (it != state.contacts.end())
        it->markVerified();
      const auto cit = std::ranges::find_if(
          state.contactCache,
          [&](const auto &c) { return c.getId() == state.selectedContactId; });
      if (cit != state.contactCache.end())
        cit->markVerified();
      contactCacheSave("known_identities.json", state.contactCache);
    }
    state.showIdentityOverlay = false;
    scr.PostEvent(Event::Custom);
  });

  auto overlayComp = Renderer(
      Container::Horizontal({btnCloseOverlay, btnMarkVerified}),
      [&, btnCloseOverlay, btnMarkVerified] {
        if (!state.showIdentityOverlay)
          return text("");
        Elements body = {
            text(" " + state.overlayTargetName + "'s Identity Key ") | bold |
                center,
            separator(),
            text(" Ed25519 public key (base64): ") | dim,
            paragraph(" " + state.overlayKeyB64),
            separator(),
            text(state.overlayVerified
                     ? " Verified out-of-band "
                     : " Not yet verified -- compare with contact directly ") |
                dim | center,
            separator(),
            btnRow({btnCloseOverlay->Render(), btnMarkVerified->Render()}),
        };
        return centeredDialog(std::move(body), MAIN_PANEL_MIN_WIDTH);
      });

  // ── Blockchain overlay ────────────────────────────────────────────────────
  auto chainVerifyInput = noNewlineInput(&state.chainVerifyInput,
                                         "paste proof package JSON…");

  auto btnExportSegment = Button(" Export Segment ", [&] {
    try {
      if (!state.localUser || !state.messageStore) {
        state.chainStatus = "Not logged in."; return;
      }
      std::string convLabel;
      state.chainLastEnvs.clear();

      auto addEnvs = [&](const auto& msgs, const std::string& cid) {
        const int take = std::min(static_cast<int>(msgs.size()), 5);
        for (int i = static_cast<int>(msgs.size()) - take;
             i < static_cast<int>(msgs.size()); ++i) {
          MessageEnvelope env;
          env.messageId      = std::to_string(msgs[static_cast<std::size_t>(i)].getId());
          env.senderId       = std::to_string(msgs[static_cast<std::size_t>(i)].getUserId());
          env.ciphertext     = msgs[static_cast<std::size_t>(i)].getCiphertext();
          env.conversationId = cid;
          state.chainLastEnvs.push_back(std::move(env));
        }
      };

      if (state.viewingGroup && state.selectedGroupId >= 0) {
        convLabel = "group-" + std::to_string(state.selectedGroupId);
        addEnvs(state.messageStore->getByGroup(state.selectedGroupId), convLabel);
      } else if (!state.viewingGroup && state.selectedContactId >= 0) {
        convLabel = "direct-" +
                    std::to_string(std::min(state.localUser->getId(),
                                            state.selectedContactId)) +
                    "-" + std::to_string(std::max(state.localUser->getId(),
                                                   state.selectedContactId));
        addEnvs(state.messageStore->getByUser(state.selectedContactId), convLabel);
      } else {
        state.chainStatus = "Select a conversation first."; return;
      }
      if (state.chainLastEnvs.empty()) {
        state.chainStatus = "No messages in this conversation."; return;
      }
      const std::string pubB64 = base64Encode(state.localUser->getKeyBundle().ik.pub);
      state.chainDigest = BlockchainManager::buildSegmentDigest(
          state.chainLastEnvs, convLabel, ++state.chainSegIdx, pubB64);
      const auto path = BlockchainManager::writeSegmentFile(
          state.chainLastEnvs, state.chainDigest);
      state.chainStatus = "Exported: " + path + "  hash: " +
                          state.chainDigest.segmentHash.substr(0, 12) + "…";
    } catch (const std::exception &ex) {
      state.chainStatus = std::string("Error: ") + ex.what();
    }
    scr.PostEvent(Event::Custom);
  });

  auto btnVerifyIntegrity = Button(" Verify Integrity ", [&] {
    try {
      if (state.chainVerifyInput.empty()) {
        state.chainVerifyResult = "Paste a proof package JSON first."; return;
      }
      auto pkg = nlohmann::json::parse(state.chainVerifyInput, nullptr, false);
      if (pkg.is_discarded()) { state.chainVerifyResult = "Invalid JSON."; return; }
      const auto local = BlockchainManager::verifyLocalHashes(pkg);
      if (local != "OK") { state.chainVerifyResult = local; return; }
      state.chainVerifyResult = "Local: OK  (set RPC URL in source to also verify on-chain)";
    } catch (const std::exception &ex) {
      state.chainVerifyResult = std::string("Error: ") + ex.what();
    }
    scr.PostEvent(Event::Custom);
  });

  auto btnCloseChain = Button(" Close ", [&] {
    state.showBlockchainOverlay = false;
    scr.PostEvent(Event::Custom);
  });

  auto chainOverlayComp = Renderer(
      Container::Vertical({chainVerifyInput, btnExportSegment,
                           btnVerifyIntegrity, btnCloseChain}),
      [&, chainVerifyInput, btnExportSegment, btnVerifyIntegrity, btnCloseChain] {
        if (!state.showBlockchainOverlay) return text("");
        Elements body = {
            text(" Blockchain ") | bold | center,
            separator(),
            text(" Export Segment ") | dim,
            text(" Take up to 5 messages from current conversation and export for recording. ") | dim,
            hbox({filler(), btnExportSegment->Render(), filler()}),
            text(" " + state.chainStatus) | color(Color::Cyan),
            separator(),
            text(" Verify Integrity ") | dim,
            hbox({text(" JSON: "), chainVerifyInput->Render() | flex}),
            hbox({filler(), btnVerifyIntegrity->Render(), filler()}),
            text(" " + state.chainVerifyResult) | color(Color::Yellow),
            separator(),
            hbox({filler(), btnCloseChain->Render(), filler()}),
        };
        return centeredDialog(std::move(body), MAIN_PANEL_MIN_WIDTH);
      });

  return CatchEvent(
      Renderer(Container::Tab({split, overlayComp, chainOverlayComp}, &state.tabIdx),
               [&, split, overlayComp, chainOverlayComp] {
                 if (state.showIdentityOverlay)        state.tabIdx = 1;
                 else if (state.showBlockchainOverlay) state.tabIdx = 2;
                 else                                  state.tabIdx = 0;
                 auto base = vbox({
                     hbox({text(" SecureMsg ") | bold, filler(),
                           state.localUser
                               ? (text(" [My Key: " +
                                       base64Encode(
                                           state.localUser->getKeyBundle().ik.pub)
                                       + "] ") |
                                  dim)
                               : text(""),
                           text(" [Ctrl+K] identity  [Ctrl+B] blockchain  [Ctrl+M] member  [Ctrl+Q] quit ") | dim}) |
                         bgcolor(Color::Blue),
                     split->Render() | flex,
                 });
                 if (state.showIdentityOverlay)
                   return dbox({base, overlayComp->Render()});
                 if (state.showBlockchainOverlay)
                   return dbox({base, chainOverlayComp->Render()});
                 return base;
               }),
      [&](const Event &e) {
        if (e == Event::Special("\x0b")) {
          openIdentityOverlay(state);
          scr.PostEvent(Event::Custom);
          return true;
        }
        if (e == Event::Special("\x02")) {
          state.showBlockchainOverlay = !state.showBlockchainOverlay;
          scr.PostEvent(Event::Custom);
          return true;
        }
        if (e == Event::Special("\x11")) {
          state.poller.reset();
          scr.ExitLoopClosure()();
          return true;
        }
        if (e == Event::Special("\x0d") && state.viewingGroup &&
            state.selectedGroupId >= 0) {
          const auto git = std::ranges::find_if(
              state.groups,
              [&](const auto &g) { return g.getId() == state.selectedGroupId; });
          if (git != state.groups.end() && !git->getMembers().empty()) {
            const int n = static_cast<int>(git->getMembers().size());
            state.selectedMemberIndex = (state.selectedMemberIndex + 1) % n;
            scr.PostEvent(Event::Custom);
            return true;
          }
        }
        return false;
      });
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main() {
  auto scr = ScreenInteractive::Fullscreen();
  const ApiClient api("https://BobbyTables.theburkenator.com");
  AppState state;

  int screenIdx = 0;

  auto welcome = makeWelcomeScreen(state, scr);
  auto reg = makeRegisterScreen(state, scr, api);
  auto login = makeLoginScreen(state, scr, api);
  auto mainScr = makeMainScreen(state, scr, api);

  const std::array screens{welcome, reg, login, mainScr};
  const auto root = CatchEvent(
      Renderer(Container::Tab({welcome, reg, login, mainScr}, &screenIdx),
               [&, screens] {
                 screenIdx = static_cast<int>(state.screen);
                 return screens.at(screenIdx)->Render();
               }),
      [](const Event &) { return false; });

  scr.Loop(root);
  return 0;
}
