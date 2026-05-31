#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
import securemsg.models;
import securemsg.crypto;
import securemsg.messaging;
import securemsg.network;

using namespace ftxui;

enum class AppScreen { Welcome, Register, Login, Main };

struct AppState {
  AppScreen screen{AppScreen::Welcome};

  std::string regUsername, regPassword, regStatus;
  bool regShowTotp{false};
  std::string regTotpUri, regTotpCode, regTotpStatus;

  std::string loginUsername, loginPassword, loginStatus;
  bool loginShowTotp{false};
  std::string loginPreAuthToken, loginTotpCode, loginTotpStatus;

  std::optional<LocalUser> localUser;

  RatchetMap ratchets;
  GroupRatchetMap groupRatchets;
  GroupSenderKeys groupSenderKeys;

  std::vector<Contact> contactCache;
  std::vector<Contact> contacts;
  std::vector<Group> groups;
  int32_t selectedContactId{-1};
  int32_t selectedGroupId{-1};
  bool viewingGroup{false};
  MessageStore messageStore;
  std::string composeText;

  // Selected message for actions (server-assigned ID)
  int32_t selectedMsgId{-1};
  std::string selectedMsgIdStr; // text input for selecting a message by ID
  std::string statusMsg;        // feedback for message actions
  std::string forwardToId;      // recipient ID for forwarding

  // Group epoch tracking for membership change warnings
  std::unordered_map<int32_t, int32_t> knownGroupEpochs;

  bool showIdentityOverlay{false};
  std::string overlayTargetName;
  std::string overlayKeyB64;
  bool overlayVerified{false};

  std::atomic<bool> pollActive{false};
  std::thread pollThread;
};

static Element qrElement(const std::string &uri) {
  struct PipeDeleter {
    void operator()(FILE *f) const { pclose(f); }
  };
  using PipePtr = std::unique_ptr<FILE, PipeDeleter>;

  const auto pipe =
      PipePtr(popen(("qrencode -t UTF8 -o - -- '" + uri + "'").c_str(), "r"));
  if (!pipe)
    return paragraph(" Install qrencode: sudo dnf install qrencode ") |
           color(Color::Red);

  std::string out;
  std::array<char, 256> buf{};
  while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get()))
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

// Forward declarations
static void startPolling(AppState &state, ScreenInteractive &scr,
                         ApiClient &api);
static void stopPolling(AppState &state);
static void openIdentityOverlay(AppState &state);

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
        return vbox({
            filler(),
            hbox({filler(),
                  vbox({
                      text(" SecureMsg ") | bold | center,
                      text(" Signal Protocol + Post-Quantum E2E Encryption ") |
                          dim | center,
                      separator(),
                      hbox({filler(), btnRegister->Render(), text("  "),
                            btnLogin->Render(), filler()}),
                  }) | border |
                      size(WIDTH, GREATER_THAN, 52),
                  filler()}),
            filler(),
        });
      });
}

Component makeRegisterScreen(AppState &state, ScreenInteractive &scr,
                             ApiClient &api) {
  auto rUser = Input(&state.regUsername, "username");
  auto rPass = Input(&state.regPassword, "password",
                     InputOption{.transform = {}, .password = true});
  auto tCode = Input(&state.regTotpCode, "6-digit code");

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
      state.regStatus = "Registered! Scan the QR code with your authenticator.";
      if (res.contains("totp_provisioning_uri"))
        state.regTotpUri = res["totp_provisioning_uri"].get<std::string>();
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
    try {
      SrpSession srp;
      auto init = api.srpInit(state.regUsername);
      const auto [A, M1] =
          srp.computeProof(state.regUsername, state.regPassword,
                           init["srp_salt"], init["server_public"]);
      auto verify = api.srpVerify(init["session_id"], A, M1);
      if (!srp.verifyServerProof(verify["server_proof"].get<std::string>())) {
        state.regTotpStatus = "Server proof invalid.";
        return;
      }
      auto tokens = api.verify2FA(verify["pre_auth_token"].get<std::string>(),
                                  state.regTotpCode);
      state.localUser.emplace(tokens.value("user_id", 0), state.regUsername,
                              tokens["access_token"].get<std::string>(),
                              tokens["refresh_token"].get<std::string>(),
                              "identity.key", state.regPassword);
      std::vector<std::string> opkPubs;
      std::ranges::transform(
          state.localUser->getKeyBundle().opks, std::back_inserter(opkPubs),
          [](const X25519KeyPair &k) { return base64Encode(k.pub); });
      const auto &kb = state.localUser->getKeyBundle();
      api.publishKeyBundle(state.localUser->getAccessToken(),
                           base64Encode(kb.ik.pub), base64Encode(kb.spk.pub),
                           base64Encode(kb.spkSig), opkPubs,
                           base64Encode(kb.pq.pub), base64Encode(kb.pqSig));

      state.screen = AppScreen::Main;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.regTotpStatus = std::string("Error: ") + e.what();
    }
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
            hbox({text(" Username : "), rUser->Render() | flex}),
            separator(),
            hbox({text(" Password : "), rPass->Render() | flex}),
        };
        if (!state.regShowTotp) {
          body.push_back(separator());
          body.push_back(hbox({filler(), btnSubmit->Render(), text("  "),
                               btnBack->Render(), filler()}));
        }
        if (!state.regStatus.empty())
          body.push_back(paragraph(" " + state.regStatus) |
                         color(state.regStatus.rfind("Error", 0) == 0
                                   ? Color::Red
                                   : Color::Green));
        if (state.regShowTotp) {
          body.push_back(separator());
          if (!state.regTotpUri.empty())
            body.push_back(qrElement(state.regTotpUri) | center);
          body.push_back(separator());
          body.push_back(hbox({text(" TOTP Code : "), tCode->Render() | flex}));
          body.push_back(separator());
          body.push_back(hbox({filler(), btnVerifyTotp->Render(), text("  "),
                               btnBack->Render(), filler()}));
          if (!state.regTotpStatus.empty())
            body.push_back(text(" " + state.regTotpStatus) | color(Color::Red));
        }
        return vbox({filler(),
                     hbox({filler(),
                           vbox(std::move(body)) | border |
                               size(WIDTH, GREATER_THAN, 52),
                           filler()}),
                     filler()});
      });
}

Component makeLoginScreen(AppState &state, ScreenInteractive &scr,
                          ApiClient &api) {
  auto lUser = Input(&state.loginUsername, "username");
  auto lPass = Input(&state.loginPassword, "password",
                     InputOption{.transform = {}, .password = true});
  auto tCode = Input(&state.loginTotpCode, "6-digit code");

  auto btnLogin = Button(" Login ", [&] {
    if (state.loginUsername.empty() || state.loginPassword.empty()) {
      state.loginStatus = "Username and password required.";
      return;
    }
    try {
      state.loginStatus = "Authenticating...";
      SrpSession srp;
      auto init = api.srpInit(state.loginUsername);
      const auto [A, M1] =
          srp.computeProof(state.loginUsername, state.loginPassword,
                           init["srp_salt"], init["server_public"]);
      auto verify = api.srpVerify(init["session_id"], A, M1);
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
    try {
      auto tokens = api.verify2FA(state.loginPreAuthToken, state.loginTotpCode);
      const bool isNewDevice = !std::filesystem::exists("identity.key");
      state.localUser.emplace(tokens.value("user_id", 0), state.loginUsername,
                              tokens["access_token"].get<std::string>(),
                              tokens["refresh_token"].get<std::string>(),
                              "identity.key", state.loginPassword);
      if (isNewDevice) {
        std::vector<std::string> opkPubs;
        std::ranges::transform(
            state.localUser->getKeyBundle().opks, std::back_inserter(opkPubs),
            [](const X25519KeyPair &k) { return base64Encode(k.pub); });
        const auto &kb = state.localUser->getKeyBundle();
        api.publishKeyBundle(state.localUser->getAccessToken(),
                             base64Encode(kb.ik.pub), base64Encode(kb.spk.pub),
                             base64Encode(kb.spkSig), opkPubs,
                             base64Encode(kb.pq.pub), base64Encode(kb.pqSig));
      }

      const auto countRes =
          api.getPrekeysCount(state.localUser->getAccessToken());
      if (countRes.value("count", 0) < 10) {
        const auto newOpkPubs =
            state.localUser->replenishOneTimePrekeys(20U, state.loginPassword);
        std::vector<std::string> newOpkPubsB64;
        std::ranges::transform(newOpkPubs, std::back_inserter(newOpkPubsB64),
                               [](const auto &p) { return base64Encode(p); });
        api.uploadPrekeys(state.localUser->getAccessToken(), newOpkPubsB64);
      }

      state.contactCache = contactCacheLoad("known_identities.json");
      state.screen = AppScreen::Main;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.loginTotpStatus = std::string("Error: ") + e.what();
    }
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
            hbox({text(" Username : "), lUser->Render() | flex}),
            separator(),
            hbox({text(" Password : "), lPass->Render() | flex}),
        };
        if (!state.loginShowTotp) {
          body.push_back(separator());
          body.push_back(hbox({filler(), btnLogin->Render(), text("  "),
                               btnBack->Render(), filler()}));
          if (!state.loginStatus.empty())
            body.push_back(text(" " + state.loginStatus) | color(Color::Red));
        } else {
          body.push_back(separator());
          body.push_back(hbox({text(" TOTP Code : "), tCode->Render() | flex}));
          body.push_back(separator());
          body.push_back(hbox({filler(), btnVerify->Render(), text("  "),
                               btnBack->Render(), filler()}));
          if (!state.loginTotpStatus.empty())
            body.push_back(text(" " + state.loginTotpStatus) |
                           color(Color::Red));
        }
        return vbox({filler(),
                     hbox({filler(),
                           vbox(std::move(body)) | border |
                               size(WIDTH, GREATER_THAN, 52),
                           filler()}),
                     filler()});
      });
}

static void startPolling(AppState &state, ScreenInteractive &scr,
                         ApiClient &api) {
  state.pollActive = true;
  state.pollThread = std::thread([&] {
    int contactTick = 0;
    while (state.pollActive) {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      if (!state.pollActive)
        break;
      try {
        if (!state.localUser)
          continue;
        const auto &lu = *state.localUser;
        if (state.selectedContactId >= 0 && !state.viewingGroup) {
          receiveDirectMessages(
              api, state.ratchets, state.messageStore, lu.getAccessToken(),
              lu.getId(), lu.getKeyBundle().spk,
              lu.getKeyBundle().opks.empty()
                  ? std::nullopt
                  : std::make_optional(lu.getKeyBundle().opks.front()),
              lu.getKeyBundle().pq, state.contactCache, api);
        } else if (state.viewingGroup && state.selectedGroupId >= 0) {
          receiveGroupMessages(api, state.groupRatchets, state.messageStore,
                               lu.getAccessToken(), state.selectedGroupId,
                               lu.getId());
        }
        if (++contactTick >= 6) {
          contactTick = 0;
          auto groupsJson = api.listGroups(lu.getAccessToken());
          if (groupsJson.contains("groups")) {
            state.groups.clear();
            for (const auto &g : groupsJson["groups"]) {
              std::vector<int32_t> members;
              if (g.contains("members")) {
                const auto &arr = g["members"];
                std::ranges::transform(
                    arr, std::back_inserter(members),
                    [](const auto &m) { return m.template get<int32_t>(); });
              }
              const int32_t gid = g.value("id", 0);
              const int32_t epoch = g.value("epoch", 0);
              // Warn if epoch changed — server may have modified membership
              if (state.knownGroupEpochs.contains(gid) &&
                  state.knownGroupEpochs.at(gid) != epoch)
                state.statusMsg =
                    "⚠ Group " + g.value("name", std::to_string(gid)) +
                    " membership changed — verify members out-of-band";
              state.knownGroupEpochs[gid] = epoch;
              state.groups.emplace_back(gid, g.value("name", ""),
                                        std::move(members), epoch);
            }
          }
        }
        scr.PostEvent(Event::Custom);
      } catch (...) {
      }
    }
  });
}

static void stopPolling(AppState &state) {
  state.pollActive = false;
  if (state.pollThread.joinable())
    state.pollThread.join();
}

static void openIdentityOverlay(AppState &state) {
  const int32_t targetId = state.viewingGroup ? -1 : state.selectedContactId;
  if (targetId < 0)
    return;
  const auto it = std::ranges::find_if(
      state.contactCache, [&](const auto &c) { return c.getId() == targetId; });
  if (it == state.contactCache.end())
    return;
  state.overlayTargetName = it->getUsername();
  state.overlayKeyB64 = base64Encode(it->getIdentityPub());
  state.overlayVerified = it->isVerified();
  state.showIdentityOverlay = true;
}

Component makeMainScreen(AppState &state, ScreenInteractive &scr,
                         ApiClient &api) {
  static bool pollingStarted = false;
  if (!pollingStarted) {
    pollingStarted = true;
    startPolling(state, scr, api);
  }

  auto composeInput = Input(&state.composeText, "Type a message...");
  auto forwardInput = Input(&state.forwardToId, "Recipient ID");
  auto msgIdInput = Input(&state.selectedMsgIdStr, "Msg ID");
  msgIdInput |= CatchEvent([&](const Event &e) {
    if (e == Event::Return && !state.selectedMsgIdStr.empty()) {
      try {
        state.selectedMsgId = std::stoi(state.selectedMsgIdStr);
        state.statusMsg = "Selected message " + state.selectedMsgIdStr;
      } catch (...) {
        state.statusMsg = "Invalid message ID.";
      }
      return true;
    }
    return false;
  });

  auto btnSend = Button(" Send ", [&] {
    if (state.composeText.empty())
      return;
    try {
      if (!state.localUser)
        return;
      if (!state.viewingGroup && state.selectedContactId >= 0) {
        sendDirectMessage(api, state.ratchets, state.messageStore,
                          state.localUser->getAccessToken(),
                          state.selectedContactId, state.composeText,
                          state.localUser->getKeyBundle().spk,
                          state.contactCache);
      } else if (state.viewingGroup && state.selectedGroupId >= 0) {
        sendGroupMessage(api, state.groupSenderKeys, state.groupRatchets,
                         state.messageStore, state.localUser->getAccessToken(),
                         state.selectedGroupId, state.localUser->getId(),
                         state.composeText);
      }
      state.composeText.clear();
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.statusMsg = "Send error: " + std::string(e.what());
    }
  });

  // Forward selected message to another user
  auto btnForward = Button(" Forward ", [&] {
    if (!state.localUser || state.selectedMsgId < 0 ||
        state.forwardToId.empty()) {
      state.statusMsg = "Select a message and enter recipient ID to forward.";
      return;
    }
    try {
      const int32_t recipientId = std::stoi(state.forwardToId);
      // Find the message plaintext in the store
      const auto msgs = state.messageStore.getByUser(state.selectedContactId);
      const auto it = std::ranges::find_if(msgs, [&](const auto &m) {
        return m.getId() == state.selectedMsgId;
      });
      if (it == msgs.end()) {
        state.statusMsg = "Message not found locally.";
        return;
      }
      sendDirectMessage(api, state.ratchets, state.messageStore,
                        state.localUser->getAccessToken(), recipientId,
                        it->getPlaintext(), state.localUser->getKeyBundle().spk,
                        state.contactCache);
      state.statusMsg = "Forwarded.";
      state.forwardToId.clear();
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.statusMsg = "Forward error: " + std::string(e.what());
    }
  });

  // Revoke selected message on server
  auto btnRevoke = Button(" Revoke ", [&] {
    if (!state.localUser || state.selectedMsgId < 0) {
      state.statusMsg = "Select a message to revoke.";
      return;
    }
    try {
      api.revokeMessage(state.localUser->getAccessToken(), state.selectedMsgId);
      state.statusMsg = "Message revoked on server.";
      state.selectedMsgId = -1;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.statusMsg = "Revoke error: " + std::string(e.what());
    }
  });

  // Download selected message to file
  auto btnDownload = Button(" Download ", [&] {
    if (state.selectedMsgId < 0) {
      state.statusMsg = "Select a message to download.";
      return;
    }
    try {
      const auto msgs = state.viewingGroup ? std::vector<BaseMessage *>{}
                                           : std::vector<BaseMessage *>{};
      // Find plaintext from store
      std::string plaintext;
      if (!state.viewingGroup) {
        const auto direct =
            state.messageStore.getByUser(state.selectedContactId);
        const auto it = std::ranges::find_if(direct, [&](const auto &m) {
          return m.getId() == state.selectedMsgId;
        });
        if (it != direct.end())
          plaintext = it->getPlaintext();
      } else {
        const auto grp = state.messageStore.getByGroup(state.selectedGroupId);
        const auto it = std::ranges::find_if(grp, [&](const auto &m) {
          return m.getId() == state.selectedMsgId;
        });
        if (it != grp.end())
          plaintext = it->getPlaintext();
      }
      if (plaintext.empty()) {
        state.statusMsg = "Message not found or empty.";
        return;
      }
      const std::string filename =
          "message_" + std::to_string(state.selectedMsgId) + ".txt";
      std::ofstream f(filename);
      if (!f) {
        state.statusMsg = "Could not write file.";
        return;
      }
      f << plaintext;
      state.statusMsg = "Saved to " + filename;
    } catch (const std::exception &e) {
      state.statusMsg = "Download error: " + std::string(e.what());
    }
  });

  // Delete message locally (acknowledge receipt removes from server too)
  auto btnDelete = Button(" Delete ", [&] {
    if (!state.localUser || state.selectedMsgId < 0) {
      state.statusMsg = "Select a message to delete.";
      return;
    }
    try {
      api.acknowledgeReceipt(state.localUser->getAccessToken(),
                             state.selectedMsgId);
      state.messageStore.clear(); // refresh from server on next poll
      state.statusMsg = "Message deleted.";
      state.selectedMsgId = -1;
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.statusMsg = "Delete error: " + std::string(e.what());
    }
  });

  int menuSelected = 0;
  const auto allLabels = std::make_shared<std::vector<std::string>>();

  auto rebuildLabels = [&] {
    allLabels->clear();
    std::ranges::transform(
        state.contacts, std::back_inserter(*allLabels), [](const auto &c) {
          return std::string(c.isVerified() ? "v " : "  ") + c.getUsername();
        });
    std::ranges::transform(state.groups, std::back_inserter(*allLabels),
                           [](const auto &g) { return "  " + g.getName(); });
  };
  rebuildLabels();

  MenuOption menuOpt;
  menuOpt.on_enter = [&] {
    const int ci = static_cast<int>(state.contacts.size());
    if (menuSelected < ci) {
      state.selectedContactId = state.contacts.at(menuSelected).getId();
      state.viewingGroup = false;
      state.messageStore.clear();
      if (state.localUser) {
        try {
          receiveDirectMessages(
              api, state.ratchets, state.messageStore,
              state.localUser->getAccessToken(), state.localUser->getId(),
              state.localUser->getKeyBundle().spk, std::nullopt,
              state.localUser->getKeyBundle().pq, state.contactCache, api);
        } catch (...) {
        }
      }
    } else if (menuSelected - ci < static_cast<int>(state.groups.size())) {
      state.selectedGroupId = state.groups.at(menuSelected - ci).getId();
      state.viewingGroup = true;
      state.messageStore.clear();
    }
    scr.PostEvent(Event::Custom);
  };

  auto leftMenu = Menu(allLabels.get(), &menuSelected, menuOpt);
  const auto leftPanel = Renderer(leftMenu, [&, leftMenu] {
    rebuildLabels();
    return vbox({
               text(" Contacts / Groups ") | bold | center,
               separator(),
               leftMenu->Render() | flex,
           }) |
           border;
  });

  const auto rightPanel = Renderer(
      Container::Vertical({composeInput, btnSend, msgIdInput, forwardInput,
                           btnForward, btnRevoke, btnDownload, btnDelete}),
      [&, composeInput, btnSend, msgIdInput, forwardInput, btnForward,
       btnRevoke, btnDownload, btnDelete] {
        Elements msgs;
        if (state.viewingGroup && state.selectedGroupId >= 0) {
          for (const auto &m :
               state.messageStore.getByGroup(state.selectedGroupId)) {
            const bool sel = m.getId() == state.selectedMsgId;
            auto line = text(" [" + std::to_string(m.getId()) +
                             "] Them: " + m.getPlaintext()) |
                        (sel ? inverted : nothing);
            msgs.push_back(line);
          }
        } else if (!state.viewingGroup && state.selectedContactId >= 0) {
          for (const auto &m :
               state.messageStore.getByUser(state.selectedContactId)) {
            const bool mine = m.getDirection() == BaseMessage::Direction::Sent;
            const bool sel = m.getId() == state.selectedMsgId;
            auto line =
                text((mine ? " You" : " Them") + std::string(" [") +
                     std::to_string(m.getId()) + "]: " + m.getPlaintext()) |
                (sel ? inverted : nothing);
            msgs.push_back(mine ? line | align_right : line);
          }
        }
        if (msgs.empty())
          msgs.push_back(text(" No messages yet ") | dim | center);
        if (!state.statusMsg.empty())
          msgs.push_back(text(" " + state.statusMsg) | dim);
        return vbox({
                   vbox(std::move(msgs)) | flex | frame,
                   separator(),
                   hbox({composeInput->Render() | flex, btnSend->Render()}),
                   separator(),
                   hbox({text(" Select: "),
                         msgIdInput->Render() | size(WIDTH, EQUAL, 6),
                         text("  Fwd→: "), forwardInput->Render() | flex,
                         btnForward->Render()}),
                   hbox({btnRevoke->Render(), btnDownload->Render(),
                         btnDelete->Render()}),
               }) |
               border;
      });

  int splitPos = 30;
  auto split = ResizableSplitLeft(leftPanel, rightPanel, &splitPos);

  auto btnCloseOverlay = Button(" Close ", [&] {
    state.showIdentityOverlay = false;
    scr.PostEvent(Event::Custom);
  });
  auto btnMarkVerified = Button(" Mark as verified ", [&] {
    if (state.selectedContactId >= 0) {
      const auto it =
          std::ranges::find_if(state.contactCache, [&](const auto &c) {
            return c.getId() == state.selectedContactId;
          });
      if (it != state.contactCache.end()) {
        it->markVerified();
        contactCacheSave("known_identities.json", state.contactCache);
      }
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
            hbox({filler(), btnCloseOverlay->Render(), text("  "),
                  btnMarkVerified->Render(), filler()}),
        };
        return vbox({filler(),
                     hbox({filler(),
                           vbox(std::move(body)) | border |
                               size(WIDTH, GREATER_THAN, 60),
                           filler()}),
                     filler()});
      });

  int tabIdx = 0;
  return CatchEvent(
      Renderer(Container::Tab({split, overlayComp}, &tabIdx),
               [&, split, overlayComp] {
                 tabIdx = state.showIdentityOverlay ? 1 : 0;
                 auto base = vbox({
                     hbox({text(" SecureMsg ") | bold, filler(),
                           text(" [i] identity  [q] quit ") | dim}) |
                         bgcolor(Color::Blue),
                     split->Render() | flex,
                 });
                 if (!state.showIdentityOverlay)
                   return base;
                 return dbox({base, overlayComp->Render()});
               }),
      [&](const Event &e) {
        if (e == Event::Character('i')) {
          openIdentityOverlay(state);
          scr.PostEvent(Event::Custom);
          return true;
        }
        if (e == Event::Character('q')) {
          stopPolling(state);
          scr.ExitLoopClosure()();
          return true;
        }
        return false;
      });
}

int main() {
  auto scr = ScreenInteractive::Fullscreen();
  ApiClient api("https://BobbyTables.theburkenator.com");
  AppState state;

  int screenIdx = 0;

  auto welcome = makeWelcomeScreen(state, scr);
  auto reg = makeRegisterScreen(state, scr, api);
  auto login = makeLoginScreen(state, scr, api);
  auto mainScr = makeMainScreen(state, scr, api);

  const auto root = CatchEvent(
      Renderer(Container::Tab({welcome, reg, login, mainScr}, &screenIdx),
               [&, welcome, reg, login, mainScr] {
                 screenIdx = static_cast<int>(state.screen);
                 switch (state.screen) {
                 case AppScreen::Welcome:
                   return welcome->Render();
                 case AppScreen::Register:
                   return reg->Render();
                 case AppScreen::Login:
                   return login->Render();
                 case AppScreen::Main:
                   return mainScr->Render();
                 }
                 return text("");
               }),
      [](const Event &) { return false; });

  scr.Loop(root);
  return 0;
}
