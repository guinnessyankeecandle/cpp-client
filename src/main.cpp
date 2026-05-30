#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
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

  std::string accessToken, refreshToken;
  int32_t myUserId{0};

  KeyBundle keyBundle;
  std::unordered_map<int32_t, Identity> identityCache;
  RatchetMap ratchets;
  GroupRatchetMap groupRatchets;
  GroupSenderKeys groupSenderKeys;

  std::vector<User> contacts;
  std::vector<Group> groups;
  int32_t selectedContactId{-1};
  int32_t selectedGroupId{-1};
  bool viewingGroup{false};
  MessageStore messageStore;
  std::string composeText;

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
      const auto verifier =
          srpComputeVerifier(state.regUsername, state.regPassword, saltHex);
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
      const auto A = srp.begin(state.regUsername, state.regPassword);
      auto init = api.srpInit(state.regUsername, A);
      auto verify = api.srpVerify(
          init["session_id"],
          srp.computeProof(init["srp_salt"], init["server_public"]));
      if (!srp.verifyServerProof(verify["server_proof"].get<std::string>())) {
        state.regTotpStatus = "Server proof invalid.";
        return;
      }
      auto tokens = api.verify2FA(verify["pre_auth_token"].get<std::string>(),
                                  state.regTotpCode);
      state.accessToken = tokens["access_token"].get<std::string>();
      state.refreshToken = tokens["refresh_token"].get<std::string>();
      state.myUserId = tokens.value("user_id", 0);

      state.keyBundle = keystoreGenerate();
      keystoreSave("identity.key", state.keyBundle, state.regPassword);
      std::vector<std::string> opkPubs;
      std::ranges::transform(
          state.keyBundle.opks, std::back_inserter(opkPubs),
          [](const X25519KeyPair &k) { return base64Encode(k.pub); });
      api.publishKeyBundle(state.accessToken,
                           base64Encode(state.keyBundle.ik.pub),
                           base64Encode(state.keyBundle.spk.pub),
                           base64Encode(state.keyBundle.spkSig), opkPubs,
                           base64Encode(state.keyBundle.pq.pub),
                           base64Encode(state.keyBundle.pqSig));

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
      const auto A = srp.begin(state.loginUsername, state.loginPassword);
      auto init = api.srpInit(state.loginUsername, A);
      auto verify = api.srpVerify(
          init["session_id"],
          srp.computeProof(init["srp_salt"], init["server_public"]));
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
      state.accessToken = tokens["access_token"].get<std::string>();
      state.refreshToken = tokens["refresh_token"].get<std::string>();
      state.myUserId = tokens.value("user_id", 0);

      if (std::filesystem::exists("identity.key")) {
        state.keyBundle = keystoreLoad("identity.key", state.loginPassword);
      } else {
        state.keyBundle = keystoreGenerate();
        keystoreSave("identity.key", state.keyBundle, state.loginPassword);
        std::vector<std::string> opkPubs;
        std::ranges::transform(
            state.keyBundle.opks, std::back_inserter(opkPubs),
            [](const X25519KeyPair &k) { return base64Encode(k.pub); });
        api.publishKeyBundle(state.accessToken,
                             base64Encode(state.keyBundle.ik.pub),
                             base64Encode(state.keyBundle.spk.pub),
                             base64Encode(state.keyBundle.spkSig), opkPubs,
                             base64Encode(state.keyBundle.pq.pub),
                             base64Encode(state.keyBundle.pqSig));
      }

      const auto countRes = api.getPrekeysCount(state.accessToken);
      if (countRes.value("count", 0) < 10) {
        std::vector<std::string> newOpkPubs;
        for (int i = 0; i < 20; ++i) {
          auto kp = x25519Generate();
          newOpkPubs.push_back(base64Encode(kp.pub));
          state.keyBundle.opks.push_back(std::move(kp));
        }
        api.uploadPrekeys(state.accessToken, newOpkPubs);
        keystoreSave("identity.key", state.keyBundle, state.loginPassword);
      }

      state.identityCache = identityCacheLoad("known_identities.json");
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
        if (state.selectedContactId >= 0 && !state.viewingGroup) {
          receiveDirectMessages(
              api, state.ratchets, state.messageStore, state.accessToken,
              state.myUserId, state.keyBundle.spk,
              state.keyBundle.opks.empty()
                  ? std::nullopt
                  : std::make_optional(state.keyBundle.opks.front()),
              state.keyBundle.pq, state.identityCache, api);
        } else if (state.viewingGroup && state.selectedGroupId >= 0) {
          receiveGroupMessages(api, state.groupRatchets, state.messageStore,
                               state.accessToken, state.selectedGroupId,
                               state.myUserId);
        }
        if (++contactTick >= 6) {
          contactTick = 0;
          auto groupsJson = api.listGroups(state.accessToken);
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
              state.groups.emplace_back(g.value("id", 0), g.value("name", ""),
                                        std::move(members),
                                        g.value("epoch", 0));
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
  const auto it = state.identityCache.find(targetId);
  if (it == state.identityCache.end())
    return;
  state.overlayTargetName = it->second.username;
  state.overlayKeyB64 = base64Encode(it->second.identityPub);
  state.overlayVerified = it->second.verified;
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

  auto btnSend = Button(" Send ", [&] {
    if (state.composeText.empty())
      return;
    try {
      if (!state.viewingGroup && state.selectedContactId >= 0) {
        sendDirectMessage(api, state.ratchets, state.accessToken,
                          state.selectedContactId, state.composeText,
                          state.keyBundle.spk, state.identityCache);
      } else if (state.viewingGroup && state.selectedGroupId >= 0) {
        sendGroupMessage(api, state.groupSenderKeys, state.groupRatchets,
                         state.accessToken, state.selectedGroupId,
                         state.myUserId, state.composeText);
      }
      state.composeText.clear();
      scr.PostEvent(Event::Custom);
    } catch (const std::exception &e) {
      state.composeText = "Error: " + std::string(e.what());
    }
  });

  int menuSelected = 0;
  const auto allLabels = std::make_shared<std::vector<std::string>>();

  auto rebuildLabels = [&] {
    allLabels->clear();
    std::ranges::transform(
        state.contacts, std::back_inserter(*allLabels), [&](const auto &u) {
          const bool ver = state.identityCache.contains(u.getId()) &&
                           state.identityCache.at(u.getId()).verified;
          return std::string(ver ? "v " : "  ") + u.getUsername();
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
      try {
        receiveDirectMessages(api, state.ratchets, state.messageStore,
                              state.accessToken, state.myUserId,
                              state.keyBundle.spk, std::nullopt,
                              state.keyBundle.pq, state.identityCache, api);
      } catch (...) {
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
      Container::Vertical({composeInput, btnSend}), [&, composeInput, btnSend] {
        Elements msgs;
        for (const auto &anyMsg : state.messageStore.getAll()) {
          std::visit(
              [&](const auto &m) {
                const bool mine =
                    m.getDirection() == BaseMessage::Direction::Sent;
                auto line =
                    text((mine ? " You: " : " Them: ") + m.getPlaintext());
                msgs.push_back(mine ? line | align_right : line);
              },
              anyMsg);
        }
        if (msgs.empty())
          msgs.push_back(text(" No messages yet ") | dim | center);
        return vbox({
                   vbox(std::move(msgs)) | flex | frame,
                   separator(),
                   hbox({composeInput->Render() | flex, btnSend->Render()}),
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
    if (state.selectedContactId >= 0 &&
        state.identityCache.contains(state.selectedContactId)) {
      state.identityCache[state.selectedContactId].verified = true;
      identityCacheSave("known_identities.json", state.identityCache);
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
  ApiClient api("https://BobbyTables.theburkenator.com", /*verifyTls=*/true);
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
