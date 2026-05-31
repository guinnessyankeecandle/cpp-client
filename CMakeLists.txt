cmake_minimum_required(VERSION 3.28)
project(SecureMsgClient VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
set(_botan_lib_hints
    /usr/lib64
    /usr/lib/x86_64-linux-gnu
    /usr/local/lib64
    /usr/local/lib
    /run/host/usr/lib64
    /run/host/usr/lib/x86_64-linux-gnu)
set(_botan_inc_hints
    /usr/include
    /usr/local/include
    /run/host/usr/include)

find_package(botan 3 QUIET CONFIG
    HINTS ${_botan_lib_hints}
    PATH_SUFFIXES cmake/Botan-3 cmake/botan-3 cmake)
if(NOT botan_FOUND AND NOT Botan_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        set(ENV{PKG_CONFIG_PATH}
            "/usr/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        pkg_check_modules(BOTAN QUIET botan-3)
    endif()
    if(BOTAN_FOUND)
        add_library(Botan::Botan INTERFACE IMPORTED)
        target_link_libraries(Botan::Botan INTERFACE ${BOTAN_LIBRARIES})
        target_include_directories(Botan::Botan INTERFACE ${BOTAN_INCLUDE_DIRS})
        target_compile_options(Botan::Botan INTERFACE ${BOTAN_CFLAGS_OTHER})
        target_link_directories(Botan::Botan INTERFACE ${BOTAN_LIBRARY_DIRS})
    else()
        find_library(BOTAN_LIB NAMES botan-3 botan
            HINTS ${_botan_lib_hints}
            REQUIRED)
        find_path(BOTAN_INCLUDE_DIR botan/srp6.h
            PATH_SUFFIXES botan-3 botan
            HINTS ${_botan_inc_hints}
            REQUIRED)
        add_library(Botan::Botan UNKNOWN IMPORTED)
        set_target_properties(Botan::Botan PROPERTIES
            IMPORTED_LOCATION "${BOTAN_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIR}")
    endif()
endif()

include(FetchContent)

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3)
    FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(ftxui QUIET)
if(NOT ftxui_FOUND)
    FetchContent_Declare(ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG        v5.0.0)
    FetchContent_MakeAvailable(ftxui)
endif()

find_package(Catch2 QUIET)
if(NOT Catch2_FOUND)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v2.13.10)
    FetchContent_MakeAvailable(Catch2)
endif()

# ── Crypto ────────────────────────────────────────────────────────────────────
add_library(securemsg_crypto)
target_sources(securemsg_crypto PUBLIC
    FILE_SET CXX_MODULES FILES
        src/crypto/random.cppm
        src/crypto/aead.cppm
        src/crypto/kdf.cppm
        src/crypto/ed25519.cppm
        src/crypto/x25519.cppm
        src/crypto/mlkem.cppm
        src/crypto/pqxdh.cppm
        src/crypto/ratchet.cppm
        src/crypto/keystore.cppm
        src/crypto/srp.cppm
        src/crypto/crypto.cppm)
target_link_libraries(securemsg_crypto PUBLIC OpenSSL::SSL OpenSSL::Crypto Botan::Botan)
target_compile_options(securemsg_crypto PRIVATE -Wall -Wextra)

# ── Models ────────────────────────────────────────────────────────────────────
add_library(securemsg_models)
target_sources(securemsg_models PUBLIC
    FILE_SET CXX_MODULES FILES
        src/models/user.cppm
        src/models/contact.cppm
        src/models/local_user.cppm
        src/models/group.cppm
        src/models/models.cppm)
target_link_libraries(securemsg_models PUBLIC securemsg_crypto nlohmann_json::nlohmann_json)
target_compile_options(securemsg_models PRIVATE -Wall -Wextra)

# ── Network ───────────────────────────────────────────────────────────────────
add_library(securemsg_network)
target_sources(securemsg_network PUBLIC
    FILE_SET CXX_MODULES FILES
        src/network/http.cppm
        src/network/api.cppm
        src/network/network.cppm)
target_link_libraries(securemsg_network PUBLIC CURL::libcurl nlohmann_json::nlohmann_json)
target_compile_options(securemsg_network PRIVATE -Wall -Wextra)

# ── Messaging ─────────────────────────────────────────────────────────────────
add_library(securemsg_messaging)
target_sources(securemsg_messaging PUBLIC
    FILE_SET CXX_MODULES FILES
        src/messaging/message.cppm
        src/messaging/store.cppm
        src/messaging/send_receive.cppm
        src/messaging/messaging.cppm)
target_link_libraries(securemsg_messaging PUBLIC securemsg_crypto securemsg_network securemsg_models)
target_compile_options(securemsg_messaging PRIVATE -Wall -Wextra)

# ── Main binary ───────────────────────────────────────────────────────────────
add_executable(securemsg src/main.cpp)
target_link_libraries(securemsg PRIVATE
    securemsg_models securemsg_crypto securemsg_network securemsg_messaging
    ftxui::screen ftxui::dom ftxui::component)
target_compile_options(securemsg PRIVATE -Wall -Wextra -Wpedantic)

# ── Tests ─────────────────────────────────────────────────────────────────────
include(CTest)
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS src/*.test.cpp)
if(TEST_SOURCES)
    add_executable(cybersec_tests
        src/test_main.cpp
        ${TEST_SOURCES})
    target_link_libraries(cybersec_tests PRIVATE
        securemsg_models securemsg_crypto securemsg_network securemsg_messaging
        Catch2::Catch2)
    add_test(NAME cybersec_tests COMMAND cybersec_tests)
endif()
