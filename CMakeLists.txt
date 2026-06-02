cmake_minimum_required(VERSION 3.28)
project(SecureMsgClient VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(SqliteOrm QUIET)

find_package(nlohmann_json REQUIRED PATHS
    /usr/share/cmake/nlohmann_json
    /run/host/usr/share/cmake/nlohmann_json
    NO_DEFAULT_PATH)
# ftxui requires Threads; pre-satisfy it for CLion's Flatpak cmake
if(NOT TARGET Threads::Threads)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(Threads_FOUND TRUE)
    add_library(Threads::Threads INTERFACE IMPORTED)
    target_link_options(Threads::Threads INTERFACE -lpthread)
endif()
find_package(ftxui REQUIRED PATHS
    /usr/lib64/cmake/ftxui
    /run/host/usr/lib64/cmake/ftxui
    NO_DEFAULT_PATH)
find_package(Catch2 REQUIRED PATHS
    /usr/lib64/cmake/Catch2
    /run/host/usr/lib64/cmake/Catch2
    NO_DEFAULT_PATH)

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
target_include_directories(securemsg_crypto PUBLIC
    /usr/include/python3.14
    /run/host/usr/include/python3.14)
target_link_libraries(securemsg_crypto PUBLIC OpenSSL::SSL OpenSSL::Crypto
    /usr/lib64/libpython3.14.so)
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
target_link_libraries(securemsg_messaging PUBLIC securemsg_crypto securemsg_network securemsg_models sqlite_orm::sqlite_orm)
target_compile_options(securemsg_messaging PRIVATE -Wall -Wextra)

# ── Main logic (pure, testable) ───────────────────────────────────────────────
add_library(securemsg_main_logic)
target_sources(securemsg_main_logic PUBLIC
    FILE_SET CXX_MODULES FILES src/main_logic.cppm)
target_compile_options(securemsg_main_logic PRIVATE -Wall -Wextra)

# ── Main binary ───────────────────────────────────────────────────────────────
add_executable(securemsg src/main.cpp)
target_link_libraries(securemsg PRIVATE
    securemsg_models securemsg_crypto securemsg_network securemsg_messaging
    securemsg_main_logic ftxui::screen ftxui::dom ftxui::component)
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
        securemsg_main_logic sqlite_orm::sqlite_orm Catch2::Catch2)
    add_test(NAME cybersec_tests COMMAND cybersec_tests)
endif()
