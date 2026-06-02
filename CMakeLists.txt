cmake_minimum_required(VERSION 3.28)
project(SecureMsgClient VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OPENSSL_ROOT_DIR /usr/local/openssl-3.5)
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
# Normalise SQLite3 target name — Conan uses SQLite::SQLite3, system CMake uses SQLite3::SQLite3
if(TARGET SQLite::SQLite3 AND NOT TARGET SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
elseif(TARGET SQLite3::SQLite3 AND NOT TARGET SQLite::SQLite3)
    add_library(SQLite::SQLite3 ALIAS SQLite3::SQLite3)
endif()
find_package(SqliteOrm QUIET PATHS
    ${CMAKE_BINARY_DIR}
    /run/host/usr/share/cmake)
if(NOT TARGET sqlite_orm::sqlite_orm)
    include(FetchContent)
    FetchContent_Declare(sqlite_orm
        GIT_REPOSITORY https://github.com/fnc12/sqlite_orm.git
        GIT_TAG        v1.8.2)
    # sqlite_orm's bundled ucm.cmake uses cmake_minimum_required < 3.5,
    # which CMake 4.x no longer accepts — suppress with the recommended policy var
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    FetchContent_MakeAvailable(sqlite_orm)
endif()

find_package(nlohmann_json QUIET PATHS
    /usr/share/cmake/nlohmann_json
    /run/host/usr/share/cmake/nlohmann_json
    NO_DEFAULT_PATH)
if(NOT nlohmann_json_FOUND)
    find_package(nlohmann_json QUIET)
endif()
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3)
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# ftxui requires Threads; pre-satisfy it for CLion's Flatpak cmake
if(NOT TARGET Threads::Threads)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(Threads_FOUND TRUE)
    add_library(Threads::Threads INTERFACE IMPORTED)
    target_link_options(Threads::Threads INTERFACE -lpthread)
endif()
find_package(ftxui QUIET PATHS
    /usr/lib64/cmake/ftxui
    /run/host/usr/lib64/cmake/ftxui
    NO_DEFAULT_PATH)
if(NOT ftxui_FOUND)
    find_package(ftxui QUIET)
endif()
if(NOT ftxui_FOUND)
    include(FetchContent)
    FetchContent_Declare(ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG        v5.0.0)
    FetchContent_MakeAvailable(ftxui)
endif()

find_package(Catch2 QUIET PATHS
    /usr/lib64/cmake/Catch2
    /run/host/usr/lib64/cmake/Catch2
    NO_DEFAULT_PATH)
if(NOT Catch2_FOUND)
    find_package(Catch2 QUIET)
endif()
if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v2.13.10)
    FetchContent_MakeAvailable(Catch2)
endif()

# ── Python (for pysrp embedding) ─────────────────────────────────────────────
find_program(Python3_EXECUTABLE NAMES python3)
if(NOT Python3_EXECUTABLE)
    message(FATAL_ERROR "python3 not found — required for SRP via pysrp")
endif()
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c
        "import sysconfig; print(sysconfig.get_path('include'))"
    OUTPUT_VARIABLE _py_inc OUTPUT_STRIP_TRAILING_WHITESPACE TIMEOUT 10)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c
        "import sysconfig; d=sysconfig.get_config_var; print(d('LIBDIR') + '/' + d('LDLIBRARY'))"
    OUTPUT_VARIABLE _py_lib OUTPUT_STRIP_TRAILING_WHITESPACE TIMEOUT 10)
# Also add Flatpak host paths so CLion's bundled CMake indexer finds Python.h
list(APPEND _py_inc_dirs "${_py_inc}")
string(REPLACE "/usr/" "/run/host/usr/" _py_inc_host "${_py_inc}")
list(APPEND _py_inc_dirs "${_py_inc_host}")

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
target_include_directories(securemsg_crypto PUBLIC ${_py_inc_dirs})
target_link_libraries(securemsg_crypto PUBLIC OpenSSL::SSL OpenSSL::Crypto "${_py_lib}")
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
# Resolve sqlite_orm include dir at configure time so clang-scan-deps sees it during module scanning.
# Generator expressions are not expanded for the module scan command, so we must use a concrete path.
get_target_property(_sqlite_orm_inc sqlite_orm::sqlite_orm INTERFACE_INCLUDE_DIRECTORIES)
if(_sqlite_orm_inc)
    target_include_directories(securemsg_messaging PUBLIC ${_sqlite_orm_inc})
endif()
target_compile_options(securemsg_messaging PRIVATE -Wall -Wextra)

# ── Main logic (pure, testable) ───────────────────────────────────────────────
add_library(securemsg_main_logic)
target_sources(securemsg_main_logic PUBLIC
    FILE_SET CXX_MODULES FILES src/main_logic.cppm)
target_compile_options(securemsg_main_logic PRIVATE -Wall -Wextra)

# ── Blockchain manager ────────────────────────────────────────────────────────
add_library(securemsg_blockchain STATIC src/BlockchainManager.cpp)
target_include_directories(securemsg_blockchain PUBLIC src)
target_link_libraries(securemsg_blockchain PUBLIC nlohmann_json::nlohmann_json CURL::libcurl)

# ── Main binary ───────────────────────────────────────────────────────────────
add_executable(securemsg src/main.cpp)
target_link_libraries(securemsg PRIVATE
    securemsg_models securemsg_crypto securemsg_network securemsg_messaging
    securemsg_main_logic securemsg_blockchain
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
        securemsg_main_logic sqlite_orm::sqlite_orm Catch2::Catch2)
    add_test(NAME cybersec_tests COMMAND cybersec_tests)
endif()
