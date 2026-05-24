cmake_minimum_required(VERSION 3.16)
project(SecureMsgClient VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(securemsg
    src/main.cpp
    src/User.cpp
    src/Message.cpp
    src/MessageStore.cpp
    src/ApiClient.cpp
    src/CryptoManager.cpp
)

target_include_directories(securemsg PRIVATE include)

target_link_libraries(securemsg PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    nlohmann_json::nlohmann_json
)

target_compile_options(securemsg PRIVATE -Wall -Wextra -Wpedantic)
