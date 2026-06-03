#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

install_if_missing() {
    local manager="$1"
    shift
    local missing=()
    for pkg in "$@"; do
        case "$manager" in
            dnf)     rpm -q "$pkg" &>/dev/null || missing+=("$pkg") ;;
            apt-get) dpkg -s "$pkg" &>/dev/null || missing+=("$pkg") ;;
        esac
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Installing: ${missing[*]}"
        sudo "$manager" install -y "${missing[@]}"
    fi
}

if command -v dnf &>/dev/null; then
    install_if_missing dnf gcc-c++ cmake ninja-build git \
        openssl-devel libcurl-devel nlohmann-json-devel \
        glibc-devel kernel-headers qrencode clang \
        catch2-devel ftxui-devel python3-devel \
        sqlite-devel python3-pip
elif command -v apt-get &>/dev/null; then
    # catch2-dev and libftxui-dev are not in Ubuntu apt — Conan provides them
    install_if_missing apt-get g++ cmake ninja-build git \
        libssl-dev libcurl4-openssl-dev nlohmann-json3-dev libsqlite3-dev \
        linux-libc-dev qrencode clang clang-tools-18 \
        python3-dev python3-pip
else
    echo "Unsupported package manager."
    exit 1
fi

# Build OpenSSL 3.5 if not already installed (required for ML-KEM-1024)
if [ ! -f /usr/local/openssl-3.5/lib64/libssl.so ]; then
    echo "Building OpenSSL 3.5 (required for ML-KEM-1024)..."
    cd /tmp
    wget -q https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
    tar xf openssl-3.5.0.tar.gz
    cd openssl-3.5.0
    ./Configure --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5 shared
    make -j"$(nproc)"
    sudo make install
    cd "$SCRIPT_DIR"
fi

# Install Python dependencies and Conan
pip3 install --quiet srp conan --break-system-packages
if [ ! -f cmake-build-debug/sqlite_ormConfig.cmake ] && [ ! -f cmake-build-debug/sqlite_orm-config.cmake ]; then
    conan profile detect --force >/dev/null 2>&1 || true
    conan install . --output-folder=cmake-build-debug \
        --build=missing \
        -s build_type=Release \
        -s compiler=clang \
        -s compiler.version=18 \
        -s compiler.libcxx=libstdc++11 \
        -s compiler.cppstd=20 \
        -c tools.cmake.cmaketoolchain:generator=Ninja \
        2>&1 | grep -v "^WARN: deprecated"
fi

rm -rf cmake-build-debug/CMakeCache.txt cmake-build-debug/CMakeFiles
cmake -B cmake-build-debug -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=cmake-build-debug/conan_toolchain.cmake \
    -DCMAKE_MAKE_PROGRAM=/usr/bin/ninja \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++-18 \
    -DCMAKE_C_COMPILER=/usr/bin/clang-18 \
    -Wno-dev
/usr/bin/ninja -C cmake-build-debug -j"$(nproc)"
exec env LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64:$LD_LIBRARY_PATH ./cmake-build-debug/securemsg
