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
    install_if_missing dnf gcc-c++ cmake make ninja-build git \
        openssl-devel libcurl-devel nlohmann-json-devel \
        glibc-devel kernel-headers qrencode clang \
        catch2-devel ftxui-devel
elif command -v apt-get &>/dev/null; then
    install_if_missing apt-get g++ cmake make ninja-build git \
        libssl-dev libcurl4-openssl-dev nlohmann-json3-dev \
        linux-libc-dev qrencode clang \
        catch2-dev libftxui-dev
else
    echo "Unsupported package manager."
    exit 1
fi

rm -rf cmake-build-debug
cmake -B cmake-build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM=/usr/bin/ninja -DCMAKE_CXX_COMPILER=clang++ -Wno-dev
/usr/bin/ninja -C cmake-build-debug -j"$(nproc)"
exec ./cmake-build-debug/securemsg
