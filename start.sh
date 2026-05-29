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
    install_if_missing dnf gcc-c++ cmake make git openssl-devel libcurl-devel nlohmann-json-devel qrencode glibc-devel kernel-headers
elif command -v apt-get &>/dev/null; then
    install_if_missing apt-get g++ cmake make git libssl-dev libcurl4-openssl-dev nlohmann-json3-dev qrencode linux-libc-dev
else
    echo "Unsupported package manager — install dependencies manually."
    exit 1
fi

rm -rf cmake-build-debug
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles" -Wno-dev
cmake --build cmake-build-debug -j"$(nproc)"

exec ./cmake-build-debug/securemsg
