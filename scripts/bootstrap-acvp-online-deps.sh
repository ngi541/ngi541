#!/usr/bin/env bash

set -euo pipefail

log()
{
    printf '==> %s\n' "$*"
}

fail()
{
    printf 'error: %s\n' "$*" >&2
    exit 1
}

have_pkg_config_curl()
{
    command -v pkg-config >/dev/null 2>&1 &&
        pkg-config --exists libcurl
}

case "$(uname -s)" in
    Darwin)
        if ! command -v brew >/dev/null 2>&1; then
            fail "Homebrew is required to bootstrap libcurl on macOS"
        fi

        if brew --prefix curl >/dev/null 2>&1; then
            log "libcurl already available through Homebrew"
        else
            log "Installing libcurl through Homebrew"
            brew install curl
        fi

        curl_root="$(brew --prefix curl)"

        log "libcurl prefix: ${curl_root}"

        ;;

    Linux)
        if have_pkg_config_curl; then
            log "libcurl development files already available"
            pkg-config --modversion libcurl
            exit 0
        fi

        if command -v apt-get >/dev/null 2>&1; then
            log "Installing libcurl development dependencies with apt"

            sudo apt-get update

            sudo apt-get install -y \
                pkg-config \
                libcurl4-openssl-dev

        elif command -v dnf >/dev/null 2>&1; then
            log "Installing libcurl development dependencies with dnf"

            sudo dnf install -y \
                pkgconf-pkg-config \
                libcurl-devel

        elif command -v yum >/dev/null 2>&1; then
            log "Installing libcurl development dependencies with yum"

            sudo yum install -y \
                pkgconfig \
                libcurl-devel

        elif command -v pacman >/dev/null 2>&1; then
            log "Installing libcurl development dependencies with pacman"

            sudo pacman \
                --sync \
                --refresh \
                --noconfirm \
                curl \
                pkgconf

        else
            fail \
                "No supported package manager found. Install the libcurl development package manually."
        fi

        if ! have_pkg_config_curl; then
            fail "libcurl installation completed but pkg-config cannot resolve libcurl"
        fi

        log "libcurl development files are available"
        pkg-config --modversion libcurl

        ;;

    *)
        fail "Automatic online ACVP dependency bootstrap is unsupported on $(uname -s)"
        ;;
esac