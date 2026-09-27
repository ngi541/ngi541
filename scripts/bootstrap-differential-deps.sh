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


run_privileged()
{
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return
    fi

    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
        return
    fi

    fail "Root privileges are required to install system packages"
}


have_openssl3_pkgconfig()
{
    command -v pkg-config >/dev/null 2>&1 &&
        pkg-config --exists openssl &&
        pkg-config --atleast-version=3.0 openssl
}


show_pkgconfig_version()
{
    if command -v pkg-config >/dev/null 2>&1 &&
       pkg-config --exists openssl; then
        printf 'OpenSSL pkg-config version: '
        pkg-config --modversion openssl
    fi
}


case "$(uname -s)" in
    Darwin)
        if ! command -v brew >/dev/null 2>&1; then
            fail \
                "Homebrew was not found. Install OpenSSL >= 3.0 manually " \
                "or provide OPENSSL_ROOT_DIR when configuring NGI541."
        fi

        if brew list --versions openssl@3 >/dev/null 2>&1; then
            log "OpenSSL 3 is already installed through Homebrew"
        else
            log "Installing OpenSSL 3 through Homebrew"
            brew install openssl@3
        fi

        openssl_root="$(brew --prefix openssl@3)"

        if [ ! -f "${openssl_root}/include/openssl/crypto.h" ]; then
            fail \
                "Homebrew OpenSSL installation does not contain " \
                "include/openssl/crypto.h"
        fi

        log "OpenSSL root: ${openssl_root}"

        if [ -x "${openssl_root}/bin/openssl" ]; then
            "${openssl_root}/bin/openssl" version
        fi
        ;;


    Linux)
        if have_openssl3_pkgconfig; then
            log "OpenSSL >= 3.0 development files are already available"
            show_pkgconfig_version
            exit 0
        fi

        if command -v apt-get >/dev/null 2>&1; then
            log "Installing OpenSSL development dependencies with apt"

            run_privileged apt-get update

            run_privileged apt-get install -y \
                pkg-config \
                libssl-dev

        elif command -v dnf >/dev/null 2>&1; then
            log "Installing OpenSSL development dependencies with dnf"

            run_privileged dnf install -y \
                pkgconf-pkg-config \
                openssl-devel

        elif command -v yum >/dev/null 2>&1; then
            log "Installing OpenSSL development dependencies with yum"

            run_privileged yum install -y \
                pkgconfig \
                openssl-devel

        elif command -v pacman >/dev/null 2>&1; then
            log "Installing OpenSSL development dependencies with pacman"

            run_privileged pacman \
                -S \
                --needed \
                --noconfirm \
                pkgconf \
                openssl

        elif command -v apk >/dev/null 2>&1; then
            log "Installing OpenSSL development dependencies with apk"

            run_privileged apk add \
                --no-cache \
                pkgconf \
                openssl-dev

        else
            fail \
                "No supported package manager was found. Install OpenSSL " \
                ">= 3.0 development files manually."
        fi

        if ! have_openssl3_pkgconfig; then
            show_pkgconfig_version

            fail \
                "OpenSSL development files were installed, but version " \
                "3.0 or newer is not available."
        fi

        log "OpenSSL >= 3.0 development files are available"
        show_pkgconfig_version
        ;;


    *)
        fail \
            "Automatic differential dependency bootstrap is unsupported " \
            "on $(uname -s)"
        ;;
esac