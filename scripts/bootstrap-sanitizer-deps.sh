#!/usr/bin/env bash

set -euo pipefail


MODE="check"
COMPILER="auto"


usage()
{
    cat <<'EOF'
Usage:
  bootstrap-sanitizer-deps.sh [options]

Options:
  --check
      Check sanitizer dependencies and capabilities.
      This is the default mode and does not modify the system.

  --install
      Install sanitizer toolchain dependencies where automatic
      installation is supported.

  --compiler <auto|clang|gcc>
      Select the compiler toolchain.

      auto:
        uses CC when set;
        otherwise Clang is preferred.

  -h, --help
      Show this help.
EOF
}


fail()
{
    echo "error: $*" >&2
    exit 1
}


info()
{
    echo "==> $*"
}


while [ "$#" -gt 0 ]; do
    case "$1" in
        --check)
            MODE="check"
            ;;

        --install)
            MODE="install"
            ;;

        --compiler)
            shift

            if [ "$#" -eq 0 ]; then
                fail "--compiler requires an argument"
            fi

            COMPILER="$1"
            ;;

        --compiler=*)
            COMPILER="${1#*=}"
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        *)
            fail "unknown argument: $1"
            ;;
    esac

    shift
done


case "${COMPILER}" in
    auto|clang|gcc)
        ;;

    *)
        fail "unsupported compiler selection: ${COMPILER}"
        ;;
esac


OS_NAME="$(uname -s)"
OS_ARCH="$(uname -m)"


info "Operating system: ${OS_NAME}"
info "Architecture:     ${OS_ARCH}"
info "Mode:             ${MODE}"
info "Compiler request: ${COMPILER}"


install_linux_dependencies()
{
    local selected_compiler="$1"
    local -a packages
    local -a privilege

    if ! command -v apt-get >/dev/null 2>&1; then
        fail \
            "automatic dependency installation currently supports " \
            "apt-based Linux distributions only; install the selected " \
            "compiler and sanitizer runtime with the system package manager"
    fi

    packages=()

    case "${selected_compiler}" in
        clang)
            packages+=(
                clang
                libclang-rt-dev
            )
            ;;

        gcc)
            #
            # Do not hard-code libasanN/libubsanN here.
            #
            # Their package ABI names differ between GCC/distribution
            # versions. The distribution GCC package resolves the
            # appropriate runtime dependencies, and the capability probe
            # below verifies the actual result.
            #
            packages+=(
                gcc
            )
            ;;

        *)
            fail "internal error: unsupported Linux compiler"
            ;;
    esac

    if [ "$(id -u)" -eq 0 ]; then
        privilege=()
    elif command -v sudo >/dev/null 2>&1; then
        privilege=(sudo)
    else
        fail \
            "root privileges or sudo are required for --install"
    fi

    info "Updating apt package metadata"

    "${privilege[@]}" apt-get update

    info "Installing sanitizer dependencies: ${packages[*]}"

    "${privilege[@]}" apt-get install -y \
        "${packages[@]}"
}


check_darwin_toolchain()
{
    if ! command -v xcrun >/dev/null 2>&1; then
        cat >&2 <<'EOF'
error: Apple developer command-line tools are not available.

Install them with:

  xcode-select --install

Then rerun this script.
EOF
        exit 1
    fi

    if ! xcrun --find clang >/dev/null 2>&1; then
        cat >&2 <<'EOF'
error: Apple Clang could not be located.

Install or update the Xcode Command Line Tools:

  xcode-select --install

Then rerun this script.
EOF
        exit 1
    fi
}


resolve_compiler()
{
    local candidate

    if [ "${COMPILER}" = "auto" ]; then
        if [ -n "${CC:-}" ]; then
            candidate="${CC}"
        else
            case "${OS_NAME}" in
                Darwin)
                    candidate="/usr/bin/clang"
                    ;;

                *)
                    if command -v clang >/dev/null 2>&1; then
                        candidate="clang"
                    elif command -v gcc >/dev/null 2>&1; then
                        candidate="gcc"
                    else
                        return 1
                    fi
                    ;;
            esac
        fi
    else
        case "${COMPILER}" in
            clang)
                if [ "${OS_NAME}" = "Darwin" ] &&
                   [ -x /usr/bin/clang ]; then
                    candidate="/usr/bin/clang"
                else
                    candidate="clang"
                fi
                ;;

            gcc)
                candidate="gcc"
                ;;
        esac
    fi

    if [[ "${candidate}" == */* ]]; then
        if [ ! -x "${candidate}" ]; then
            return 1
        fi

        printf '%s\n' "${candidate}"
        return 0
    fi

    command -v "${candidate}"
}


requested_install_compiler()
{
    if [ "${COMPILER}" != "auto" ]; then
        printf '%s\n' "${COMPILER}"
        return
    fi

    #
    # Clang is the canonical sanitizer toolchain for NGI541.
    #
    printf '%s\n' "clang"
}


if [ "${MODE}" = "install" ]; then
    install_compiler="$(requested_install_compiler)"

    case "${OS_NAME}" in
        Linux)
            install_linux_dependencies \
                "${install_compiler}"
            ;;

        Darwin)
            #
            # Xcode Command Line Tools installation is interactive and is
            # intentionally not launched implicitly by this script.
            #
            check_darwin_toolchain
            ;;

        *)
            fail \
                "automatic sanitizer dependency installation is not " \
                "implemented for ${OS_NAME}; use the platform package " \
                "manager and rerun this script with --check"
            ;;
    esac
fi


if [ "${OS_NAME}" = "Darwin" ]; then
    check_darwin_toolchain
fi


if ! CC_PATH="$(resolve_compiler)"; then
    cat >&2 <<EOF
error: requested compiler is unavailable.

OS:       ${OS_NAME}
compiler: ${COMPILER}

Install the compiler toolchain or run:

  $0 --install --compiler ${COMPILER}
EOF

    exit 1
fi


info "Compiler: ${CC_PATH}"

"${CC_PATH}" --version | head -n 1


TMPDIR_SANITIZER="$(
    mktemp -d \
        "${TMPDIR:-/tmp}/ngi541-sanitizer.XXXXXX"
)"

trap 'rm -rf "${TMPDIR_SANITIZER}"' EXIT


PROBE_SOURCE="${TMPDIR_SANITIZER}/probe.c"

cat > "${PROBE_SOURCE}" <<'EOF'
#include <stddef.h>
#include <stdint.h>

int
main (void)
{
    volatile uint32_t value = 1;

    return value == 1 ? 0 : 1;
}
EOF


probe_sanitizer()
{
    local name="$1"
    shift

    local binary
    local log

    binary="${TMPDIR_SANITIZER}/probe-${name}"
    log="${TMPDIR_SANITIZER}/probe-${name}.log"

    info "Checking ${name}"

    if ! "${CC_PATH}" \
        -g \
        -fno-omit-frame-pointer \
        "$@" \
        "${PROBE_SOURCE}" \
        -o "${binary}" \
        >"${log}" 2>&1; then

        cat "${log}" >&2

        echo >&2
        echo "error: ${name} compile/link probe failed" >&2
        echo "compiler: ${CC_PATH}" >&2
        echo "OS:       ${OS_NAME}" >&2

        exit 1
    fi

    if ! "${binary}" >"${log}" 2>&1; then
        cat "${log}" >&2

        echo >&2
        echo "error: ${name} runtime probe failed" >&2
        echo "compiler: ${CC_PATH}" >&2
        echo "OS:       ${OS_NAME}" >&2

        exit 1
    fi

    echo "PASS: ${name}"
}


probe_sanitizer \
    "AddressSanitizer" \
    -fsanitize=address


probe_sanitizer \
    "UndefinedBehaviorSanitizer" \
    -fsanitize=undefined \
    -fno-sanitize-recover=all


probe_sanitizer \
    "AddressSanitizer+UndefinedBehaviorSanitizer" \
    -fsanitize=address \
    -fsanitize=undefined \
    -fno-sanitize-recover=all


echo
echo "Sanitizer dependency check passed"
echo "OS:           ${OS_NAME}"
echo "architecture: ${OS_ARCH}"
echo "compiler:     ${CC_PATH}"