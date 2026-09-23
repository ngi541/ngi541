# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Ivan Ivanets

include(CheckCCompilerFlag)

# ---------------------------------------------------------------------------
# General compiler configuration
# ---------------------------------------------------------------------------

if(CMAKE_C_COMPILER_ID MATCHES "Clang|AppleClang|GNU")

    add_compile_options(
        -fno-strict-aliasing
    )

    if(NGI541_ENABLE_STRICT_WARNINGS)
        add_compile_options(
            -Wall
            -Wextra
            -Wshadow
            -Wpointer-arith
            -Wcast-align
            -Wstrict-prototypes
            -Wmissing-prototypes
            -Wno-unused-function
            -Wno-unused-parameter
        )
    endif()

else()
    message(
        WARNING
        "NGI541 currently targets GCC/Clang-compatible compilers. "
        "Compiler '${CMAKE_C_COMPILER_ID}' is not yet validated."
    )
endif()

# ---------------------------------------------------------------------------
# ISA configuration helpers
# ---------------------------------------------------------------------------

function(ngi541_require_compiler_flag flag result_var)

    check_c_compiler_flag("${flag}" ${result_var})

    if(NOT ${result_var})
        message(
            FATAL_ERROR
            "Compiler '${CMAKE_C_COMPILER_ID}' does not support required "
            "NGI541 compiler flag '${flag}'"
        )
    endif()

endfunction()


function(ngi541_configure_crypto_isa target)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")

        ngi541_require_compiler_flag(
            "-msse4.2"
            NGI541_COMPILER_HAS_SSE42
        )

        ngi541_require_compiler_flag(
            "-maes"
            NGI541_COMPILER_HAS_AES
        )

        ngi541_require_compiler_flag(
            "-mpclmul"
            NGI541_COMPILER_HAS_PCLMUL
        )

        target_compile_options(
            ${target}
            INTERFACE
                -msse4.2
                -maes
                -mpclmul
        )

        message(
            STATUS
            "NGI541 x86 crypto baseline: SSE4.2 + AES-NI + PCLMULQDQ"
        )

    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")

        message(
            STATUS
            "NGI541 ARM64 crypto configuration will use the ARM crypto path"
        )

    else()

        message(
            FATAL_ERROR
            "Unsupported NGI541 architecture: ${CMAKE_SYSTEM_PROCESSOR}"
        )

    endif()

endfunction()