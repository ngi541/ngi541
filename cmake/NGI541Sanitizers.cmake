# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Ivan Ivanets

include_guard(GLOBAL)

include(CheckCSourceCompiles)


option(
    NGI541_ENABLE_ASAN
    "Enable AddressSanitizer instrumentation"
    OFF
)

option(
    NGI541_ENABLE_UBSAN
    "Enable UndefinedBehaviorSanitizer instrumentation"
    OFF
)


if(NOT NGI541_ENABLE_ASAN AND
   NOT NGI541_ENABLE_UBSAN)
    return()
endif()


if(NOT CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang|GNU)$")
    message(
        FATAL_ERROR
        "NGI541 sanitizers require Clang, AppleClang, or GCC; "
        "current compiler is ${CMAKE_C_COMPILER_ID}"
    )
endif()


function(
    ngi541_sanitizer_configuration_error
    sanitizer_name
)
    message(
        FATAL_ERROR
        "${sanitizer_name} was explicitly requested, but the "
        "compiler/runtime compile-link probe failed.\n"
        "\n"
        "System:        ${CMAKE_SYSTEM_NAME}\n"
        "Architecture:  ${CMAKE_SYSTEM_PROCESSOR}\n"
        "Compiler:      ${CMAKE_C_COMPILER_ID} "
        "${CMAKE_C_COMPILER_VERSION}\n"
        "Compiler path: ${CMAKE_C_COMPILER}\n"
        "\n"
        "Check the sanitizer toolchain with:\n"
        "\n"
        "  CC=${CMAKE_C_COMPILER} "
        "${PROJECT_SOURCE_DIR}/scripts/"
        "bootstrap-sanitizer-deps.sh --check\n"
        "\n"
        "If dependencies are missing on a supported development "
        "environment, run:\n"
        "\n"
        "  ${PROJECT_SOURCE_DIR}/scripts/"
        "bootstrap-sanitizer-deps.sh --install\n"
    )
endfunction()

#
# A sanitizer is not only a compiler feature.
#
# The -fsanitize=<name> option must also be supplied during the
# final link so that the corresponding sanitizer runtime is linked.
#
# Therefore, test both compilation and linking instead of using
# check_c_compiler_flag() alone.
#
function(
    ngi541_check_sanitizer
    sanitizer_name
    result_variable
)
    set(
        sanitizer_flag
        "-fsanitize=${sanitizer_name}"
    )

    set(
        CMAKE_REQUIRED_FLAGS
        "${sanitizer_flag}"
    )

    set(
        CMAKE_REQUIRED_LINK_OPTIONS
        "${sanitizer_flag}"
    )

    check_c_source_compiles(
        "
        int main(void)
        {
          return 0;
        }
        "
        ${result_variable}
    )

    set(
        ${result_variable}
        "${${result_variable}}"
        PARENT_SCOPE
    )
endfunction()


set(
    NGI541_SANITIZER_COMPILE_OPTIONS
)

set(
    NGI541_SANITIZER_LINK_OPTIONS
)

set(
    NGI541_SANITIZER_NAMES
)


if(NGI541_ENABLE_ASAN)
    ngi541_check_sanitizer(
        address
        NGI541_SANITIZER_ADDRESS_AVAILABLE
    )

    if(NOT NGI541_SANITIZER_ADDRESS_AVAILABLE)
        ngi541_sanitizer_configuration_error(
            "AddressSanitizer"
        )
    endif()

    list(
        APPEND
        NGI541_SANITIZER_COMPILE_OPTIONS

        -fsanitize=address
    )

    list(
        APPEND
        NGI541_SANITIZER_LINK_OPTIONS

        -fsanitize=address
    )

    list(
        APPEND
        NGI541_SANITIZER_NAMES

        "AddressSanitizer"
    )
endif()


if(NGI541_ENABLE_UBSAN)
    ngi541_check_sanitizer(
        undefined
        NGI541_SANITIZER_UNDEFINED_AVAILABLE
    )

    if(NOT NGI541_SANITIZER_UNDEFINED_AVAILABLE)
        ngi541_sanitizer_configuration_error(
            "UndefinedBehaviorSanitizer"
        )
    endif()

    list(
        APPEND
        NGI541_SANITIZER_COMPILE_OPTIONS

        -fsanitize=undefined
        -fno-sanitize-recover=all
    )

    list(
        APPEND
        NGI541_SANITIZER_LINK_OPTIONS

        -fsanitize=undefined
    )

    list(
        APPEND
        NGI541_SANITIZER_NAMES

        "UndefinedBehaviorSanitizer"
    )
endif()


list(
    APPEND
    NGI541_SANITIZER_COMPILE_OPTIONS

    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
)


add_compile_options(
    ${NGI541_SANITIZER_COMPILE_OPTIONS}
)

add_link_options(
    ${NGI541_SANITIZER_LINK_OPTIONS}
)


string(
    JOIN
    ", "
    NGI541_SANITIZER_SUMMARY
    ${NGI541_SANITIZER_NAMES}
)

message(
    STATUS
    "NGI541 sanitizers enabled: ${NGI541_SANITIZER_SUMMARY}"
)