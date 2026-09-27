cmake_minimum_required(VERSION 3.20)

project(
    NGI541
    VERSION 0.1.0
    DESCRIPTION "High-performance vectorized cryptographic engine"
    LANGUAGES C
)

# ---------------------------------------------------------------------------
# Global project configuration
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# VPP-derived crypto code relies on compiler extensions such as vector types,
# attributes and GNU/Clang extensions.
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(
    NGI541_BUILD_TESTS
    "Build NGI541 tests"
    ON
)

option(
    NGI541_BUILD_DIFFERENTIAL_TESTS
    "Build NGI541 differential correctness tests"
    OFF
)

option(
    NGI541_BUILD_ENGINE
    "Build the NGI541 engine layer"
    OFF
)

option(
    NGI541_ENABLE_STRICT_WARNINGS
    "Enable additional compiler warnings"
    ON
)

option(
    NGI541_BUILD_ACVP
    "Build NGI541 ACVP validation harness"
    OFF
)

option(
    NGI541_ENABLE_ACVP_ONLINE
    "Build network-enabled ACVTS support"
    OFF
)

set(
    NGI541_ACVP_CURL_ROOT
    ""
    CACHE PATH
    "Optional libcurl installation prefix for online ACVP builds"
)

# ACVP validation is a consumer of the public NGI541 engine API.
# It cannot be built without the engine layer.
if(NGI541_BUILD_ACVP AND NOT NGI541_BUILD_ENGINE)
    message(
        FATAL_ERROR
        "NGI541_BUILD_ACVP requires NGI541_BUILD_ENGINE=ON"
    )
endif()

if(NGI541_ENABLE_ACVP_ONLINE AND NOT NGI541_BUILD_ACVP)
    message(
        FATAL_ERROR
        "NGI541_ENABLE_ACVP_ONLINE requires "
        "NGI541_BUILD_ACVP=ON"
    )
endif()

# ---------------------------------------------------------------------------
# Compiler configuration
# ---------------------------------------------------------------------------

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(NGI541Compiler)

# ---------------------------------------------------------------------------
# Source tree
# ---------------------------------------------------------------------------

add_subdirectory(src)

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

if(NGI541_BUILD_ACVP)
    add_subdirectory(validation/acvp)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(NGI541_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(
    NGI541_BUILD_DIFFERENTIAL_TESTS
    AND
    NOT NGI541_BUILD_TESTS
)
    message(
        FATAL_ERROR
        "NGI541_BUILD_DIFFERENTIAL_TESTS requires "
        "NGI541_BUILD_TESTS=ON"
    )
endif()

if(
    NGI541_BUILD_DIFFERENTIAL_TESTS
    AND
    NOT NGI541_BUILD_ENGINE
)
    message(
        FATAL_ERROR
        "NGI541_BUILD_DIFFERENTIAL_TESTS requires "
        "NGI541_BUILD_ENGINE=ON"
    )
endif()