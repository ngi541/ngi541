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
    NGI541_BUILD_ENGINE
    "Build the NGI541 engine layer"
    OFF
)

option(
    NGI541_ENABLE_STRICT_WARNINGS
    "Enable additional compiler warnings"
    ON
)

# ---------------------------------------------------------------------------
# Compiler configuration
# ---------------------------------------------------------------------------

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(NGI541Compiler)

# ---------------------------------------------------------------------------
# Source tree
# ---------------------------------------------------------------------------

add_subdirectory(src)

if(NGI541_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()