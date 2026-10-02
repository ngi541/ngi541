cmake_minimum_required(VERSION 3.20)

project(
    NGI541
    VERSION 0.1.0
    DESCRIPTION "Verification-first, performance-oriented cryptographic execution engine"
    LANGUAGES C
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

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
    NGI541_BUILD_EXAMPLES
    "Build NGI541 public API examples"
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

if(NGI541_BUILD_EXAMPLES AND NOT NGI541_BUILD_ENGINE)
    message(
        FATAL_ERROR
        "NGI541_BUILD_EXAMPLES requires NGI541_BUILD_ENGINE=ON"
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

include(NGI541Sanitizers)

# ---------------------------------------------------------------------------
# Source tree
# ---------------------------------------------------------------------------

add_subdirectory(src)

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(NGI541_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

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

# ---------------------------------------------------------------------------
# Installation and CMake package
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Installation and CMake package
# ---------------------------------------------------------------------------

if(NGI541_BUILD_ENGINE)
    set(
        NGI541_INSTALL_CMAKEDIR
        "${CMAKE_INSTALL_LIBDIR}/cmake/NGI541"
    )

    set(
        NGI541_THIRD_PARTY_NOTICES_FILE
        "${PROJECT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
    )

    set(
        NGI541_DOCUMENTATION_ROOT_FILES
        "${PROJECT_SOURCE_DIR}/README.md"
        "${PROJECT_SOURCE_DIR}/CHANGELOG.md"
    )

    set(
        NGI541_DOCUMENTATION_TECHNICAL_FILES
        "${PROJECT_SOURCE_DIR}/docs/architecture.md"
        "${PROJECT_SOURCE_DIR}/docs/validation.md"
        "${PROJECT_SOURCE_DIR}/docs/API.md"
        "${PROJECT_SOURCE_DIR}/docs/ABI.md"
        "${PROJECT_SOURCE_DIR}/docs/PLATFORMS.md"
        "${PROJECT_SOURCE_DIR}/docs/performance.md"
        "${PROJECT_SOURCE_DIR}/docs/roadmap.md"
    )

    set(
        NGI541_DOCUMENTATION_LEGAL_FILES
        "${PROJECT_SOURCE_DIR}/docs/legal/DEVELOPMENT_POLICY.md"
        "${PROJECT_SOURCE_DIR}/docs/legal/PROVENANCE.md"
    )

    set(
        NGI541_DOCUMENTATION_BRAND_FILES
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/README.md"
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/logo-dark.svg"
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/logo-light.svg"
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/mark-avatar.svg"
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/mark-dark.svg"
        "${PROJECT_SOURCE_DIR}/docs/assets/brand/mark-light.svg"
    )

    set(
        NGI541_DOCUMENTATION_EXAMPLE_FILES
        "${PROJECT_SOURCE_DIR}/examples/README.md"
        "${PROJECT_SOURCE_DIR}/examples/sha256.c"
        "${PROJECT_SOURCE_DIR}/examples/aes_ctr.c"
        "${PROJECT_SOURCE_DIR}/examples/aes_gcm.c"
    )

    set(
        NGI541_REQUIRED_INSTALL_FILES
        "${PROJECT_SOURCE_DIR}/LICENSE"
        "${NGI541_THIRD_PARTY_NOTICES_FILE}"
        ${NGI541_DOCUMENTATION_ROOT_FILES}
        ${NGI541_DOCUMENTATION_TECHNICAL_FILES}
        ${NGI541_DOCUMENTATION_LEGAL_FILES}
        ${NGI541_DOCUMENTATION_BRAND_FILES}
        ${NGI541_DOCUMENTATION_EXAMPLE_FILES}
    )

    foreach(
        required_install_file
        IN LISTS
            NGI541_REQUIRED_INSTALL_FILES
    )
        if(NOT EXISTS "${required_install_file}")
            message(
                FATAL_ERROR
                "Required installation file does not exist: "
                "${required_install_file}"
            )
        endif()
    endforeach()

    if(UNIX)
        set(
            NGI541_INSTALL_PKGCONFIGDIR
            "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
        )
    endif()

    # -----------------------------------------------------------------------
    # Runtime component
    # -----------------------------------------------------------------------

    install(
        TARGETS
            ngi541_engine_shared
        EXPORT
            NGI541Targets
        LIBRARY
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            COMPONENT Runtime
            NAMELINK_COMPONENT Development
        RUNTIME
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT Runtime
        ARCHIVE
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            COMPONENT Development
    )

    # Licensing material must accompany redistributable runtime artifacts.
    install(
        FILES
            "${PROJECT_SOURCE_DIR}/LICENSE"
            "${NGI541_THIRD_PARTY_NOTICES_FILE}"
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}"
        COMPONENT
            Runtime
    )

    # -----------------------------------------------------------------------
    # Development component
    # -----------------------------------------------------------------------

    install(
        TARGETS
            ngi541_engine
            ngi541_support
        EXPORT
            NGI541Targets
        ARCHIVE
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            COMPONENT Development
    )

    # Internal interface targets do not install binary artifacts, but they
    # must remain part of the exported target graph required by
    # NGI541::engine.
    install(
        TARGETS
            ngi541_core
            ngi541_crypto_isa
        EXPORT
            NGI541Targets
    )

    install(
        DIRECTORY
            "${PROJECT_SOURCE_DIR}/include/ngi541"
        DESTINATION
            "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT
            Development
        FILES_MATCHING
            PATTERN "*.h"
    )

    # -----------------------------------------------------------------------
    # CMake package metadata
    # -----------------------------------------------------------------------

    configure_package_config_file(
        "${PROJECT_SOURCE_DIR}/cmake/NGI541Config.cmake.in"
        "${PROJECT_BINARY_DIR}/NGI541Config.cmake"
        INSTALL_DESTINATION
            "${NGI541_INSTALL_CMAKEDIR}"
    )

    write_basic_package_version_file(
        "${PROJECT_BINARY_DIR}/NGI541ConfigVersion.cmake"
        VERSION
            "${PROJECT_VERSION}"
        COMPATIBILITY
            SameMinorVersion
    )

    if(UNIX)
        configure_file(
            "${PROJECT_SOURCE_DIR}/cmake/ngi541.pc.in"
            "${PROJECT_BINARY_DIR}/ngi541.pc"
            @ONLY
        )
    endif()

    install(
        EXPORT
            NGI541Targets
        FILE
            NGI541Targets.cmake
        NAMESPACE
            NGI541::
        DESTINATION
            "${NGI541_INSTALL_CMAKEDIR}"
        COMPONENT
            Development
    )

    install(
        FILES
            "${PROJECT_BINARY_DIR}/NGI541Config.cmake"
            "${PROJECT_BINARY_DIR}/NGI541ConfigVersion.cmake"
        DESTINATION
            "${NGI541_INSTALL_CMAKEDIR}"
        COMPONENT
            Development
    )

    if(UNIX)
        install(
            FILES
                "${PROJECT_BINARY_DIR}/ngi541.pc"
            DESTINATION
                "${NGI541_INSTALL_PKGCONFIGDIR}"
            COMPONENT
                Development
        )
    endif()

    # -----------------------------------------------------------------------
    # Documentation component
    # -----------------------------------------------------------------------

    install(
        FILES
            ${NGI541_DOCUMENTATION_ROOT_FILES}
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}"
        COMPONENT
            Documentation
    )

    install(
        FILES
            ${NGI541_DOCUMENTATION_TECHNICAL_FILES}
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}/docs"
        COMPONENT
            Documentation
    )

    install(
        FILES
            ${NGI541_DOCUMENTATION_LEGAL_FILES}
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}/docs/legal"
        COMPONENT
            Documentation
    )

    install(
        FILES
            ${NGI541_DOCUMENTATION_BRAND_FILES}
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}/docs/assets/brand"
        COMPONENT
            Documentation
    )

    install(
        FILES
            ${NGI541_DOCUMENTATION_EXAMPLE_FILES}
        DESTINATION
            "${CMAKE_INSTALL_DOCDIR}/examples"
        COMPONENT
            Documentation
    )

    # -----------------------------------------------------------------------
    # Uninstall target
    # -----------------------------------------------------------------------

    configure_file(
        "${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
        "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake"
        @ONLY
    )

    add_custom_target(
        uninstall
        COMMAND
            "${CMAKE_COMMAND}"
            -P
            "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake"
        COMMENT
            "Uninstall NGI541 files recorded in install_manifest.txt"
        VERBATIM
    )
endif()