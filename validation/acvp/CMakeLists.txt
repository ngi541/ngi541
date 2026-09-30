include(ExternalProject)

find_program(
    NGI541_ACVP_MAKE
    NAMES gmake make
    REQUIRED
)

set(
    NGI541_LIBACVP_SOURCE_DIR
    "${PROJECT_SOURCE_DIR}/third_party/libacvp"
)

set(
    NGI541_LIBACVP_PREFIX
    "${CMAKE_CURRENT_BINARY_DIR}/libacvp"
)

set(
    NGI541_LIBACVP_INSTALL_DIR
    "${NGI541_LIBACVP_PREFIX}/install"
)

if(NOT EXISTS "${NGI541_LIBACVP_SOURCE_DIR}/configure")
    message(
        FATAL_ERROR
        "libacvp submodule is missing. Run: "
        "git submodule update --init --recursive"
    )
endif()

file(
    MAKE_DIRECTORY
    "${NGI541_LIBACVP_INSTALL_DIR}/include"
)

ExternalProject_Add(
    ngi541_libacvp_external

    SOURCE_DIR
        "${NGI541_LIBACVP_SOURCE_DIR}"

    PREFIX
        "${NGI541_LIBACVP_PREFIX}"

    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""

    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env
        "CC=${CMAKE_C_COMPILER}"
        "CPPFLAGS=-I${NGI541_LIBACVP_SOURCE_DIR}/safe_c_stub/include"
        <SOURCE_DIR>/configure
        --prefix=${NGI541_LIBACVP_INSTALL_DIR}
        --disable-app
        --enable-offline
        --disable-shared
        --enable-static

    BUILD_COMMAND
        ${NGI541_ACVP_MAKE}

    INSTALL_COMMAND
        ${NGI541_ACVP_MAKE} install

    BUILD_BYPRODUCTS
        "${NGI541_LIBACVP_INSTALL_DIR}/lib/libacvp.a"
)

add_library(
    ngi541_libacvp
    STATIC
    IMPORTED
    GLOBAL
)

set_target_properties(
    ngi541_libacvp
    PROPERTIES
        IMPORTED_LOCATION
            "${NGI541_LIBACVP_INSTALL_DIR}/lib/libacvp.a"

        INTERFACE_INCLUDE_DIRECTORIES
            "${NGI541_LIBACVP_INSTALL_DIR}/include"
)

if(UNIX AND NOT APPLE)
    target_link_libraries(
        ngi541_libacvp
        INTERFACE
            m
    )
endif()

add_dependencies(
    ngi541_libacvp
    ngi541_libacvp_external
)

# ---------------------------------------------------------------------------
# Optional network-enabled libacvp build
# ---------------------------------------------------------------------------

if(NGI541_ENABLE_ACVP_ONLINE)
    include(NGI541Curl)

    ngi541_resolve_acvp_curl(
        NGI541_ACVP_CURL_ROOT_RESOLVED
    )

    set(
        NGI541_LIBACVP_ONLINE_PREFIX
        "${CMAKE_CURRENT_BINARY_DIR}/libacvp-online"
    )

    set(
        NGI541_LIBACVP_ONLINE_INSTALL_DIR
        "${NGI541_LIBACVP_ONLINE_PREFIX}/install"
    )

    file(
        MAKE_DIRECTORY
        "${NGI541_LIBACVP_ONLINE_INSTALL_DIR}/include"
    )

    ExternalProject_Add(
        ngi541_libacvp_online_external

        SOURCE_DIR
            "${NGI541_LIBACVP_SOURCE_DIR}"

        PREFIX
            "${NGI541_LIBACVP_ONLINE_PREFIX}"

        DOWNLOAD_COMMAND ""
        UPDATE_COMMAND ""
        PATCH_COMMAND ""

        CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
            "CC=${CMAKE_C_COMPILER}"
            "CPPFLAGS=-I${NGI541_LIBACVP_SOURCE_DIR}/safe_c_stub/include"
            <SOURCE_DIR>/configure
            --prefix=${NGI541_LIBACVP_ONLINE_INSTALL_DIR}
            --disable-app
            --with-libcurl-dir=${NGI541_ACVP_CURL_ROOT_RESOLVED}
            --disable-shared
            --enable-static

        BUILD_COMMAND
            ${NGI541_ACVP_MAKE}

        INSTALL_COMMAND
            ${NGI541_ACVP_MAKE} install

        BUILD_BYPRODUCTS
            "${NGI541_LIBACVP_ONLINE_INSTALL_DIR}/lib/libacvp.a"
    )

    add_library(
        ngi541_libacvp_online
        STATIC
        IMPORTED
        GLOBAL
    )

    set_target_properties(
        ngi541_libacvp_online
        PROPERTIES
            IMPORTED_LOCATION
                "${NGI541_LIBACVP_ONLINE_INSTALL_DIR}/lib/libacvp.a"

            INTERFACE_INCLUDE_DIRECTORIES
                "${NGI541_LIBACVP_ONLINE_INSTALL_DIR}/include"
    )

    target_link_libraries(
        ngi541_libacvp_online
        INTERFACE
            CURL::libcurl
    )

    if(UNIX AND NOT APPLE)
        target_link_libraries(
            ngi541_libacvp_online
            INTERFACE
                m
        )
    endif()

    add_dependencies(
        ngi541_libacvp_online
        ngi541_libacvp_online_external
    )
endif()

add_library(
    ngi541_acvp_adapter STATIC

    adapter.c

    callbacks/aes_cbc.c
    callbacks/aes_ctr.c
    callbacks/aes_gcm.c
    callbacks/sha2.c

    registrations/profile_v1.c
)

target_include_directories(
    ngi541_acvp_adapter
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(
    ngi541_acvp_adapter
    PUBLIC
        NGI541::engine
        ngi541_libacvp
)

if(NGI541_ENABLE_ACVP_ONLINE)
    add_library(
        ngi541_acvp_online_adapter
        STATIC

        adapter.c

        callbacks/aes_cbc.c
        callbacks/aes_ctr.c
        callbacks/aes_gcm.c
        callbacks/sha2.c

        registrations/profile_v1.c
    )

    target_include_directories(
        ngi541_acvp_online_adapter
        PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}"
    )

    target_link_libraries(
        ngi541_acvp_online_adapter
        PUBLIC
            NGI541::engine
            ngi541_libacvp_online
    )
endif()

add_executable(
    ngi541_acvp
    main.c
)

target_link_libraries(
    ngi541_acvp
    PRIVATE
        ngi541_acvp_adapter
)

if(NGI541_ENABLE_ACVP_ONLINE)
    add_executable(
        ngi541_acvp_online_probe

        online_build_probe.c
    )

    target_link_libraries(
        ngi541_acvp_online_probe
        PRIVATE
            ngi541_acvp_online_adapter
    )

    # -----------------------------------------------------------------------
    # ACVTS Demo client
    #
    # This target is deliberately separate from the offline ACVP runner and
    # from the no-network online build probe.
    #
    # The TOTP implementation is compiled directly from the pinned libacvp
    # source tree so NGI541 does not maintain an independent TOTP algorithm.
    # -----------------------------------------------------------------------

    add_executable(
        ngi541_acvp_demo

        demo_main.c

        "${NGI541_LIBACVP_SOURCE_DIR}/app/totp/totp.c"
        "${NGI541_LIBACVP_SOURCE_DIR}/app/totp/hmac_sha256.c"
        "${NGI541_LIBACVP_SOURCE_DIR}/app/totp/sha256.c"
    )

    target_include_directories(
        ngi541_acvp_demo
        PRIVATE
            "${NGI541_LIBACVP_SOURCE_DIR}/app"
            "${NGI541_LIBACVP_SOURCE_DIR}/app/totp"
            "${NGI541_LIBACVP_SOURCE_DIR}/safe_c_stub/include"
    )

    target_link_libraries(
        ngi541_acvp_demo
        PRIVATE
            ngi541_acvp_online_adapter
    )
endif()