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

add_executable(
    ngi541_acvp
    main.c
)

target_link_libraries(
    ngi541_acvp
    PRIVATE
        ngi541_acvp_adapter
)