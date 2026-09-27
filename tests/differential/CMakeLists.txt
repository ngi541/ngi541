include(NGI541OpenSSL)

ngi541_find_differential_openssl()

add_library(
    ngi541_diff_common
    STATIC

    common/prng.c
    common/corpus.c
    common/test_util.c
)

target_include_directories(
    ngi541_diff_common
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_library(
    ngi541_diff_reference_openssl
    STATIC

    reference/openssl_ref.c
)

target_include_directories(
    ngi541_diff_reference_openssl
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(
    ngi541_diff_reference_openssl
    PUBLIC
        OpenSSL::Crypto
)

add_library(
    ngi541_diff_reference
    STATIC

    reference/reference.c
)

target_include_directories(
    ngi541_diff_reference
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(
    ngi541_diff_reference
    PUBLIC
        ngi541_diff_reference_openssl
)

add_executable(
    ngi541_diff_framework_smoke

    framework_smoke.c
)

target_link_libraries(
    ngi541_diff_framework_smoke
    PRIVATE
        NGI541::engine
        ngi541_diff_common
        ngi541_diff_reference_openssl
)

add_test(
    NAME differential.framework_smoke
    COMMAND ngi541_diff_framework_smoke
)

add_executable(
    ngi541_diff_aes_cbc

    aes_cbc.c
)

target_link_libraries(
    ngi541_diff_aes_cbc
    PRIVATE
        NGI541::engine
        ngi541_diff_common
        ngi541_diff_reference
)

add_test(
    NAME differential.aes_cbc
    COMMAND ngi541_diff_aes_cbc
)

add_executable(
    ngi541_diff_aes_ctr

    aes_ctr.c
)

target_link_libraries(
    ngi541_diff_aes_ctr
    PRIVATE
        NGI541::engine
        ngi541_diff_common
        ngi541_diff_reference
)

add_test(
    NAME differential.aes_ctr
    COMMAND ngi541_diff_aes_ctr
)

add_executable(
    ngi541_diff_aes_gcm

    aes_gcm.c
)

target_link_libraries(
    ngi541_diff_aes_gcm
    PRIVATE
        NGI541::engine
        ngi541_diff_common
        ngi541_diff_reference
)

add_test(
    NAME differential.aes_gcm
    COMMAND ngi541_diff_aes_gcm
)