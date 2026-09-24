add_executable(
    ngi541_acvp_aes_cbc_callback_kat_test
    aes_cbc_callback_kat.c
)

target_link_libraries(
    ngi541_acvp_aes_cbc_callback_kat_test
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.aes_cbc_callback_kat
    COMMAND ngi541_acvp_aes_cbc_callback_kat_test
)

add_executable(
    ngi541_acvp_aes_ctr_callback_kat_test
    aes_ctr_callback_kat.c
)

target_link_libraries(
    ngi541_acvp_aes_ctr_callback_kat_test
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.aes_ctr_callback_kat
    COMMAND ngi541_acvp_aes_ctr_callback_kat_test
)

add_executable(
    ngi541_acvp_aes_gcm_callback_kat_test
    aes_gcm_callback_kat.c
)

target_link_libraries(
    ngi541_acvp_aes_gcm_callback_kat_test
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.aes_gcm_callback_kat
    COMMAND ngi541_acvp_aes_gcm_callback_kat_test
)

add_test(
    NAME acvp.aes_gcm_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_gcm_aft.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/aes_gcm_aft_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_aes_gcm_offline.cmake"
)

add_test(
    NAME acvp.sha256_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/sha256_aft.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/sha256_aft_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_sha256_offline.cmake"
)

add_executable(
    ngi541_acvp_sha256_callback_kat
    sha256_callback_kat.c
)

target_link_libraries(
    ngi541_acvp_sha256_callback_kat
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.sha256_callback_kat
    COMMAND ngi541_acvp_sha256_callback_kat
)