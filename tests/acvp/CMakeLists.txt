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
    ngi541_acvp_aes_cbc_ctr_callback_negative_test
    aes_cbc_ctr_callback_negative.c
)

target_link_libraries(
    ngi541_acvp_aes_cbc_ctr_callback_negative_test
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.aes_cbc_ctr_callback_negative
    COMMAND
        ngi541_acvp_aes_cbc_ctr_callback_negative_test
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

add_executable(
    ngi541_acvp_aes_gcm_callback_negative_test
    aes_gcm_callback_negative.c
)

target_link_libraries(
    ngi541_acvp_aes_gcm_callback_negative_test
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.aes_gcm_callback_negative
    COMMAND
        ngi541_acvp_aes_gcm_callback_negative_test
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
    NAME acvp.aes_gcm_complete_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_gcm_complete_aft.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/aes_gcm_complete_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_aes_gcm_complete_offline.cmake"
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

add_test(
    NAME acvp.sha224_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/sha224_aft.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/sha224_aft_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_sha224_offline.cmake"
)

add_test(
    NAME acvp.aes_ctr_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_ctr_ctr.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/aes_ctr_ctr_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_aes_ctr_offline.cmake"
)

add_test(
    NAME acvp.aes_cbc_mct_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_cbc_mct.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/aes_cbc_mct_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_aes_cbc_mct_offline.cmake"
)

add_test(
    NAME acvp.sha256_mct_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/sha256_mct.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/sha256_mct_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_sha256_mct_offline.cmake"
)

add_test(
    NAME acvp.sha224_mct_offline
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        "-DNGI541_ACVP_REQUEST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/sha224_mct.json"
        "-DNGI541_ACVP_RESPONSE=${CMAKE_CURRENT_BINARY_DIR}/sha224_mct_response.json"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_sha224_mct_offline.cmake"
)

add_test(
    NAME acvp.registration
    COMMAND
        ${CMAKE_COMMAND}
        "-DNGI541_ACVP_RUNNER=$<TARGET_FILE:ngi541_acvp>"
        -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify_registration.cmake"
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

add_executable(
    ngi541_acvp_sha224_callback_kat
    sha224_callback_kat.c
)

target_link_libraries(
    ngi541_acvp_sha224_callback_kat
    PRIVATE
        ngi541_acvp_adapter
)

add_test(
    NAME acvp.sha224_callback_kat
    COMMAND ngi541_acvp_sha224_callback_kat
)

add_executable(
    ngi541_acvp_sha_callback_negative_test

    sha_callback_negative.c
)

target_link_libraries(
    ngi541_acvp_sha_callback_negative_test

    PRIVATE

        ngi541_acvp_adapter
)

add_test(
    NAME acvp.sha_callback_negative

    COMMAND
        ngi541_acvp_sha_callback_negative_test
)

if(NGI541_ENABLE_ACVP_ONLINE)
    add_test(
        NAME acvp.online_build_probe

        COMMAND
            ngi541_acvp_online_probe
    )
endif()