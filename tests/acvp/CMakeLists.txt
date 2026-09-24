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