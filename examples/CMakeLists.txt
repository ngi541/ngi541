add_executable(
    ngi541_example_sha256
    sha256.c
)

target_link_libraries(
    ngi541_example_sha256
    PRIVATE
        NGI541::engine
)


add_executable(
    ngi541_example_aes_ctr
    aes_ctr.c
)

target_link_libraries(
    ngi541_example_aes_ctr
    PRIVATE
        NGI541::engine
)


add_executable(
    ngi541_example_aes_gcm
    aes_gcm.c
)

target_link_libraries(
    ngi541_example_aes_gcm
    PRIVATE
        NGI541::engine
)