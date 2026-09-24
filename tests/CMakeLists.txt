add_executable(
    ngi541_core_compile_test
    compile/core_compile.c
)

target_link_libraries(
    ngi541_core_compile_test
    PRIVATE
        NGI541::core
)

add_test(
    NAME core.compile
    COMMAND ngi541_core_compile_test
)

if(NGI541_BUILD_ENGINE)
    add_subdirectory(engine)

    add_executable(
        ngi541_public_api_compile_test
        public/api_compile.c
    )

    target_link_libraries(
        ngi541_public_api_compile_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME public.api_compile
        COMMAND ngi541_public_api_compile_test
    )

    add_executable(
        ngi541_public_api_runtime_test
        public/api_runtime.c
    )

    target_link_libraries(
        ngi541_public_api_runtime_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME public.api_runtime
        COMMAND ngi541_public_api_runtime_test
    )

    add_executable(
        ngi541_sha256_kat_test
        public/sha256_kat.c
    )

    target_link_libraries(
        ngi541_sha256_kat_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME crypto.sha256_kat
        COMMAND ngi541_sha256_kat_test
    )

    add_executable(
        ngi541_aes_cbc_kat_test
        public/aes_cbc_kat.c
    )

    target_link_libraries(
        ngi541_aes_cbc_kat_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME crypto.aes_cbc_kat
        COMMAND ngi541_aes_cbc_kat_test
    )

    add_executable(
        ngi541_aes_ctr_kat_test
        public/aes_ctr_kat.c
    )

    target_link_libraries(
        ngi541_aes_ctr_kat_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME crypto.aes_ctr_kat
        COMMAND ngi541_aes_ctr_kat_test
    )

    add_executable(
        ngi541_aes_gcm_kat_test
        public/aes_gcm_kat.c
    )

    target_link_libraries(
        ngi541_aes_gcm_kat_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME crypto.aes_gcm_kat
        COMMAND ngi541_aes_gcm_kat_test
    )

    add_executable(
        ngi541_sha224_kat_test
        public/sha224_kat.c
    )

    target_link_libraries(
        ngi541_sha224_kat_test
        PRIVATE
            NGI541::engine
    )

    add_test(
        NAME crypto.sha224_kat
        COMMAND ngi541_sha224_kat_test
    )

    if(NGI541_BUILD_ACVP)
        add_subdirectory(acvp)
    endif()
endif()