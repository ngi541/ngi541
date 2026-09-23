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
endif()