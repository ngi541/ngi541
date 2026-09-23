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
endif()