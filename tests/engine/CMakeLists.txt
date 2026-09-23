add_executable(
    ngi541_engine_smoke

    engine_smoke.c

    $<TARGET_OBJECTS:ngi541_engine_objects>
)

target_include_directories(
    ngi541_engine_smoke
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    ngi541_engine_smoke
    PRIVATE
        NGI541::core
)

add_test(
    NAME engine.smoke
    COMMAND ngi541_engine_smoke
)

add_executable(
    ngi541_engine_dlopen_smoke
    engine_dlopen_smoke.c
)

target_include_directories(
    ngi541_engine_dlopen_smoke
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/src/support
)

target_link_libraries(
    ngi541_engine_dlopen_smoke
    PRIVATE
        ${CMAKE_DL_LIBS}
)

add_dependencies(
    ngi541_engine_dlopen_smoke
    ngi541_engine_shared
)

add_test(
    NAME engine.dlopen
    COMMAND
        ngi541_engine_dlopen_smoke
        $<TARGET_FILE:ngi541_engine_shared>
)