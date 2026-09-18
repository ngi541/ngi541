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
    NAME ngi541_engine_smoke
    COMMAND ngi541_engine_smoke
)