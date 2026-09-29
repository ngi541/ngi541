add_executable(
    ngi541_buffer_geometry_test
    buffer_geometry.c
)

target_link_libraries(
    ngi541_buffer_geometry_test
    PRIVATE
        NGI541::engine
)

add_test(
    NAME robustness.buffer_geometry
    COMMAND ngi541_buffer_geometry_test
)