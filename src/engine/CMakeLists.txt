add_library(
    ngi541_engine_objects OBJECT

    native.c

    handlers/aes_cbc.c
    handlers/aes_ctr.c
    handlers/aes_gcm.c
    handlers/sha2.c
)

set_target_properties(
    ngi541_engine_objects
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(
    ngi541_engine_objects
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    ngi541_engine_objects
    PRIVATE
        NGI541::core
)

add_library(
    ngi541_engine STATIC
    $<TARGET_OBJECTS:ngi541_engine_objects>
)

add_library(
    NGI541::engine
    ALIAS ngi541_engine
)

target_link_libraries(
    ngi541_engine
    PRIVATE
        NGI541::core
)

add_library(
    ngi541_engine_shared SHARED
    $<TARGET_OBJECTS:ngi541_engine_objects>
)

add_library(
    NGI541::engine_shared
    ALIAS ngi541_engine_shared
)

target_link_libraries(
    ngi541_engine_shared
    PRIVATE
        NGI541::core
)

set_target_properties(
    ngi541_engine_shared
    PROPERTIES
        OUTPUT_NAME ngi541_engine
)
