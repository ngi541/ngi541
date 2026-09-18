add_library(
    ngi541_engine_objects OBJECT

    native.c

    handlers/aes_cbc.c
    handlers/aes_ctr.c
    handlers/aes_gcm.c
    handlers/sha2.c
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