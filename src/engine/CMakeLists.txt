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
        C_VISIBILITY_PRESET hidden
)

target_include_directories(
    ngi541_engine_objects
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/include
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

target_include_directories(
    ngi541_engine
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(
    ngi541_engine
    PRIVATE
        NGI541::core
)

add_library(
    NGI541::engine
    ALIAS ngi541_engine
)

add_library(
    ngi541_engine_shared SHARED
    $<TARGET_OBJECTS:ngi541_engine_objects>
)

target_include_directories(
    ngi541_engine_shared
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
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

add_library(
    NGI541::engine_shared
    ALIAS ngi541_engine_shared
)