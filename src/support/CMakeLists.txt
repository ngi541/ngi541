add_library(
    ngi541_support STATIC
    compat/string.c
)

add_library(
    NGI541::support
    ALIAS ngi541_support
)

target_include_directories(
    ngi541_support
    PUBLIC
        ${PROJECT_SOURCE_DIR}/src/support
)

set_target_properties(
    ngi541_support
    PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)