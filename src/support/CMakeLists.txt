add_library(ngi541_support INTERFACE)

target_include_directories(
    ngi541_support
    INTERFACE
        ${PROJECT_SOURCE_DIR}/src/support
)