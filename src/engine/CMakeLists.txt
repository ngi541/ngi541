add_library(
    ngi541_engine STATIC

    crypto.c
    main.c
    native.c

    handlers/aes_cbc.c
    handlers/aes_ctr.c
    handlers/aes_gcm.c
    handlers/sha2.c
)

add_library(NGI541::engine ALIAS ngi541_engine)

target_include_directories(
    ngi541_engine

    PRIVATE
        ${PROJECT_SOURCE_DIR}/src

    PUBLIC
        ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    ngi541_engine

    PRIVATE
        NGI541::core
)