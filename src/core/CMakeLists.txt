# ---------------------------------------------------------------------------
# Crypto ISA requirements
# ---------------------------------------------------------------------------

add_library(ngi541_crypto_isa INTERFACE)

ngi541_configure_crypto_isa(
    ngi541_crypto_isa
)

# ---------------------------------------------------------------------------
# Cryptographic core
# ---------------------------------------------------------------------------

add_library(ngi541_core INTERFACE)

add_library(
    NGI541::core
    ALIAS ngi541_core
)

target_include_directories(
    ngi541_core
    INTERFACE
        ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    ngi541_core
    INTERFACE
        NGI541::support
        ngi541_crypto_isa
)