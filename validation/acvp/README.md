# NGI541 ACVP validation adapter

This directory contains the ACVP validation layer for NGI541.

The validation layer is not part of the NGI541 production crypto ABI.

Dependency direction:

libacvp -> NGI541 ACVP adapter -> public NGI541 API

The adapter must not include NGI541 internal engine, provider, handler,
core, or VPP compatibility headers.

## libacvp

Pinned as a Git submodule under:

    third_party/libacvp

Initial release:

    libacvp v2.3.1

The exact dependency revision is recorded by the Git submodule commit.

## Build

ACVP validation is disabled by default:

    -DNGI541_BUILD_ACVP=OFF

Enable it explicitly with:

    -DNGI541_BUILD_ENGINE=ON
    -DNGI541_BUILD_ACVP=ON