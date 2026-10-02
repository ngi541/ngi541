<p align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="docs/assets/brand/logo-dark.svg">
    <source
      media="(prefers-color-scheme: light)"
      srcset="docs/assets/brand/logo-light.svg">
    <img
      src="docs/assets/brand/logo-light.svg"
      alt="NGI541"
      width="520">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/ngi541/ngi541/actions/workflows/ci.yml?query=branch%3Amain">
    <img
      alt="CI"
      src="https://github.com/ngi541/ngi541/actions/workflows/ci.yml/badge.svg?branch=main&event=push">
  </a>
  <img alt="Project status" src="https://img.shields.io/badge/status-active%20development-2ea44f">
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue">
  </a>
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1.1-blue">
</p>

<p align="center">
  <a href="validation/evidence/acvts-demo/README.md">
    <img alt="NIST ACVTS Demo A11030" src="https://img.shields.io/badge/NIST%20ACVTS%20Demo-A11030-6f42c1">
  </a>
  <a href="https://ngi541.org">
    <img alt="Website" src="https://img.shields.io/badge/website-ngi541.org-1f6feb">
  </a>
</p>

# NGI541

**NGI541 is a verification-first, performance-oriented cryptographic execution engine designed for networking and data-plane workloads.**

It provides an independent public execution API, SIMD/ISA-oriented native cryptographic execution, standards-facing ACVP validation, and reproducible correctness and robustness evidence.

NGI541 is derived from selected cryptographic components of the FD.io VPP native crypto implementation, but operates independently of the VPP runtime and public API.

> [!IMPORTANT]
> **NGI541 0.1.0 completed validation in the NIST ACVTS Demo environment under Validation ID `A11030`.**
>
> The validated profile includes AES-CBC, AES-CTR, AES-GCM, SHA2-224, and SHA2-256.
>
> NIST ACVTS Demo validation is **not** a Production CAVP certificate and is **not** a FIPS 140 validation.

## Why NGI541

NGI541 explores whether a cryptographic execution architecture originating in a high-performance packet-processing environment can be developed into an independently verifiable and reusable standalone component.

The project focuses on a deliberately small set of properties:

- **verification-first development** — correctness and robustness evidence precede performance claims;
- **standalone execution** — no VPP runtime dependency;
- **controlled public API** — validation and consumers exercise the same public execution boundary;
- **SIMD/ISA-oriented implementation** — preserving the performance-oriented characteristics of the native crypto core;
- **networking-oriented workloads** — with particular interest in packet-sized operations and future batch execution;
- **reproducibility** — validation and future performance claims are intended to be independently reproducible.

NGI541 is not intended to be a general-purpose TLS, PKI, or cryptographic toolkit and is not positioned as a replacement for OpenSSL.

## Supported algorithms

The current `0.1.x` public execution surface is intentionally narrow:

| Algorithm | Support |
| --- | --- |
| AES-CBC | AES-128 / AES-192 / AES-256, encrypt and decrypt |
| AES-CTR | AES-128 / AES-192 / AES-256, encrypt and decrypt |
| AES-GCM | AES-128 / AES-192 / AES-256, authenticated encrypt and decrypt |
| SHA-2 | SHA-224 / SHA-256 |

The production engine has no VPP runtime dependency and no OpenSSL dependency.

For the full API contract, see [`docs/API.md`](docs/API.md).

## Build and test

NGI541 uses CMake and a C11-capable GCC, Clang, or AppleClang toolchain on supported platforms.

A recommended source build keeps the regular test suite enabled:

```bash
cmake \
  -S . \
  -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_TESTS=ON \
  -DNGI541_BUILD_EXAMPLES=OFF \
  -DNGI541_BUILD_ACVP=OFF

cmake \
  --build build \
  --parallel

ctest \
  --test-dir build \
  --output-on-failure
```

Validation-specific dependencies such as OpenSSL and `libacvp` are not required for a normal production-engine build.

ACVP and validation workflows are documented in [`docs/validation.md`](docs/validation.md) and [`validation/acvp/README.md`](validation/acvp/README.md).

## Install

Install only after the configured test suite passes:

```bash
cmake \
  --install build
```

NGI541 follows CMake's normal installation-prefix model and `GNUInstallDirs`. The project does not hardcode a package-manager-specific installation path.

For a custom prefix, set it when configuring the build:

```bash
cmake \
  -S . \
  -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_TESTS=ON \
  -DNGI541_BUILD_EXAMPLES=OFF \
  -DNGI541_BUILD_ACVP=OFF \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local"

cmake \
  --build build \
  --parallel

ctest \
  --test-dir build \
  --output-on-failure

cmake \
  --install build
```

Setting `CMAKE_INSTALL_PREFIX` at configure time is recommended for custom-prefix installs because the generated `pkg-config` metadata records the configured prefix. The installed CMake package remains relocatable.

### Installation components

The installation is divided into three components:

| Component | Contents |
| --- | --- |
| `Runtime` | Versioned shared library and required redistribution notices |
| `Development` | Public headers, static library, shared-library linker name, CMake package metadata, and `pkg-config` metadata |
| `Documentation` | Project documentation and public example sources |

A component can be installed independently:

```bash
cmake --install build --component Runtime
cmake --install build --component Development
cmake --install build --component Documentation
```

`DESTDIR` staging is supported for package construction.

### Uninstall

The build tree provides a manifest-based uninstall target:

```bash
cmake \
  --build build \
  --target uninstall
```

The uninstall step removes only files recorded in CMake's installation manifest. Empty installation directories are intentionally left in place.

## Use from CMake

The canonical installed static-library target is:

```cmake
NGI541::engine
```

A minimal consumer project can use:

```cmake
cmake_minimum_required(VERSION 3.20)

project(my_app LANGUAGES C)

find_package(
  NGI541
  CONFIG
  REQUIRED
)

add_executable(
  my_app
  main.c
)

target_link_libraries(
  my_app
  PRIVATE
    NGI541::engine
)
```

The shared-library target is:

```cmake
NGI541::engine_shared
```

If NGI541 is installed under a non-standard prefix, configure the consumer with that prefix:

```bash
cmake \
  -S . \
  -B build \
  -DCMAKE_PREFIX_PATH="$HOME/.local"
```

Applications must not depend directly on internal package targets such as:

```text
NGI541::_core
NGI541::_support
NGI541::_crypto_isa
```

See [`docs/API.md`](docs/API.md) and [`docs/ABI.md`](docs/ABI.md) for the public API and compatibility contracts.

## Use with pkg-config

Supported Unix-like installations also provide:

```text
ngi541.pc
```

Compiler and linker flags can be obtained with:

```bash
pkg-config --cflags --libs ngi541
```

For static linking:

```bash
pkg-config --static --cflags --libs ngi541
```

The CMake package is the canonical cross-platform consumer interface.

## Examples

Public API examples are available under [`examples/`](examples/):

- SHA-256 hashing;
- AES-128-CTR encryption and decryption;
- AES-128-GCM authenticated encryption and decryption.

Build them with:

```bash
cmake \
  -S . \
  -B build-examples \
  -DCMAKE_BUILD_TYPE=Release \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_EXAMPLES=ON \
  -DNGI541_BUILD_TESTS=OFF \
  -DNGI541_BUILD_ACVP=OFF

cmake \
  --build build-examples \
  --parallel
```

The examples use only the public NGI541 API. See [`examples/README.md`](examples/README.md) for usage and security notes.

## Documentation

Detailed project documentation is intentionally kept outside the README so that this file remains the project entry point rather than a duplicate reference manual.

| Topic | Document |
| --- | --- |
| Architecture and production boundaries | [`docs/architecture.md`](docs/architecture.md) |
| Validation model and ACVTS evidence | [`docs/validation.md`](docs/validation.md) |
| Public API | [`docs/API.md`](docs/API.md) |
| ABI and versioning policy | [`docs/ABI.md`](docs/ABI.md) |
| Supported platforms and ISA policy | [`docs/PLATFORMS.md`](docs/PLATFORMS.md) |
| Performance methodology and claim policy | [`docs/performance.md`](docs/performance.md) |
| Project roadmap | [`docs/roadmap.md`](docs/roadmap.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Source provenance | [`docs/legal/PROVENANCE.md`](docs/legal/PROVENANCE.md) |
| Development policy | [`docs/legal/DEVELOPMENT_POLICY.md`](docs/legal/DEVELOPMENT_POLICY.md) |
| ACVP adapter | [`validation/acvp/README.md`](validation/acvp/README.md) |
| NIST ACVTS Demo evidence | [`validation/evidence/acvts-demo/README.md`](validation/evidence/acvts-demo/README.md) |

## Contributing

NGI541 welcomes technically rigorous contributions consistent with the project's provenance, security, validation, and performance-engineering requirements.

Contributions require Developer Certificate of Origin sign-off.

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

NGI541 has not undergone an independent security audit and must not currently be treated as production-ready cryptographic software.

Do not report suspected security vulnerabilities through public GitHub issues.

See [`SECURITY.md`](SECURITY.md) for the current reporting policy.

## License and provenance

NGI541 is licensed under the **Apache License 2.0**.

Portions of the cryptographic implementation are derived from publicly available FD.io VPP source code. Exact upstream revisions, imported files, licensing information, and subsequent NGI541 modifications are recorded explicitly.

See:

- [`LICENSE`](LICENSE)
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- [`docs/legal/PROVENANCE.md`](docs/legal/PROVENANCE.md)

NGI541 is developed as an independent open-source project and does not require the FD.io VPP runtime.

## Contact

Project website: [https://ngi541.org](https://ngi541.org)

Email: [contact@ngi541.org](mailto:contact@ngi541.org)
