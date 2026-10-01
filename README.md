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
  <a href="https://github.com/ngi541/ngi541/actions">
    <img alt="CI" src="https://github.com/ngi541/ngi541/actions/workflows/ci.yml/badge.svg">
  </a>
  <img alt="Project status" src="https://img.shields.io/badge/status-active%20development-2ea44f">
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue">
  </a>
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1.0-blue">
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

## Current capabilities

NGI541 0.1.0 currently exposes:

| Area | Support |
| --- | --- |
| AES-CBC | AES-128 / AES-192 / AES-256 |
| AES-CTR | AES-128 / AES-192 / AES-256 |
| AES-GCM | AES-128 / AES-192 / AES-256 |
| SHA-2 | SHA-224 / SHA-256 |
| Public execution API | Yes |
| Standalone native engine | Yes |
| VPP runtime dependency | None |
| Production OpenSSL dependency | None |
| ACVP validation adapter | Yes |
| Differential validation | OpenSSL EVP reference |
| Sanitizer / memory-geometry testing | Yes |
| NIST ACVTS Demo | `A11030` |

The algorithm portfolio is intentionally narrow at this stage. The current priority is assurance, reproducibility, and execution architecture rather than expanding algorithm count.

## Architecture

At a high level:

```text
                    Consumer
                        │
                        ▼
                 NGI541 Public API
                        │
                        ▼
                Execution Facade
                        │
                        ▼
                  Native Provider
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
             AES                SHA-2
       CBC / CTR / GCM        224 / 256
              │                   │
              └─────────┬─────────┘
                        ▼
               SIMD / ISA primitives
```

Validation remains outside the production execution architecture:

```text
               NIST ACVTS / ACVP
                        │
                     libacvp
                        │
                 ACVP adapter
                        │
                        ▼
                 NGI541 Public API
                        │
                        ▼
                 production engine
```

The ACVP adapter is therefore a consumer of the same public API that is exposed to other NGI541 consumers. It does not bypass the public execution boundary through internal engine interfaces.

## Verification and validation

NGI541 follows an evidence-producing validation model:

```text
known-answer tests
        ↓
randomized differential verification
        ↓
memory / buffer-geometry testing
        ↓
ASan / UBSan validation
        ↓
ACVP semantic verification
        ↓
NIST-generated ACVTS vectors
        ↓
external server verdict
```

### NIST ACVTS Demo

NGI541 0.1.0 completed a full non-sample validation session in the NIST ACVTS Demo environment.

| Property | Value |
| --- | --- |
| Version | `0.1.0` |
| Git tag | `v0.1.0` |
| Baseline commit | `be5b8db305b557bbf079dc262e34532dacc00ade` |
| Test session | `772630` |
| Validation ID | `A11030` |
| Environment | NIST ACVTS Demo |

Validated vector sets:

| Algorithm | Revision | Result |
| --- | --- | --- |
| ACVP-AES-CBC | 1.0 | passed |
| ACVP-AES-CTR | 1.0 | passed |
| ACVP-AES-GCM | 1.0 | passed |
| SHA2-224 | 1.0 | passed |
| SHA2-256 | 1.0 | passed |

Sanitized validation evidence is available under:

[`validation/evidence/acvts-demo/`](validation/evidence/acvts-demo/)

The evidence pack intentionally excludes credentials, JWTs, TOTP material, private keys, raw ACVTS vectors, and other sensitive validation state.

## Performance

NGI541 is currently described as **performance-oriented**, not as faster than any specific cryptographic implementation.

A reproducible performance methodology and benchmark harness are being developed before comparative performance claims are made.

The planned evaluation focuses on:

- packet-sized workloads;
- single-operation execution;
- future batch / multi-operation execution;
- cycles per byte;
- throughput;
- operations per second;
- latency per operation;
- CPU/core efficiency;
- cache and memory behavior;
- reproducible comparisons with established cryptographic implementations.

Performance claims published by the project will be accompanied by sufficient environment and methodology metadata to allow independent reproduction.

## Building

NGI541 uses CMake and requires a C11-capable GCC or Clang toolchain.

Basic build:

```bash
cmake -S . -B build \
  -DNGI541_BUILD_ENGINE=ON

cmake --build build
```

Run the test suite:

```bash
ctest --test-dir build --output-on-failure
```

The ACVP validation layer and differential-reference tests are optional and are disabled independently from the production engine.

### ACVP build

```bash
cmake -S . -B build-acvp \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_ACVP=ON

cmake --build build-acvp
```

Additional bootstrap scripts are available under [`scripts/`](scripts/) for validation and test dependencies.

## Installation

NGI541 provides installable public headers, static and shared libraries, and a
CMake package for external consumers.

### Build and install

Configure a release build with the engine enabled:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_TESTS=OFF \
  -DNGI541_BUILD_EXAMPLES=OFF
```

Build and install:

```bash
cmake --build build --parallel
cmake --install build
```

To install into a custom prefix:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_TESTS=OFF \
  -DNGI541_BUILD_EXAMPLES=OFF \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local"

cmake --build build --parallel
cmake --install build
```

The installation contains:

```text
include/ngi541/
├── api.h
├── crypto.h
└── engine.h

lib/
├── libngi541_engine.*
├── libngi541_support.*
└── cmake/NGI541/
    ├── NGI541Config.cmake
    ├── NGI541ConfigVersion.cmake
    └── NGI541Targets*.cmake
```

`libngi541_support` and the internal exported CMake targets are implementation
details required by the installed package. Applications should link only to the
public NGI541 targets described below.

### Using NGI541 from CMake

An external CMake project can consume an installed NGI541 package with:

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

`NGI541::engine` is the canonical installed target for the static NGI541
execution engine.

A shared-library target is also available:

```cmake
NGI541::engine_shared
```

Applications should not depend directly on the package's internal targets:

```text
NGI541::_core
NGI541::_support
NGI541::_crypto_isa
```

Those targets are exported only to preserve the transitive implementation
dependencies of the public package.

### Finding a custom installation

If NGI541 is installed into a non-standard prefix, provide that prefix when
configuring the consumer:

```bash
cmake -S . -B build \
  -DCMAKE_PREFIX_PATH="$HOME/.local"
```

Then build normally:

```bash
cmake --build build --parallel
```

### Public headers

Consumers use the installed public API through:

```c
#include <ngi541/engine.h>
```

`engine.h` includes the public cryptographic API required for normal engine
usage. Applications may also include the lower-level public headers directly
when appropriate:

```c
#include <ngi541/api.h>
#include <ngi541/crypto.h>
```

Cryptographic operations require explicit engine initialization:

```c
ngi541_status_t status = ngi541_engine_init ();
```

NGI541 `0.1.x` does not currently expose a public shutdown/deinitialization
function.

### Minimal consumer example

```c
#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>

int
main (void)
{
  static const uint8_t message[] = {
    'N', 'G', 'I', '5', '4', '1'
  };

  uint8_t digest[32] = { 0 };

  ngi541_hash_request_t request = {
    .struct_size = sizeof (request),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = message,
    .message_len = sizeof (message),
    .digest = digest,
    .digest_capacity = sizeof (digest),
  };

  ngi541_status_t status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    return 1;

  status = ngi541_crypto_hash_compute (&request);

  if (status != NGI541_STATUS_OK)
    return 2;

  for (size_t i = 0; i < sizeof (digest); i++)
    printf ("%02x", digest[i]);

  putchar ('\n');

  return 0;
}
```

For more complete public API usage examples, see
[`examples/`](examples/).

### ABI compatibility

NGI541 is currently in the `0.x` development series.

Patch releases within the same minor release line are treated as compatible by
the installed CMake package. Compatibility is not guaranteed across minor
release lines.

For example:

```text
0.1.0 -> 0.1.1   same compatibility line
0.1.x -> 0.2.x   compatibility not guaranteed
```

## Examples

Minimal examples using only the public NGI541 API are available in
[`examples/`](examples/).

They demonstrate:

- SHA-256 hashing;
- AES-128-CTR encryption and decryption;
- AES-128-GCM authenticated encryption and decryption.

Build NGI541 with the examples enabled:

```bash
cmake -S . -B build \
  -DNGI541_BUILD_ENGINE=ON \
  -DNGI541_BUILD_EXAMPLES=ON

cmake --build build
```

Run them:

```bash
./build/examples/ngi541_example_sha256
./build/examples/ngi541_example_aes_ctr
./build/examples/ngi541_example_aes_gcm
```

The examples use only the public NGI541 API and link against the NGI541::engine CMake target.

See [`examples/README.md`](examples/README.md) for API usage and security notes.

## Project status

NGI541 is under active development.

Version `0.1.0` represents the first externally validated standalone baseline. The public API boundary has been established, but the project has **not** declared a long-term stable ABI.

Current development is focused on:

1. public-project readiness and documentation;
2. reproducible performance methodology;
3. standalone benchmark infrastructure;
4. multi-platform performance characterization;
5. performance-oriented execution architecture development.

Future versions may change public interfaces while the project remains in the `0.x` development series.

## Documentation

Current project documentation includes:

- [Source provenance](docs/legal/PROVENANCE.md)
- [Development policy](docs/legal/DEVELOPMENT_POLICY.md)
- [ACVP validation adapter](validation/acvp/README.md)
- [NIST ACVTS Demo evidence](validation/evidence/acvts-demo/README.md)

Additional architecture, validation, performance, and roadmap documentation will be published as the public project structure is completed.

## Contributing

NGI541 welcomes technically rigorous contributions consistent with the project's provenance, security, validation, and performance-engineering requirements.

Contributions require Developer Certificate of Origin sign-off.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

NGI541 has not undergone an independent security audit and must not currently be treated as production-ready cryptographic software.

Do not report suspected security vulnerabilities through public GitHub issues.

See [SECURITY.md](SECURITY.md) for the current reporting policy.

## License and provenance

NGI541 is licensed under the **Apache License 2.0**.

Portions of the cryptographic implementation are derived from publicly available FD.io VPP source code. Exact upstream revisions, imported files, licensing information, and subsequent NGI541 modifications are recorded explicitly.

See:

- [LICENSE](LICENSE)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- [docs/legal/PROVENANCE.md](docs/legal/PROVENANCE.md)

NGI541 is developed as an independent open-source project and does not require the FD.io VPP runtime.

## Contact

Project website: [https://ngi541.org](https://ngi541.org)

Email: [contact@ngi541.org](mailto:contact@ngi541.org)
