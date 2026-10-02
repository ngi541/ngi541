# NGI541 Architecture

NGI541 is a standalone, verification-first, performance-oriented
cryptographic execution engine intended for networking and data-plane
workloads.

The project provides a small public execution API backed by native
cryptographic implementations derived from selected FD.io VPP native crypto
components.

NGI541 is not a general-purpose TLS, PKI, certificate, or protocol library.
Its current scope is cryptographic primitive execution through a controlled
public API.

## Architecture overview

The production execution path is:

```text
Application / consumer
        |
        v
Public NGI541 API
include/ngi541/*
        |
        v
Execution facade
        |
        v
Internal engine interfaces
        |
        v
Native provider
        |
        +-------------------------+
        |                         |
        v                         v
AES handlers                  SHA-2 handlers
CBC / CTR / GCM               SHA-224 / SHA-256
        |                         |
        +------------+------------+
                     |
                     v
            SIMD / ISA primitives
```

The public API is the boundary between NGI541 consumers and implementation
internals.

Consumers do not depend on internal engine structures, VPP runtime APIs, or
validation-specific interfaces.

## Public API boundary

The installed public API is defined by the headers under:

```text
include/ngi541/
├── api.h
├── crypto.h
└── engine.h
```

The public API currently provides:

- engine initialization;
- AES-CBC encryption and decryption;
- AES-CTR encryption and decryption;
- AES-GCM authenticated encryption and decryption;
- SHA2-224 hashing;
- SHA2-256 hashing.

Cryptographic operations are represented by public request structures rather
than by internal engine operation structures.

The internal operation representation is not part of the public API or ABI.

Applications should include the public headers and link through the exported
NGI541 library targets.

For CMake consumers, the canonical installed target is:

```cmake
NGI541::engine
```

A shared-library target is also available:

```cmake
NGI541::engine_shared
```

Internal CMake targets such as `NGI541::_core`, `NGI541::_support`, and
`NGI541::_crypto_isa` are implementation details and must not be treated as
public interfaces.

## Execution facade

The execution facade translates public API requests into the internal
representation used by the native execution engine.

Its responsibilities include:

- enforcing the public request contract;
- validating request parameters;
- selecting the requested cryptographic operation;
- passing the operation to the configured native implementation;
- mapping execution results back to public NGI541 status codes.

This layer separates the consumer-facing request model from the
implementation-oriented engine structures.

## Native provider

The current production implementation uses the NGI541 native provider.

The native provider owns the mapping between supported operations and their
native handlers, including:

```text
AES-CBC
AES-CTR
AES-GCM
SHA2-224
SHA2-256
```

The provider and its handler interfaces are internal implementation details.

They are not exposed through installed public headers.

## Cryptographic core

The cryptographic core contains the low-level primitives used by the native
provider.

This code originates in selected FD.io VPP native cryptographic components and
has been extracted and adapted for standalone NGI541 operation.

NGI541 preserves the provenance and applicable copyright and license notices
for the upstream-derived code.

Detailed provenance is documented in:

```text
docs/legal/PROVENANCE.md
```

and third-party notices are provided in:

```text
THIRD_PARTY_NOTICES.md
```

The production engine does not depend on the FD.io VPP runtime.

## Support layer

NGI541 contains a minimized support layer required by the cryptographic core.

Selected support code is derived or adapted from VPP infrastructure, while
NGI541-specific compatibility code provides the minimum standalone environment
needed by the engine.

This support layer is internal.

Applications must not include headers from `src/` or depend on support-layer
types directly.

## Validation architecture

Validation is intentionally separated from the production architecture.

Conceptually:

```text
Validation infrastructure
        |
        +----------------------------+
        |                            |
        v                            v
ACVP adapter                 Differential / test tooling
        |                            |
        +-------------+--------------+
                      |
                      v
               Public NGI541 API
                      |
                      v
               Production engine
```

The validation layer exercises the same public API available to external
consumers.

Validation-specific semantics are kept outside the production engine.

This means that ACVP handling, test-vector processing, and external reference
implementations do not become dependencies of the production execution path.

## External validation dependencies

NGI541 uses external software in validation and testing without making that
software part of the production dependency graph.

### libacvp

`libacvp` is used by the ACVP validation infrastructure.

It is not a production dependency of the NGI541 engine.

### OpenSSL

OpenSSL is used as an independent reference implementation for differential
correctness testing.

It is not linked into the production NGI541 engine and is not required by
applications using NGI541.

The intended relationship is:

```text
OpenSSL
   |
   | reference results
   v
Differential tests
   |
   v
NGI541 public API
```

not:

```text
Application
   |
   v
NGI541
   |
   v
OpenSSL
```

## Build-time architecture

The major internal build targets are conceptually:

```text
ngi541_support
      |
      v
ngi541_core
      |
      v
ngi541_engine_objects
      |
      +------------------+
      |                  |
      v                  v
ngi541_engine      ngi541_engine_shared
```

The static and shared libraries expose the same public NGI541 API.

The implementation is built with the internal dependency graph hidden behind
the public installed targets.

## Installation boundary

A normal installation exposes the consumer-facing development surface:

```text
<prefix>/
├── include/ngi541/
│   ├── api.h
│   ├── crypto.h
│   └── engine.h
│
└── lib/
    ├── libngi541_engine.*
    ├── cmake/NGI541/
    └── pkgconfig/ngi541.pc
```

Additional internal static artifacts may be installed to satisfy transitive
link requirements, but they are not public APIs.

Tests, validation executables, and example executables are not part of the
runtime installation.

## Source-tree boundaries

The repository is intentionally divided into separate areas:

```text
include/ngi541/       public API

src/                  production implementation

examples/             public API usage examples

tests/                correctness and robustness tests

validation/           standards-facing validation infrastructure

docs/                 project and technical documentation

third_party/          externally maintained dependencies used by
                      validation or development infrastructure
```

Code under `src/` is not part of the installed public API.

Code under `validation/` is not part of the production execution path.

## Supported algorithm surface

The current NGI541 0.1.x execution surface is intentionally small:

| Class | Algorithms |
| --- | --- |
| Block/stream mode | AES-CBC |
| Counter mode | AES-CTR |
| AEAD | AES-GCM |
| Hash | SHA2-224, SHA2-256 |

AES supports 128-, 192-, and 256-bit keys where applicable.

The project does not currently aim to grow into a general-purpose
cryptographic toolkit solely by increasing the number of algorithms.

The intended direction is to keep the execution surface controlled while
improving verification, performance-oriented execution, portability, and
integration quality.

## Relationship to FD.io VPP

NGI541 originates from selected FD.io VPP native cryptographic components, but
the production architecture is standalone.

The relationship is:

```text
FD.io VPP native crypto components
              |
              | extraction and adaptation
              v
            NGI541
              |
              +--> standalone public API
              +--> standalone validation
              +--> standalone packaging
```

NGI541 does not require the VPP runtime for normal library use.

VPP may become an external consumer of NGI541 in a future integration, but
that is separate from the current production architecture.

## Current architectural constraints

The current public API is operation-oriented:

```text
one request
    |
    v
one cryptographic operation
```

This interface is appropriate for:

- correctness validation;
- ACVP integration;
- simple external consumers;
- controlled public API development.

It is not intended to expose internal operation structures or to define the
future high-throughput batching interface.

A separate public batch-oriented API may be introduced in a future release
line after its semantics and performance requirements are defined.

## Architectural non-goals

NGI541 0.1.x is not intended to provide:

- TLS protocol implementation;
- PKI or X.509 processing;
- certificate management;
- key storage or key-management infrastructure;
- a general EVP-style cryptographic abstraction;
- a replacement for OpenSSL;
- public access to internal engine operation structures;
- validation-specific APIs as production interfaces.

## Version scope

This document describes the architecture of the NGI541 `0.1.x` release line.

The public API boundary has been established, but NGI541 remains in the `0.x`
development series.

Detailed API and ABI compatibility rules are documented separately.
