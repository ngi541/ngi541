# Source Provenance

This document records the origin and licensing provenance of source code
incorporated into NGI541.

Its purpose is to maintain a clear and auditable distinction between:

- original NGI541 development;
- publicly available upstream open-source code;
- modifications derived from upstream open-source code;
- third-party dependencies.

## Repository origin

NGI541 is an independent open-source software project.

Development is performed independently using personal development equipment,
personal source-control infrastructure, and publicly available technical
information.

The NGI541 repository and its source-provenance policy were established before
any third-party source code was imported.

## Project license

NGI541 is licensed under the Apache License, Version 2.0.

See the repository root `LICENSE` file.

## Source import policy

Third-party source code incorporated into NGI541 must have traceable
provenance.

An import record should identify, where applicable:

1. upstream project;
2. source repository;
3. exact upstream revision;
4. original source path;
5. NGI541 destination path;
6. applicable license;
7. preservation of applicable copyright and licensing notices;
8. whether the source was copied, derived, or independently implemented;
9. material NGI541 modifications.

## Provenance log

### 2026-09-17 — FD.io VPP native crypto baseline

#### Upstream

- Project: FD.io VPP
- Project repository: https://github.com/FDio/vpp
- Source repository: https://gerrit.fd.io/r/vpp
- Gerrit Change: 44827
- Patchset: 20
- Commit: `d7ed54b83682e753e772274409696d8fa8f8108c`
- Parent: `48e1f751ef7726c7358a3315c69bb011a6fda946`
- License: Apache License 2.0

The imported revision corresponds to the publicly available Gerrit change:

`crypto: unify per-thread key_data allocation`

Public Gerrit change:

https://gerrit.fd.io/r/c/vpp/+/44827

#### Import classification

Classification: **copied upstream source baseline**

The initial import relocates selected upstream source files into the NGI541
source tree.

No algorithmic or semantic modification is intended as part of this initial
import. NGI541-specific refactoring and implementation changes are maintained
in subsequent commits.

#### Imported source mapping

| Upstream source | NGI541 destination |
| --- | --- |
| `src/vnet/crypto/crypto.h` | `src/core/crypto.h` |
| `src/vnet/crypto/crypto.c` | `src/core/crypto.c` |
| `src/vnet/crypto/engine.h` | `src/core/engine.h` |
| `src/vnet/crypto/main.c` | `src/core/main.c` |
| `src/crypto_engines/native/main.c` | `src/engines/native/main.c` |
| `src/crypto_engines/native/crypto_native.h` | `src/engines/native/crypto_native.h` |
| `src/crypto_engines/native/aes_gcm.c` | `src/engines/native/aes_gcm.c` |
| `src/crypto_engines/native/aes_cbc.c` | `src/engines/native/aes_cbc.c` |
| `src/crypto_engines/native/aes_ctr.c` | `src/engines/native/aes_ctr.c` |
| `src/crypto_engines/native/sha2.c` | `src/engines/native/sha2.c` |
| `src/crypto_engines/native/sha2.h` | `src/engines/native/sha2.h` |
| `src/vppinfra/crypto/aes.h` | `src/crypto/aes.h` |
| `src/vppinfra/crypto/aes_gcm.h` | `src/crypto/aes_gcm.h` |
| `src/vppinfra/crypto/aes_cbc.h` | `src/crypto/aes_cbc.h` |
| `src/vppinfra/crypto/aes_ctr.h` | `src/crypto/aes_ctr.h` |
| `src/vppinfra/crypto/ghash.h` | `src/crypto/ghash.h` |
| `src/vppinfra/crypto/sha2.h` | `src/crypto/sha2.h` |

#### Copyright and licensing notices

The initial import preserves the applicable SPDX license identifiers,
copyright notices, and other licensing notices contained in the upstream
source files.

Upstream copyright notices are not replaced by NGI541 copyright notices.

Files subsequently modified by NGI541 will retain applicable upstream notices
and will be identified as modified where required.

#### Development boundary

Only publicly available FD.io VPP source code from the revision identified
above is used as the source for this import.

No private repository, non-public branch, unpublished patch, internal design
document, non-public benchmark result, customer information, or other
confidential material forms part of this import.

NGI541-specific development following this baseline is maintained separately
in the NGI541 Git history.

#### Imported support infrastructure

The cryptographic core depends on a limited subset of FD.io VPP
infrastructure headers.

The following files were imported from the same upstream revision without
semantic modification:

| Upstream source | NGI541 destination |
| --- | --- |
| `src/vppinfra/atomics.h` | `src/support/vppinfra/atomics.h` |
| `src/vppinfra/bitops.h` | `src/support/vppinfra/bitops.h` |
| `src/vppinfra/byte_order.h` | `src/support/vppinfra/byte_order.h` |
| `src/vppinfra/cache.h` | `src/support/vppinfra/cache.h` |
| `src/vppinfra/clib.h` | `src/support/vppinfra/clib.h` |
| `src/vppinfra/error_bootstrap.h` | `src/support/vppinfra/error_bootstrap.h` |
| `src/vppinfra/memcpy.h` | `src/support/vppinfra/memcpy.h` |
| `src/vppinfra/memcpy_x86_64.h` | `src/support/vppinfra/memcpy_x86_64.h` |
| `src/vppinfra/string.h` | `src/support/vppinfra/string.h` |
| `src/vppinfra/types.h` | `src/support/vppinfra/types.h` |
| `src/vppinfra/vector.h` | `src/support/vppinfra/vector.h` |
| `src/vppinfra/vector_altivec.h` | `src/support/vppinfra/vector_altivec.h` |
| `src/vppinfra/vector_avx2.h` | `src/support/vppinfra/vector_avx2.h` |
| `src/vppinfra/vector_avx512.h` | `src/support/vppinfra/vector_avx512.h` |
| `src/vppinfra/vector_neon.h` | `src/support/vppinfra/vector_neon.h` |
| `src/vppinfra/vector_sse42.h` | `src/support/vppinfra/vector_sse42.h` |
| `src/vppinfra/warnings.h` | `src/support/vppinfra/warnings.h` |

These files form the initial compatibility layer required by the imported
cryptographic core.

They are intentionally isolated under `src/support/vppinfra/` so that their
future replacement or reduction can be performed independently from the
cryptographic algorithms.

#### NGI541 modification phase

Following the exact upstream import, NGI541 development modifies the imported
crypto and engine sources to use the NGI541 source-tree layout.

The first modification phase replaces upstream VPP source-tree include paths
with NGI541 internal paths while preserving the imported cryptographic
algorithms, operation model, engine model, and low-level support implementation.

The compatibility files under `src/support/vppinfra/` remain unmodified from
the recorded upstream baseline at this stage.

## FD.io VPP baseline

Repository:
https://gerrit.fd.io/r/vpp

Baseline commit:
d7ed54b83682e753e772274409696d8fa8f8108c

The NGI541 native crypto engine and selected supporting crypto and
VPPInfra files were extracted from this historical VPP baseline.

### VPPInfra support

`src/support/vppinfra/` contains selected Apache-2.0 licensed VPPInfra
headers required by the extracted crypto implementation.

NGI541 does not vendor or depend on the complete VPPInfra runtime.

### Compatibility implementation

`src/support/compat/string.c` is an NGI541 implementation of the
compatibility symbol required by the imported VPPInfra string helpers.
It replaces the VPP runtime dependency chain that would otherwise pull
in error formatting, dynamic vectors, the VPP memory allocator, and OS
runtime support.

This file is original NGI541 code and is not copied from the upstream
VPP `string.c` implementation.

## Standalone extraction boundary

The NGI541 production engine is derived from the FD.io VPP native
crypto implementation at the recorded historical baseline.

The VPP `vnet/crypto` runtime/framework is not carried forward as a
production dependency. NGI541 retains only the engine contract,
native handlers, required crypto primitives, and selected supporting
VPPInfra headers.

Runtime/framework code from the original VPP implementation may be
consulted as historical reference, but future validation interfaces
are developed independently around standardized cryptographic
validation requirements.