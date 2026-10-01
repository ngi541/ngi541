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

The NGI541 repository and its source-provenance policy were established before
third-party source code was imported. Development after the recorded upstream
imports is maintained in the NGI541 Git history.

## Project license

NGI541 is licensed under the Apache License, Version 2.0.

See the repository root `LICENSE` file.

Individual retained or derived third-party files may carry additional or
alternative upstream licensing terms where recorded by their SPDX identifiers
or embedded notices. Those notices are preserved.

## Source import policy

Third-party source incorporated into NGI541 must have traceable provenance.

An import record should identify, where applicable:

1. upstream project;
2. source repository;
3. exact upstream revision;
4. original source path;
5. NGI541 import path;
6. current NGI541 path, if different;
7. applicable license;
8. preservation of applicable copyright and licensing notices;
9. whether the source was copied, derived, adapted, or independently implemented;
10. material NGI541 modifications.

## Provenance log

### 2026-09-17 — FD.io VPP native crypto baseline

#### Upstream

- Project: FD.io VPP
- Project repository: https://github.com/FDio/vpp
- Source repository: https://gerrit.fd.io/r/vpp
- Gerrit Change: `44827`
- Patchset: `20`
- Upstream commit: `d7ed54b83682e753e772274409696d8fa8f8108c`
- Upstream parent: `48e1f751ef7726c7358a3315c69bb011a6fda946`
- License: Apache License 2.0

The imported revision corresponds to the publicly available Gerrit change:

`crypto: unify per-thread key_data allocation`

Public Gerrit change:

https://gerrit.fd.io/r/c/vpp/+/44827

#### Canonical NGI541 import

The selected native-crypto and crypto-primitive source baseline was imported by:

- NGI541 commit: `0e3b62b010a85fda82a55c9b3fd6f09cdecd7a09`
- Tag: `vpp-44827-ps20-import`
- Historical branch: `import/vpp-44827-ps20`
- Commit subject: `import: add FD.io VPP crypto baseline from Gerrit 44827 PS20`

The tag and historical import branch resolve to the same canonical import
commit.

Classification: **copied upstream source baseline**

No algorithmic or semantic modification was intended as part of the canonical
initial import. NGI541-specific refactoring and implementation changes are
recorded in later commits.

#### Initial imported-source mapping

| Upstream source | Initial NGI541 import path |
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

#### Current derived-source mapping

The current production tree preserves the following traceable lineage from the
canonical import:

| Upstream source | Initial NGI541 path | Current NGI541 path |
| --- | --- | --- |
| `src/vppinfra/crypto/aes.h` | `src/crypto/aes.h` | `src/core/aes/aes.h` |
| `src/vppinfra/crypto/aes_cbc.h` | `src/crypto/aes_cbc.h` | `src/core/aes/aes_cbc.h` |
| `src/vppinfra/crypto/aes_ctr.h` | `src/crypto/aes_ctr.h` | `src/core/aes/aes_ctr.h` |
| `src/vppinfra/crypto/aes_gcm.h` | `src/crypto/aes_gcm.h` | `src/core/aes/aes_gcm.h` |
| `src/vppinfra/crypto/ghash.h` | `src/crypto/ghash.h` | `src/core/aes/ghash.h` |
| `src/vppinfra/crypto/sha2.h` | `src/crypto/sha2.h` | `src/core/sha/sha2.h` |
| `src/crypto_engines/native/aes_cbc.c` | `src/engines/native/aes_cbc.c` | `src/engine/handlers/aes_cbc.c` |
| `src/crypto_engines/native/aes_ctr.c` | `src/engines/native/aes_ctr.c` | `src/engine/handlers/aes_ctr.c` |
| `src/crypto_engines/native/aes_gcm.c` | `src/engines/native/aes_gcm.c` | `src/engine/handlers/aes_gcm.c` |
| `src/crypto_engines/native/sha2.c` | `src/engines/native/sha2.c` | `src/engine/handlers/sha2.c` |
| `src/crypto_engines/native/sha2.h` | `src/engines/native/sha2.h` | `src/engine/handlers/sha2.h` |
| `src/crypto_engines/native/main.c` | `src/engines/native/main.c` | `src/engine/native.c` |
| `src/vnet/crypto/crypto.h` | `src/core/crypto.h` | `src/engine/internal/crypto_types.h` |

The `crypto.h` lineage passed through intermediate standalone paths
`src/engine/crypto.h` and `src/engine/crypto_types.h` before reaching
`src/engine/internal/crypto_types.h`.

The imported native interface was also progressively internalized. The
upstream-derived `src/crypto_engines/native/crypto_native.h` was imported as
`src/engines/native/crypto_native.h`, later moved through the standalone engine
layout, and was internalized as `src/engine/internal/native.h`.
`src/engine/internal/provider.h` was created during the same internalization
phase to express the NGI541-internal provider ABI.

The current public execution facade, including `src/engine/execute.c` and
`src/engine/internal/execute.h`, is original NGI541 code and was introduced
after the upstream import.

### 2026-09-17 — VPPInfra support baseline

A limited VPPInfra compatibility baseline required by the imported crypto core
was imported from the same recorded upstream VPP revision by:

- NGI541 commit: `c34f2e8d69c92abe6f08d398789ff5a613973172`
- Commit subject: `import: add VPP infrastructure required by crypto core`

#### Imported VPPInfra mapping

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

The VPPInfra files are intentionally isolated under `src/support/vppinfra/` so
that the compatibility dependency can be reduced independently from the crypto
algorithms.

### Standalone extraction and dependency minimization

The standalone extraction proceeded through traceable follow-up commits.

#### Standalone engine baseline

Commit:

`4572ec1418058d9659ba31f23bb43d0961442552`

Subject:

`crypto: establish standalone native engine baseline`

This phase reorganized the imported engine and temporarily expanded the
VPPInfra dependency closure needed to establish a working standalone baseline.

It also introduced `src/support/compat/string.c`, an original NGI541
implementation of the compatibility symbol required by the retained VPPInfra
string helpers. It is not copied from the upstream VPP `string.c`
implementation.

#### VPPInfra dependency minimization

Commit:

`3817964b8a20c23f18f34b8aeaf741d906ee81c9`

Subject:

`support: minimize standalone VPPInfra dependency closure`

This phase removed the broad VPP runtime dependency chain and retained only the
low-level support required by the crypto/SIMD implementation.

The originally imported files:

- `src/support/vppinfra/atomics.h`
- `src/support/vppinfra/bitops.h`
- `src/support/vppinfra/clib.h`
- `src/support/vppinfra/error_bootstrap.h`

were removed during this minimization phase.

Additional VPPInfra runtime files that had been temporarily introduced during
the standalone-baseline work were also removed. They remain traceable in Git
history but are not part of the current production source tree.

The following compatibility headers were introduced during dependency
minimization:

- `src/support/compat/assert.h`
- `src/support/compat/base.h`
- `src/support/compat/compiler.h`
- `src/support/compat/cpu.h`

These files are NGI541 compatibility adaptations derived from selected VPPInfra
definitions and primitives. Applicable upstream copyright and SPDX notices are
retained.

### Internal execution architecture

Later NGI541 commits established a public execution facade and internalized the
provider ABI.

Relevant commits include:

- `40d27aea29ec3c90740f8790d5b96a0d7ff4db7b` —
  `engine: internalize provider ABI and adopt NGI541 namespace`
- `4b053a2c69cd8ba8d20a72df3a105162dfd4ef48` —
  `engine: add public execution facade`

These changes separate the public NGI541 execution API from the retained and
adapted native cryptographic implementation.

The VPP `vnet/crypto` runtime/framework is not a production dependency of
NGI541.

## Modification and attribution policy

Current VPP-derived files retain applicable upstream SPDX identifiers,
copyright notices, and embedded third-party notices.

Current files that have been modified or adapted for NGI541 carry an explicit
`Modified for NGI541:` or equivalent adaptation notice in the source header.

At the current audited baseline, the following retained VPPInfra files remain
byte-for-byte unchanged from the recorded NGI541 VPPInfra import commit:

- `src/support/vppinfra/vector_altivec.h`
- `src/support/vppinfra/vector_neon.h`
- `src/support/vppinfra/warnings.h`

They retain their upstream notices and do not carry an NGI541 modification
notice because the current file content is unchanged from that import
baseline.

`src/core/aes/ghash.h` retains an Intel Corporation copyright and redistribution
notice that was present in the upstream-derived source. The complete
redistribution conditions and disclaimer remain embedded in that source file.

All current tracked C and header files in the audited production, validation,
and test source trees carry an SPDX or equivalent license marker.

## Third-party validation dependency — Cisco libacvp

NGI541 uses Cisco `libacvp` as a validation-only dependency for ACVP/ACVTS
integration.

The dependency is recorded as a Git submodule:

- Path: `third_party/libacvp`
- Repository: `https://github.com/cisco/libacvp.git`
- Version tag: `v2.3.1`
- Pinned commit: `91a49ff512d14ffba6cc1ef52d8185c9e1f3735e`
- License: Apache License 2.0

`libacvp` is not a production dependency of the NGI541 cryptographic execution
engine. The ACVP adapter uses the NGI541 public execution API.

## Development boundary

Only publicly available upstream open-source material identified in this
provenance record is used as the source for the recorded third-party imports.

No private VPP repository, non-public branch, unpublished patch, internal
design document, customer information, or other confidential material forms
part of the recorded imports.

NGI541-specific changes following the upstream baselines are maintained in the
NGI541 Git history.

## Validated standalone baseline

NGI541 version `0.1.0` is identified by Git tag `v0.1.0`, resolving to:

`be5b8db305b557bbf079dc262e34532dacc00ade`

That immutable baseline is the code associated with NIST ACVTS Demo Validation
ID `A11030`.

The NIST ACVTS Demo validation is not a Production CAVP certificate and is not
a FIPS 140 validation.
