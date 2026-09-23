# NGI541

**High-performance vectorized cryptography for modern software dataplanes.**

NGI541 is an experimental standalone cryptographic library focused on
high-throughput and low-latency CPU execution for networking and dataplane
workloads.

> [!IMPORTANT]
> NGI541 is currently under early development.
> The API is unstable, the implementation has not been independently audited,
> and the project is not FIPS 140-3 validated.

## Project goals

NGI541 is being designed around several principles:

- standalone operation without a packet-processing framework dependency;
- low-overhead cryptographic execution;
- SIMD/vector-oriented implementations;
- efficient processing of packet-sized buffers;
- both single-operation and batch-oriented APIs;
- explicit runtime CPU backend selection;
- cache-conscious key and execution contexts;
- architecture suitable for a future clearly defined cryptographic module
  boundary.

The initial implementation target is AES-GCM.

## Planned algorithm support

| Algorithm | Status |
| --- | --- |
| AES-GCM | Planned first implementation |
| AES-CBC | Planned |
| AES-CTR | Planned |
| SHA-2 | Planned |
| ChaCha20-Poly1305 | Future / non-FIPS-oriented path |

## Architecture

    src/engine
        ↓
    src/core
        ↓
    src/support

`src/engine` contains the native engine contract, registration logic,
ISA selection, and crypto handlers.

`src/core` contains the AES, GHASH, SHA-2, and SIMD-oriented
cryptographic primitives.

`src/support` contains the minimal compatibility and low-level support
required by the standalone implementation.

NGI541 deliberately does not reproduce the VPP crypto framework or
VLIB runtime. External validation and execution interfaces will be
defined from standardized validation requirements rather than by
porting the historical VPP runtime.

## Source provenance

NGI541 maintains explicit source-provenance records for imported or derived
open-source code.

See:

- [`docs/legal/PROVENANCE.md`](docs/legal/PROVENANCE.md)
- [`docs/legal/DEVELOPMENT_POLICY.md`](docs/legal/DEVELOPMENT_POLICY.md)

The project may derive portions of its implementation from publicly available
FD.io VPP source code distributed under Apache License 2.0. Any such imports
will be recorded using exact upstream revisions.

## FIPS status

NGI541 is **not FIPS 140-3 validated**.

The project architecture may be developed with future validation requirements
in mind, but no FIPS validation, certification, or compliance claim is made.

## License

NGI541 is licensed under the Apache License, Version 2.0.

See [`LICENSE`](LICENSE).

## Project status

NGI541 currently provides a standalone extraction of the FD.io VPP
native cryptographic engine.

The current milestone includes:

- standalone AES/GHASH/SHA crypto primitives;
- standalone native crypto engine registration and ISA selection;
- static library build (`libngi541_engine.a`);
- shared module build (`libngi541_engine.so` / `.dylib`);
- dynamic loading through the exported `__vnet_crypto_engine` ABI;
- compile, static-engine smoke, and dynamic-engine smoke tests.

The VPP crypto framework and VLIB runtime are intentionally not part
of the standalone production engine.

Current tests validate compilation, module loading, engine
initialization, CPU feature probing, and native handler registration.
They do not yet constitute cryptographic algorithm validation.

The next milestone is integration with an external standardized
cryptographic validation framework, starting with investigation of
NIST ACVP and libacvp.