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

NGI541 is intended to expose a small standalone API while dispatching work to
architecture-specific optimized implementations.

Initial CPU target:

- x86-64
- AES-NI
- PCLMULQDQ
- AVX2
- VAES
- VPCLMULQDQ

ARM64 support is planned for a later stage.

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

NGI541 is currently in private early-stage development.

No stable API or production release is available yet.