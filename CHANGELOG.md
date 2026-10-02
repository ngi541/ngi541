# Changelog

All notable changes to NGI541 are documented in this file.

NGI541 is currently in the `0.x` development series. Patch releases within the
same minor line are intended to remain source- and ABI-compatible, while
compatibility is not guaranteed across different `0.x` minor lines.

See [`docs/ABI.md`](docs/ABI.md) for the compatibility policy.

## [Unreleased]

This section contains changes intended for the first public-ready packaged
release in the `0.1.x` line.

### Added

- Installable static and shared NGI541 engine libraries.
- Canonical installed CMake targets:
  - `NGI541::engine`
  - `NGI541::engine_shared`
- Installed CMake package support through:
  - `find_package(NGI541 CONFIG REQUIRED)`
  - generated package version metadata using `SameMinorVersion`.
- Unix-like `pkg-config` integration through `ngi541.pc`.
- Runtime, Development, and Documentation installation components.
- Manifest-based `uninstall` target that removes only files recorded by the
  CMake installation manifest and intentionally leaves directories in place.
- `DESTDIR` staging support for package construction.
- Public API examples for:
  - SHA-256;
  - AES-CTR encryption/decryption;
  - AES-GCM authenticated encryption/decryption.
- Public project documentation:
  - `docs/architecture.md`
  - `docs/validation.md`
  - `docs/API.md`
  - `docs/ABI.md`
  - `docs/PLATFORMS.md`
  - `docs/performance.md`
  - `docs/roadmap.md`
- Public project branding assets under `docs/assets/brand/`.
- Public project governance and security documentation, including
  `SECURITY.md` and `CODE_OF_CONDUCT.md`.

### Changed

- Expanded the root README into the public project entry point with project
  identity, build/use guidance, validation status, performance-claim policy,
  provenance references, and project links.
- Clarified the public/private implementation boundary:
  - installed headers under `include/ngi541/` are public;
  - `src/` interfaces are internal;
  - `NGI541::_core`, `NGI541::_support`, and `NGI541::_crypto_isa` are
    internal package targets.
- Completed the public provenance and third-party attribution audit for the
  VPP-derived cryptographic core, engine, support code, and compatibility
  layer.
- Added or completed NGI541 modification notices on adapted upstream-derived
  source files where required.
- Expanded `THIRD_PARTY_NOTICES.md` to document FD.io VPP, the Intel GHASH
  notice, and the pinned Cisco `libacvp` validation dependency.
- Defined the `0.1.x` ABI compatibility line and shared-library versioning
  policy.
- Defined the current platform-support policy and separated tested support from
  source-level ISA presence.
- Defined the performance-status policy: NGI541 is performance-oriented, but
  comparative performance claims are deferred until Benchmark Specification v1
  and a reproducible benchmark campaign are complete.
- Kept OpenSSL and `libacvp` outside the production dependency graph:
  - OpenSSL is used as a differential correctness oracle;
  - `libacvp` is used only by validation tooling.

### Release preparation

The planned public-ready release is `0.1.1`.

Before release, this section should be converted into:

```text
## [0.1.1] - YYYY-MM-DD
```

and a new empty `## [Unreleased]` section should be created above it.

The `v0.1.0` tag remains the frozen externally validated implementation
baseline and must not be moved or recreated.

## [0.1.0] - 2026-09-30

Initial standalone and externally validated NGI541 baseline.

### Added

- Standalone NGI541 cryptographic execution engine derived from selected
  FD.io VPP native cryptographic components.
- Independent public execution API under `include/ngi541/`.
- Explicit engine initialization through `ngi541_engine_init()`.
- Public status model for successful execution, authentication failure,
  argument validation, buffer-capacity errors, unsupported/unavailable
  operations, initialization state, and internal failures.
- AES-CBC support:
  - AES-128;
  - AES-192;
  - AES-256;
  - encryption;
  - decryption.
- AES-CTR support:
  - AES-128;
  - AES-192;
  - AES-256;
  - encryption;
  - decryption.
- AES-GCM support:
  - AES-128;
  - AES-192;
  - AES-256;
  - authenticated encryption;
  - authenticated decryption;
  - authentication-failure reporting.
- SHA2-224 support.
- SHA2-256 support.
- Standalone native provider and execution facade.
- Static and shared engine build foundations.
- Public API conformance and runtime tests.
- Known-answer tests for the supported cryptographic surface.
- ACVP validation infrastructure using the public NGI541 API.
- ACVP registration and processing support for:
  - AES-CBC;
  - AES-CTR;
  - AES-GCM;
  - SHA2-224;
  - SHA2-256.
- Deterministic ACVP registration behavior.
- Local/offline ACVP vector processing and end-to-end validation.
- Mandatory ACVP test-type support required by the implemented capability
  profile.
- Negative ACVP validation coverage.
- Pinned Cisco `libacvp` validation dependency.
- Deterministic differential correctness testing using OpenSSL EVP as an
  independent reference implementation.
- Differential coverage for:
  - AES-CBC 128/192/256-bit encryption and decryption;
  - AES-CTR 128/192/256-bit encryption and decryption;
  - AES-GCM ciphertext, tag, authenticated decryption, and bad-tag behavior;
  - SHA-224;
  - SHA-256.
- Deterministic randomized differential corpus with reproducible seed/case
  identification.
- AddressSanitizer and UndefinedBehaviorSanitizer validation infrastructure.
- Dedicated sanitizer memory-geometry regression coverage.
- Source provenance documentation for the imported and adapted FD.io VPP
  implementation.
- Apache-2.0 project licensing and retained upstream notices.

### Fixed

- Partial vector-store undefined behavior identified during sanitizer testing.
- Unaligned AES-192 key access identified during sanitizer testing.
- Alignment-sensitive SHA digest finalization identified during sanitizer
  testing.
- ACVP negative-conformance behavior where permissive handling did not match
  the intended validation contract.

Each sanitizer-discovered defect was converted into regression coverage.

### Validation

The frozen `v0.1.0` implementation baseline completed a NIST ACVTS Demo
validation covering:

```text
AES-CBC
AES-CTR
AES-GCM
SHA2-224
SHA2-256
```

The associated NIST ACVTS Demo validation identifier is:

```text
A11030
```

A11030 is a **NIST ACVTS Demo validation identifier**.

It is **not**:

- a Production CAVP validation certificate;
- a FIPS 140-2 or FIPS 140-3 certificate;
- a CMVP module validation;
- a statement that later NGI541 source revisions were independently
  revalidated by NIST.

Validation evidence for the frozen baseline is retained under:

```text
validation/evidence/acvts-demo/
```

See [`docs/validation.md`](docs/validation.md) for the full validation claim
boundary.

## Versioning notes

The intended release relationship is:

```text
0.1.0
    frozen externally validated implementation baseline
        |
        v
0.1.1
    first public-ready packaged release
        |
        v
0.2.x
    future performance-oriented architectural evolution
```

Patch releases in the `0.1.x` line are intended to remain source- and
ABI-compatible.

Compatibility is not guaranteed between `0.1.x` and `0.2.x`.

See [`docs/ABI.md`](docs/ABI.md) for details.
