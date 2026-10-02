# NGI541 Validation

NGI541 uses a layered validation model designed to verify the correctness,
robustness, and standards-facing behavior of the same public API exposed to
external consumers.

Validation is intentionally separated from the production execution path.
Validation-specific dependencies and protocols do not become production
dependencies of the NGI541 engine.

## Validation model

The validation path is:

```text
Known-answer tests
        |
        v
Public API and runtime tests
        |
        v
Differential correctness testing
        |
        v
Sanitizer-based robustness testing
        |
        v
ACVP local/offline validation
        |
        v
NIST ACVTS Demo validation
        |
        v
Demo validation identifier A11030
```

Each layer answers a different question.

- Known-answer tests verify deterministic algorithm behavior against expected
  results.
- Public API and runtime tests verify the consumer-facing execution contract.
- Differential tests compare NGI541 results against an independent reference
  implementation across large deterministic randomized corpora.
- Sanitizer runs detect undefined behavior and memory-safety defects.
- ACVP validation verifies standards-facing algorithm semantics.
- NIST ACVTS Demo exercises the registered implementation through the NIST
  ACVP workflow.

No single layer is treated as sufficient by itself.

## Production and validation boundary

The intended relationship is:

```text
Validation tooling
        |
        v
Public NGI541 API
        |
        v
Production engine
```

not:

```text
Production engine
        |
        v
Validation framework
```

The production engine does not depend on OpenSSL or libacvp.

Validation-specific behavior is kept under the validation and test layers so
that the same public API used by applications is also the interface exercised
by correctness and ACVP tooling.

For the architectural boundary between production and validation, see
[`architecture.md`](architecture.md).

## Current validated algorithm surface

The NGI541 0.1.x validation surface currently covers:

| Algorithm | Key sizes / variants | Operations |
| --- | --- | --- |
| AES-CBC | 128, 192, 256 bits | encrypt, decrypt |
| AES-CTR | 128, 192, 256 bits | encrypt, decrypt |
| AES-GCM | 128, 192, 256 bits | authenticated encrypt, authenticated decrypt |
| SHA2-224 | SHA-224 | hash |
| SHA2-256 | SHA-256 | hash |

The validation scope intentionally matches the currently supported public
execution surface rather than attempting to maximize algorithm count.

## Known-answer testing

Known-answer tests provide deterministic verification for supported
cryptographic operations.

They are used to check that the public execution path produces expected
results for fixed inputs, keys, IVs, associated data, and messages.

Known-answer tests are useful as a stable regression layer, but they are not
treated as sufficient correctness evidence on their own because their input
coverage is necessarily limited.

## Public API and runtime testing

NGI541 validates behavior through the same public API exposed to consumers.

The API/runtime test layer verifies properties such as:

- explicit engine initialization requirements;
- repeated initialization behavior;
- request-structure handling;
- algorithm selection;
- input and output buffer validation;
- output-capacity checks;
- error status propagation;
- authenticated-decryption failure behavior;
- in-place behavior where supported;
- rejection of invalid or unsupported overlap patterns.

Internal engine structures are not used as a validation bypass.

This ensures that validation exercises the public execution boundary rather
than only low-level primitives.

## Differential correctness testing

NGI541 uses OpenSSL as an independent reference implementation for
differential correctness testing.

The conceptual model is:

```text
                    +--> NGI541 public API
randomized input ---|
                    +--> OpenSSL reference implementation
                             |
                             v
                         comparison
```

The differential suite covers:

```text
AES-CBC
AES-CTR
AES-GCM
SHA-224
SHA-256
```

The randomized corpus is deterministic and reproducible.

The current differential test design executes thousands of cases per run and
covers multiple key sizes, input lengths, encryption/decryption paths, hash
inputs, and authenticated-encryption behavior.

OpenSSL is used only as a test/reference oracle.

It is not a production dependency of NGI541.

## Sanitizer validation

NGI541 uses sanitizer-enabled builds to exercise the public execution path and
the underlying VPP-derived SIMD/ISA implementation.

The current hardening work includes AddressSanitizer and UndefinedBehaviorSanitizer
coverage.

Sanitizer testing has already identified and driven fixes for implementation
issues including:

- partial vector-store undefined behavior;
- unaligned AES-192 key access;
- alignment-sensitive SHA digest finalization.

These findings were converted into fixes and regression coverage.

Sanitizer evidence is therefore part of the NGI541 correctness process rather
than only a build-time convenience.

## ACVP validation architecture

NGI541 provides a dedicated ACVP validation layer under:

```text
validation/acvp/
```

The ACVP adapter is a consumer of the public NGI541 API.

Conceptually:

```text
ACVP vectors / session
        |
        v
NGI541 ACVP adapter
        |
        v
Public NGI541 API
        |
        v
Production engine
```

ACVP-specific request handling, registration metadata, vector processing, and
protocol behavior remain outside the production engine.

The ACVP layer currently registers and processes:

- ACVP-AES-CBC;
- ACVP-AES-CTR;
- ACVP-AES-GCM;
- SHA2-224;
- SHA2-256.

## libacvp

NGI541 uses Cisco's `libacvp` for ACVP protocol integration.

The repository pins the validation dependency to a specific upstream revision
for reproducibility.

`libacvp` is not a production dependency of the NGI541 engine and is not
required by applications using NGI541.

It exists only in the validation/tooling dependency graph.

## Local and offline ACVP validation

Before external ACVTS execution, the NGI541 ACVP path is exercised locally.

The local validation workflow verifies:

- capability registration;
- adapter-to-public-API mapping;
- algorithm-specific callbacks;
- request and response semantics;
- offline vector processing;
- end-to-end JSON handling;
- regression behavior across supported algorithms.

This local layer makes ACVP behavior reproducible without requiring every
correctness check to depend on an external service.

## NIST ACVTS Demo validation

The NGI541 0.1.0 validation baseline completed a NIST ACVTS Demo validation
for the supported algorithm set.

The associated Demo validation identifier is:

```text
A11030
```

The validated algorithm set includes:

```text
AES-CBC
AES-CTR
AES-GCM
SHA2-224
SHA2-256
```

The validated implementation baseline is preserved by the frozen repository
tag:

```text
v0.1.0
```

The validation evidence is retained under:

```text
validation/evidence/acvts-demo/
```

The evidence set includes the registration profile, non-sample validation
results, metadata, checksums, and the validation record associated with
A11030.

## Meaning and limits of A11030

A11030 is a **NIST ACVTS Demo validation identifier** associated with the
validated NGI541 0.1.0 baseline.

It must not be represented as:

- a Production CAVP validation certificate;
- a FIPS 140-2 or FIPS 140-3 certificate;
- a CMVP module validation;
- evidence that every later NGI541 commit or release was independently
  revalidated by NIST.

The correct interpretation is:

```text
NGI541 v0.1.0
        |
        v
NIST ACVTS Demo workflow
        |
        v
supported algorithm vectors passed
        |
        v
Demo validation identifier A11030
```

The NGI541 0.1.1 release contains project-readiness, packaging,
documentation, provenance, and integration work performed after the frozen
0.1.0 validation baseline.

Therefore, the existence of A11030 must not be used to imply that the entire
0.1.1 source tree is itself the exact NIST-tested artifact.

## Evidence preservation

Validation evidence is treated as a reproducibility artifact.

The project preserves enough information to identify:

- the implementation baseline;
- the algorithm registration profile;
- the external validation context;
- the result set;
- the associated validation identifier;
- integrity checks for retained evidence.

Secrets and credential material are not part of the public evidence set.

Examples of material that must not be published include:

- private keys;
- TOTP seed values;
- access tokens;
- authentication credentials;
- private credential files.

## Reproducibility

NGI541 validation is designed around reproducible inputs and explicit build
boundaries.

Important properties include:

- deterministic randomized differential testing;
- pinned validation dependencies;
- explicit ACVP capability definitions;
- clean separation between production and validation dependencies;
- sanitizer-enabled regression runs;
- retained validation metadata and checksums;
- frozen reference tags for externally validated baselines.

Reproducibility is treated as part of the validation design rather than as a
post-release documentation task.

## Validation does not equal certification

NGI541 validation evidence establishes correctness and standards-facing
engineering evidence for the tested scope.

It does not by itself constitute a FIPS 140 module certification.

A future production CAVP or CMVP/FIPS validation track would be a separate
formal process with its own requirements, operating-environment definition,
laboratory interaction, artifact controls, and release constraints.

Such a track should be undertaken only when justified by a concrete deployment
or certification requirement.

## Current validation status

For the NGI541 0.1.x line:

```text
Known-answer tests                 complete
Public API/runtime tests           complete
Differential correctness testing   complete
ASan/UBSan hardening               complete
Local/offline ACVP validation      complete
NIST ACVTS Demo validation         complete
Demo identifier                    A11030
Production CAVP validation         not claimed
FIPS 140 / CMVP validation         not claimed
```

Fuzzing and additional external validation may be added as later hardening
work, but they are not represented as completed evidence for the current
release line.

## Validation principles

The NGI541 validation strategy follows these principles:

1. Validate through the public API.
2. Keep validation dependencies out of the production engine.
3. Prefer multiple independent evidence layers over a single test source.
4. Preserve deterministic and reproducible test inputs where practical.
5. Convert discovered defects into regression coverage.
6. Keep external validation claims narrower than the evidence actually
   supports.
7. Preserve exact provenance between externally validated baselines and later
   development.

## Related documentation

See also:

- [`architecture.md`](architecture.md) for production and validation
  boundaries;
- [`legal/PROVENANCE.md`](legal/PROVENANCE.md) for source provenance;
- the future public API documentation for request and error semantics;
- the future ABI policy document for release compatibility guarantees.
