# NGI541 Roadmap

This document describes the current public development direction for NGI541.

The roadmap is intentionally outcome-oriented. It explains the major technical
stages of the project without exposing every internal development task or
treating tentative future work as a release commitment.

NGI541 is currently focused on three priorities:

```text
verification
    |
    v
public project readiness
    |
    v
performance architecture and reproducible benchmarking
```

The roadmap may change as implementation evidence, platform coverage, and
external integration requirements evolve.

## 1. Current project position

The first standalone NGI541 baseline is complete.

The project currently has:

- a standalone cryptographic execution engine;
- an independent public API;
- AES-CBC, AES-CTR, and AES-GCM support;
- SHA2-224 and SHA2-256 support;
- public API validation and regression tests;
- deterministic differential correctness testing against OpenSSL;
- AddressSanitizer and UndefinedBehaviorSanitizer hardening;
- ACVP validation infrastructure;
- a completed NIST ACVTS Demo validation for the frozen `v0.1.0` baseline;
- NIST ACVTS Demo validation identifier `A11030`;
- provenance and third-party licensing documentation;
- static and shared-library builds;
- installable CMake package metadata;
- pkg-config integration on supported Unix-like platforms;
- public API examples;
- installation components and manifest-based uninstall support.

The current engineering focus is preparing the first public-ready packaged
release in the `0.1.x` line.

## 2. Release-line overview

The current high-level release direction is:

```text
v0.1.0
    |
    | externally validated baseline
    v
v0.1.1
    |
    | first public-ready packaged release
    v
0.2.x
    |
    | NGI541-specific performance architecture
    v
later releases
    |
    +--> broader hardware support
    +--> performance regression infrastructure
    +--> reproducibility and research artifacts
    +--> formal validation track if justified
```

The version boundaries are intentional.

`0.1.x` establishes the verified standalone library and public-consumer
foundation.

`0.2.x` is reserved for architectural work that may change the public
execution model and therefore is not assumed to be ABI-compatible with
`0.1.x`.

See [`ABI.md`](ABI.md) for the compatibility policy.

## 3. Completed foundation

The following foundation milestones are complete.

### Provenance and project identity

Completed work includes:

- Apache-2.0 project licensing;
- explicit FD.io VPP source provenance;
- exact upstream baseline identification;
- preserved upstream copyright and license notices;
- NGI541 modification notices for adapted upstream-derived files;
- third-party notices;
- separation between public project code and credential material.

### Standalone execution engine

The production engine is independent of the FD.io VPP runtime.

The current architecture provides:

```text
public NGI541 API
        |
        v
execution facade
        |
        v
native provider
        |
        v
cryptographic core
```

Static and shared-library builds are available.

### Public API boundary

The consumer-facing interface is defined under:

```text
include/ngi541/
```

Internal engine structures remain private.

Validation tooling exercises the public API rather than bypassing it through
private execution structures.

### Validation foundation

The current validation stack includes:

```text
known-answer and API tests
        |
        v
differential correctness testing
        |
        v
sanitizer hardening
        |
        v
local/offline ACVP validation
        |
        v
NIST ACVTS Demo validation
```

The frozen `v0.1.0` baseline is associated with NIST ACVTS Demo validation
identifier `A11030`.

See [`validation.md`](validation.md) for the exact claim boundary.

## 4. Current milestone: public-ready 0.1.1

The current release objective is:

> NGI541 `0.1.1` — first public-ready packaged release.

This release is intended to convert the validated standalone implementation
into a project that an external engineer can understand, build, install, link,
and evaluate without private project context.

The current `0.1.1` readiness work includes:

- complete public architecture documentation;
- public validation documentation;
- public API documentation;
- ABI/version policy;
- supported-platform policy;
- performance-status and benchmark methodology documentation;
- public roadmap;
- changelog;
- README cross-links;
- installable static and shared libraries;
- CMake package export;
- pkg-config integration;
- install components;
- safe uninstall support;
- external consumer validation;
- canonical source-release engineering.

The final `0.1.1` release should preserve the distinction between:

```text
v0.1.0
    externally validated implementation baseline

v0.1.1
    public-readiness and packaging release in the same 0.1 compatibility line
```

The project must not imply that the complete `0.1.1` source tree is the exact
artifact evaluated by NIST ACVTS Demo.

## 5. 0.1.1 release engineering

Before the first public-ready release, NGI541 will establish a reproducible
source-distribution process.

The intended release chain is:

```text
release-content freeze
        |
        v
signed Git tag
        |
        v
canonical source archive
        |
        v
SHA-256 checksum
        |
        v
detached release signature
        |
        v
clean archive extraction
        |
        v
configure / build / test / install
        |
        v
external consumer smoke tests
        |
        v
GitHub Release
```

The canonical source archive should be buildable independently of the original
Git working tree.

Special care is required for external source dependencies such as the pinned
`third_party/libacvp` submodule so that the canonical archive has a clearly
defined and reproducible dependency model.

The automatically generated GitHub source archives are not assumed to replace
the canonical project release artifact.

## 6. Public project launch

After the `0.1.1` release content is frozen and release artifacts are verified,
the project can move to a public-repository launch.

The public project should provide a clear entry point for:

```text
what NGI541 is
how to build it
how to install it
how to use the public API
what has been validated
what has not been claimed
which platforms are supported
how releases are versioned
how performance will be measured
```

The public launch should not depend on comparative performance claims.

Correctness, provenance, validation evidence, and reproducibility are the
primary foundation of the initial release.

## 7. 0.2.x: performance execution architecture

The `0.2.x` line is intended to introduce the first NGI541-specific execution
architecture optimized explicitly for high-throughput networking and
data-plane workloads.

Potential work includes:

- a public batch-oriented execution API;
- explicit multi-operation submission;
- reduced per-operation dispatch overhead;
- data layout designed for SIMD-friendly execution;
- improved cache locality;
- separation between control-path setup and hot-path execution;
- execution models suitable for packet-processing workloads;
- clearer ISA-specific implementation tiers.

The exact API must be designed from workload requirements rather than from
benchmark convenience.

Any new public execution interface must receive the same treatment as the
current API:

```text
contract
    |
    v
correctness tests
    |
    v
differential validation
    |
    v
sanitizer hardening
    |
    v
ABI/API documentation
    |
    v
performance evaluation
```

Because this work may change public request structures or execution semantics,
ABI compatibility between `0.1.x` and `0.2.x` is not guaranteed.

## 8. Benchmark Specification v1

Before publishing comparative performance results, NGI541 will define
**Benchmark Specification v1**.

The specification will define at least:

- canonical hardware metadata;
- operating-system metadata;
- compiler and build configuration;
- CPU affinity;
- CPU frequency and boost policy;
- cache warm-up;
- message sizes;
- batch sizes;
- algorithms and key sizes;
- iteration and sample counts;
- reported metrics;
- statistical methodology;
- comparison-library configuration;
- result artifact format.

The initial comparison set is expected to include relevant implementations
such as:

```text
NGI541
OpenSSL
Intel IPsec Multi-Buffer
```

FD.io VPP native crypto may be included as a historical or integration
baseline where the comparison can be made reproducibly.

No comparison implementation should be intentionally placed at a
disadvantage through inappropriate compiler, ISA, batching, or configuration
choices.

See [`performance.md`](performance.md) for the benchmark policy.

## 9. Benchmark harness

After Benchmark Specification v1 is frozen, the project will implement a
dedicated benchmark harness.

The harness should support machine-readable result output and preserve the
metadata required to reproduce each run.

The intended progression is:

```text
Benchmark Specification v1
        |
        v
benchmark harness
        |
        v
NGI541 local baseline
        |
        v
OpenSSL comparison
        |
        v
IPsec-MB comparison
        |
        v
published reproducible results
```

Primitive benchmarks and future batch benchmarks must be reported as separate
result classes.

## 10. Performance regression infrastructure

After a stable benchmark baseline exists, performance testing should become
part of the engineering lifecycle rather than remain a one-time exercise.

The intended model is:

```text
known baseline
        |
        v
new implementation change
        |
        v
controlled benchmark
        |
        v
statistical comparison
        |
        +--> expected improvement
        |
        +--> no material change
        |
        +--> investigate regression
```

Performance regression thresholds must account for measurement noise.

Correctness CI and performance CI should remain separate gates.

## 11. x86-64 platform expansion

The first performance work will focus on x86-64 systems where the current
implementation and validation evidence are strongest.

The hardware campaign should expand beyond a single processor generation.

Relevant goals include:

- newer Intel platforms;
- AMD x86-64 platforms;
- ISA-path characterization;
- per-core efficiency;
- batch scaling;
- memory/cache behavior;
- compiler sensitivity.

The project should record exact CPU, compiler, OS, and build metadata for all
published measurements.

## 12. ARM64 enablement

ARM64 is a later portability and performance milestone.

The source tree already contains ARM/NEON-derived support material, but ARM64
is not currently part of the supported `0.1.x` platform contract.

The enablement path should include:

```text
clean build
    |
    v
public API tests
    |
    v
differential correctness
    |
    v
sanitizer coverage where available
    |
    v
package/install validation
    |
    v
real-hardware ISA validation
    |
    v
performance characterization
```

Linux AArch64 / Neoverse systems are particularly relevant to networking and
data-plane use cases.

Apple Silicon may be evaluated separately.

See [`PLATFORMS.md`](PLATFORMS.md) for the current support matrix.

## 13. External replication

A later milestone is independent reproduction outside the original development
environment.

External replication should cover:

- clean source build;
- test execution;
- package consumption;
- benchmark reproduction;
- hardware-platform comparison.

This is particularly important for performance claims because independent
replication reduces the risk that results depend on an undocumented local
environment.

## 14. Reproducibility and research artifact

Once validation and performance infrastructure are mature, NGI541 should
provide a reproducible research/engineering artifact.

The artifact may include:

- canonical source release;
- benchmark specification;
- benchmark harness;
- exact dependency revisions;
- environment metadata;
- raw benchmark datasets;
- result-generation scripts;
- validation evidence;
- experiment reproduction instructions.

The project should make it possible to trace a published result back to:

```text
source revision
    +
build configuration
    +
hardware
    +
execution command
    +
raw results
```

## 15. Publication / paper track

A technical publication may follow after the architecture and benchmark
evidence are stable.

A useful publication should be evidence-driven rather than primarily
descriptive.

Potential topics include:

- extracting a standalone execution engine from a high-performance data plane;
- verification-first development of SIMD cryptographic code;
- public API versus performance API separation;
- SIMD/batching architecture for networking workloads;
- reproducible comparison with general-purpose and multi-buffer libraries;
- integration into VPP/CSIT.

The paper should use reproducible public artifacts wherever possible.

## 16. Formal validation track

Production CAVP and CMVP/FIPS validation are not part of the immediate
`0.1.1` release objective.

The current NIST evidence is specifically a NIST ACVTS Demo validation.

A future formal validation track may be justified by:

- a concrete downstream deployment requirement;
- a product or customer requirement;
- integration into a regulated environment;
- funding that supports the laboratory and certification process.

Such a track would be separate from ordinary open-source release engineering.

It may require:

- an accredited laboratory;
- controlled operating-environment definitions;
- stricter module-boundary decisions;
- formal artifact management;
- additional documentation;
- certification-specific release controls.

The project should not claim formal FIPS or Production CAVP status unless that
process has actually been completed.

## 17. Distribution packaging

The first public source release does not need to wait for inclusion in Linux
distribution archives.

After a stable upstream `0.1.1` release exists, distribution packaging can
proceed separately.

Potential stages include:

```text
upstream source release
        |
        v
Debian source packaging
        |
        +--> runtime package
        +--> development package
        +--> documentation package
        |
        v
lintian / package tests
        |
        v
distribution submission
```

Additional packaging such as RPM or Homebrew may follow based on user demand.

Native distribution packaging should use the distribution's standard tooling
rather than treating generic CPack output as a substitute for official
packaging policy.

## 18. Security and hardening follow-up

The current `0.1.x` line includes differential testing and sanitizer hardening.

Additional security work may include:

- structured fuzzing;
- API misuse testing;
- expanded negative testing;
- concurrency validation;
- side-channel analysis where appropriate;
- compiler/toolchain hardening;
- expanded platform-specific sanitizer coverage.

These activities should be added to the validation evidence chain only after
they are implemented and reproducible.

Fuzzing is therefore a planned hardening stage, not a completed `0.1.x`
validation claim.

## 19. Public API evolution

The current public API is intentionally small and operation-oriented.

The project should resist adding general-purpose cryptographic abstractions
that are unrelated to its data-plane execution goals.

Public API evolution should be driven by demonstrated consumer requirements.

The expected direction is:

```text
0.1.x
    simple, explicit operation-oriented API

0.2.x
    possible batch/high-throughput API

later
    integration-specific interfaces only where justified
```

NGI541 is not intended to become a general replacement for OpenSSL.

## 20. Project principles

Future roadmap decisions should preserve several core principles.

### Verification before claims

Correctness evidence precedes performance claims.

### Public boundary first

Validation and external integrations should exercise documented public
interfaces rather than depend on private implementation structures.

### Reproducibility

Validation and benchmark results should be reproducible from explicit source,
build, environment, and execution metadata.

### Standalone architecture

VPP, OpenSSL, libacvp, and benchmark dependencies must not become accidental
production dependencies unless the architecture explicitly changes.

### Narrow claims

Public statements should remain no broader than the evidence that supports
them.

### Performance with workload context

Performance optimization should target real networking and data-plane workload
models rather than synthetic benchmark scores alone.

## 21. High-level milestone status

The current public roadmap can be summarized as:

| Milestone | Status |
| --- | --- |
| Provenance / legal baseline | Complete |
| Standalone execution engine | Complete |
| Public API boundary | Complete |
| ACVP validation infrastructure | Complete |
| NIST ACVTS Demo validation | Complete |
| Differential correctness | Complete |
| Sanitizer hardening | Complete |
| Installable package foundation | Complete |
| Public documentation set | In progress |
| `0.1.1` release engineering | Next |
| Public repository / release launch | Planned |
| Benchmark Specification v1 | Planned |
| Benchmark harness | Planned |
| OpenSSL / IPsec-MB comparative campaign | Planned |
| Performance regression infrastructure | Planned |
| Wider Intel / AMD hardware campaign | Planned |
| ARM64 enablement | Planned |
| VPP integration | Planned |
| CSIT data-plane campaign | Planned |
| External replication | Planned |
| Research/reproducibility artifact | Planned |
| Production CAVP / CMVP / FIPS track | Conditional / long-term |

## 22. Immediate next steps

The immediate sequence before the first public-ready release is:

```text
complete public documentation
        |
        v
complete CHANGELOG
        |
        v
update README cross-links
        |
        v
update Documentation install component
        |
        v
align project version to 0.1.1
        |
        v
final release-content audit
        |
        v
release-content freeze
        |
        v
canonical 0.1.1 source release
```

Performance architecture and comparative benchmarking follow after the
`0.1.1` public release foundation is established.

## 23. Related documentation

See also:

- [`architecture.md`](architecture.md) for production architecture;
- [`validation.md`](validation.md) for correctness and ACVTS evidence;
- [`API.md`](API.md) for the public API contract;
- [`ABI.md`](ABI.md) for release compatibility policy;
- [`PLATFORMS.md`](PLATFORMS.md) for supported platforms and ISA policy;
- [`performance.md`](performance.md) for benchmark methodology and claim
  policy;
- [`legal/PROVENANCE.md`](legal/PROVENANCE.md) for source provenance.
