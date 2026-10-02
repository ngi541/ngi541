# NGI541 Performance

This document defines the performance-status policy and benchmark methodology
for NGI541.

NGI541 is designed as a performance-oriented cryptographic execution engine for
networking and data-plane workloads.

The `0.1.x` release line does **not** make comparative performance claims.

The project has not yet completed the reproducible benchmark campaign required
to support statements such as:

```text
faster than OpenSSL
faster than Intel IPsec-MB
higher throughput than another cryptographic engine
lower latency than another cryptographic engine
```

Such claims must be supported by reproducible benchmark evidence before they
are published.

## 1. Current performance status

The current status is:

```text
performance-oriented architecture        established

correctness and validation baseline       established

public API and packaging                  established

comparative benchmark specification       pending

comparative benchmark campaign            pending

public comparative performance claims     not made
```

NGI541 `0.1.x` should therefore be described as:

> a verification-first, performance-oriented cryptographic execution engine

and not as:

> the fastest cryptographic engine

or:

> faster than OpenSSL / Intel IPsec-MB

until the corresponding benchmark evidence exists.

## 2. Performance and correctness are separate dimensions

Performance measurements are meaningful only after correctness has been
established for the implementation under test.

The intended order is:

```text
correctness
    |
    v
robustness
    |
    v
stable public execution boundary
    |
    v
benchmark specification
    |
    v
benchmark implementation
    |
    v
comparative measurements
```

NGI541 therefore treats the validation work completed for the `0.1.x`
baseline as a prerequisite for the performance campaign.

See [`validation.md`](validation.md) for the correctness and validation
evidence model.

## 3. Benchmark Specification v1

Before publishing comparative results, NGI541 will define a reproducible
**Benchmark Specification v1**.

The specification should define at least:

- hardware environment;
- operating-system environment;
- compiler and toolchain versions;
- compiler flags;
- NGI541 revision and build configuration;
- comparison-library versions and build configurations;
- CPU frequency and power-management policy;
- CPU affinity and isolation policy;
- NUMA placement where applicable;
- warm-up procedure;
- measured operation;
- message and packet sizes;
- batch sizes;
- iteration counts;
- sample counts;
- reported metrics;
- statistical aggregation;
- result-retention format.

Benchmark results that do not include sufficient environment metadata should
not be treated as canonical NGI541 performance evidence.

## 4. Benchmark layers

The performance campaign should distinguish multiple layers rather than
combining them into a single number.

### Primitive execution

Measures direct cryptographic operation cost.

Examples:

```text
AES-CBC
AES-CTR
AES-GCM
SHA-224
SHA-256
```

This layer answers:

> How efficiently does the engine execute an individual cryptographic
> primitive?

### Public API execution

Measures the cost of the supported NGI541 public API path.

This includes the consumer-facing execution boundary rather than calling
private low-level primitives directly.

This layer answers:

> What performance does an external NGI541 consumer observe through the
> documented API?

### Batch-oriented execution

A future batch-oriented API may expose a different execution model optimized
for high-throughput workloads.

That interface is not part of the `0.1.x` public API.

Any future batch benchmark must be reported separately from the current
single-operation API so that the results are not conflated.

### Network/data-plane integration

A later campaign may measure NGI541 in a networking context such as FD.io VPP
or an equivalent data-plane workload.

Those measurements are separate from primitive benchmarks because they include
additional system effects such as:

- packet processing;
- memory access;
- queueing;
- framework overhead;
- scheduling;
- NIC and driver behavior;
- protocol processing.

Primitive results must not be presented as equivalent to end-to-end network
performance.

## 5. Algorithms

The first benchmark specification should cover the current public algorithm
surface:

| Class | Algorithms |
| --- | --- |
| Cipher mode | AES-CBC |
| Counter mode | AES-CTR |
| AEAD | AES-GCM |
| Hash | SHA2-224, SHA2-256 |

AES benchmarks should cover:

```text
AES-128
AES-192
AES-256
```

where supported by the selected operation.

Encryption and decryption should be measured separately where they represent
distinct execution paths.

For AES-GCM, authenticated encryption and authenticated decryption should be
reported independently.

## 6. Input-size coverage

A single message size is insufficient for characterizing a cryptographic
engine.

Benchmark Specification v1 should include multiple input-size classes.

A useful initial structure is:

```text
small:
    packet/header-oriented sizes

medium:
    common networking payload sizes

large:
    bulk-throughput sizes
```

The exact canonical sizes must be defined before the benchmark campaign and
kept stable across compared implementations.

Candidate packet-oriented sizes may include values representative of
networking workloads, while larger values should characterize steady-state
bulk throughput.

The final set should be specified explicitly rather than selected differently
for each implementation.

## 7. Batch-size coverage

Batching can materially change cryptographic throughput and latency.

Where a benchmark API supports batching, results should cover multiple batch
sizes rather than reporting only the best-performing batch.

Conceptually:

```text
batch = 1
batch = small
batch = medium
batch = large
```

Exact batch sizes belong in Benchmark Specification v1.

Single-operation and batch results must be labeled separately.

NGI541 `0.1.x` currently exposes an operation-oriented public API and therefore
must not imply public batch performance that the API does not yet provide.

## 8. Core metrics

The benchmark campaign should report metrics appropriate to both primitive and
data-plane analysis.

### Throughput

Examples:

```text
bytes/s
Gb/s
operations/s
```

Throughput should always identify:

- algorithm;
- key size where applicable;
- direction;
- input size;
- batch size;
- thread count.

### Cycles per byte

For bulk cryptographic processing:

```text
cycles/byte
```

is useful for comparing CPU efficiency across implementations.

The CPU-frequency measurement methodology must be defined explicitly.

### Cycles per operation

For small-message workloads:

```text
cycles/operation
```

may be more informative than cycles/byte.

### Latency

For latency-sensitive operation paths, report a defined per-operation latency
metric.

The document must state whether the reported value is:

```text
mean
median
p95
p99
minimum
```

and how measurement overhead is accounted for.

### Scaling

Later multi-core benchmarks may report:

```text
1 thread
2 threads
4 threads
...
```

but single-core results should remain independently available.

Multi-core scaling must not replace per-core efficiency measurements.

## 9. Statistical methodology

Performance results should not be based on a single run.

A benchmark run should include:

```text
warm-up
    |
    v
multiple measured samples
    |
    v
outlier / stability inspection
    |
    v
reported aggregate
```

Benchmark Specification v1 should define:

- warm-up duration or iteration count;
- measurement duration;
- number of repeated samples;
- reported central tendency;
- variability metric;
- conditions under which a run is rejected.

The project should retain raw or sufficiently detailed intermediate results so
published aggregates can be reproduced.

## 10. CPU environment

Cryptographic performance is highly sensitive to CPU state.

Canonical runs should record at least:

```text
CPU vendor
CPU model
microarchitecture
core count
logical CPU count
microcode / relevant platform metadata where practical
available ISA features
NUMA topology where applicable
```

Benchmark policy should also define handling of:

- CPU turbo / boost;
- frequency scaling;
- thermal throttling;
- background load;
- CPU affinity;
- SMT / Hyper-Threading;
- core isolation where practical.

A comparison is not considered strong evidence if the compared
implementations are measured under materially different CPU conditions.

## 11. Compiler and build metadata

Every canonical result should identify:

```text
compiler family
compiler version
build type
optimization level
architecture flags
link mode
library version
source revision
```

For NGI541, the source revision should be recorded as an immutable Git commit
or release tag.

The same level of metadata should be retained for comparison implementations.

Compiler settings should be reasonable and documented for each implementation.

The benchmark must not intentionally disadvantage a comparison library through
an obviously inappropriate build configuration.

## 12. ISA behavior

NGI541 contains architecture-specific cryptographic and vector code.

Performance results must identify the ISA path actually exercised by the
measured build.

Source-code presence alone is not sufficient.

For example, the existence of:

```text
AVX2-related code
AVX-512-related code
NEON-related code
```

does not establish that a benchmark executed those paths.

Future benchmark tooling should record or verify the selected execution path
where practical.

See [`PLATFORMS.md`](PLATFORMS.md) for the current platform-support contract.

## 13. Cache state and warm-up

Cache state can materially affect short cryptographic measurements.

Benchmark Specification v1 should explicitly define its warm-up policy.

The benchmark should avoid publishing results where one implementation is
measured after a warm cache while another is measured under an effectively
cold-start condition unless cold-start behavior itself is the measurement
target.

Different benchmark classes may intentionally measure:

```text
steady-state warm execution
cold-start / initialization
```

but those results must be labeled separately.

The primary cryptographic throughput campaign should focus on stable
steady-state execution.

## 14. Initialization cost

`ngi541_engine_init()` is part of the public lifecycle but should not normally
be included in each cryptographic operation measurement.

The normal steady-state benchmark model is:

```text
initialize once
    |
    v
warm up
    |
    v
measure repeated cryptographic operations
```

Initialization latency may be measured separately if it becomes relevant to a
consumer use case.

The benchmark documentation must state whether initialization is included or
excluded.

## 15. Memory allocation

A benchmark must identify whether memory allocation occurs inside the measured
region.

The preferred primitive benchmark should use preallocated buffers where the
public API permits it.

Otherwise, allocator cost may dominate small-message results and obscure the
cryptographic execution cost.

If an implementation requires allocation as part of its documented public
operation, that behavior should not be artificially removed from a
consumer-level benchmark.

Therefore the project should distinguish:

```text
primitive implementation benchmark
public consumer-path benchmark
```

where necessary.

## 16. Static versus shared linking

Static and shared-library configurations may exhibit different performance or
link/load behavior.

The first canonical campaign should define one primary linking model and keep
it consistent across the comparison set.

Additional configurations may be reported separately.

The chosen link mode must be recorded in the benchmark metadata.

## 17. Comparison implementations

The initial comparative campaign is expected to consider implementations
relevant to the NGI541 problem domain.

Potential comparison baselines include:

```text
OpenSSL
Intel IPsec Multi-Buffer
```

FD.io VPP native crypto may be included as a historical or integration
baseline where the comparison can be made reproducibly.

The comparison policy must distinguish the roles of these projects:

```text
OpenSSL
    general-purpose cryptographic library
    and existing differential correctness oracle

Intel IPsec Multi-Buffer
    performance-oriented multi-buffer cryptographic library

FD.io VPP native crypto
    historical source lineage and possible networking baseline

NGI541
    standalone verification-first, performance-oriented execution engine
```

These implementations expose different APIs and optimization strategies.

Therefore, benchmark methodology must explain whether a result compares:

- equivalent primitive operations;
- equivalent public API calls;
- equivalent batch execution;
- equivalent networking workloads.

## 18. Fair-comparison policy

Comparative benchmarks should follow a simple rule:

> Compare equivalent work under equivalent conditions.

The project must avoid practices such as:

- selecting favorable message sizes for only one implementation;
- disabling hardware acceleration in a comparison library while enabling it in
  NGI541;
- comparing batch execution against single-operation execution without
  labeling the difference;
- using different CPU affinity or frequency policy between implementations;
- reporting only the best run for NGI541 and an arbitrary run for another
  implementation;
- comparing Debug and Release builds;
- omitting comparison-library version or build configuration.

A benchmark that cannot satisfy these conditions should be labeled
exploratory rather than canonical.

## 19. OpenSSL comparison

OpenSSL is already used as a correctness reference in NGI541 differential
testing.

Performance comparison is a separate activity.

The benchmark must not assume that correctness-oracle usage makes OpenSSL a
performance baseline automatically.

For performance measurements, the selected OpenSSL APIs, provider
configuration, build configuration, hardware acceleration, and version must be
documented explicitly.

## 20. Intel IPsec Multi-Buffer comparison

Intel IPsec Multi-Buffer is relevant because it is designed for high-throughput
cryptographic processing and batch/multi-buffer execution.

A fair comparison must account for API-model differences.

In particular:

```text
single-operation NGI541 0.1.x API
    !=
multi-buffer API
```

If IPsec-MB is measured through an explicitly batched path while NGI541 is
measured one operation at a time, that difference must be documented rather
than hidden.

A future NGI541 batch API should enable a more direct comparison of
high-throughput execution models.

## 21. Bare-metal versus virtualized environments

Canonical performance results should preferably use controlled bare-metal
systems for architecture comparisons.

Cloud or virtualized environments may be useful for:

- smoke testing;
- portability checks;
- preliminary measurements;
- reproducibility experiments.

They should not automatically be treated as the primary performance baseline
because CPU scheduling, frequency behavior, and underlying hardware allocation
may be less controlled.

The environment type must always be recorded.

## 22. Platform campaign

After the initial benchmark methodology is stable, the campaign is expected to
expand across hardware families.

A likely progression is:

```text
Intel x86-64
    |
    v
AMD x86-64
    |
    v
ARM64 / Neoverse
```

The purpose is not only to identify peak performance, but also to understand:

- portability;
- per-core efficiency;
- ISA dependence;
- scaling behavior;
- architectural bottlenecks.

Apple Silicon may be evaluated separately once it is part of the supported
platform matrix.

## 23. Regression benchmarking

After a stable baseline exists, performance testing should evolve from a
one-time campaign into regression infrastructure.

Conceptually:

```text
known benchmark baseline
        |
        v
new commit / release
        |
        v
repeat controlled benchmark
        |
        v
compare against baseline
        |
        +--> expected change
        |
        +--> investigate regression
```

Regression thresholds must be defined carefully enough to distinguish real
performance changes from measurement noise.

Correctness regressions and performance regressions should remain separate
gates.

## 24. Performance evidence artifacts

Canonical benchmark output should be preservable as data rather than only as
screenshots or prose.

A future result artifact should contain enough information to reconstruct:

```text
what was tested
where it was tested
how it was built
how it was executed
what was measured
what raw/aggregated results were produced
```

Possible result formats include structured JSON, CSV, or another
machine-readable representation accompanied by human-readable reports.

The exact schema belongs in Benchmark Specification v1.

## 25. Reproducibility

A published result should provide enough information for an independent
engineer to reproduce the experiment on equivalent hardware.

At minimum, reproducibility requires:

- exact source revisions;
- exact dependency versions;
- build configuration;
- benchmark command;
- hardware metadata;
- OS metadata;
- compiler metadata;
- affinity/frequency policy;
- input sizes;
- iteration/sample policy;
- raw or sufficiently detailed result data.

Reproducibility is part of the benchmark definition rather than an optional
post-processing step.

## 26. Reporting policy

Every published performance result should state its scope.

For example:

```text
algorithm
key size
operation
message size
batch size
thread count
CPU
OS
compiler
library revision
metric
```

Charts and summaries must retain enough context that a reader can determine
what was actually measured.

The project should avoid headline claims detached from the underlying
configuration.

## 27. Current claim policy

Until Benchmark Specification v1 and the corresponding benchmark campaign are
complete, the following wording is appropriate:

> NGI541 is performance-oriented and derived from native data-plane
> cryptographic implementation techniques.

The following wording is not currently supported:

```text
NGI541 is faster than OpenSSL.
NGI541 is faster than Intel IPsec Multi-Buffer.
NGI541 is the fastest AES-GCM implementation.
NGI541 provides X% better throughput.
```

Historical or exploratory internal observations must not be promoted into
public project claims without a reproducible benchmark campaign.

## 28. Benchmark campaign Definition of Done

A first public benchmark campaign should not be considered complete until it
has:

```text
Benchmark Specification v1          complete
benchmark harness                   complete
correctness gate                    pass
environment metadata               captured
NGI541 baseline                     captured
OpenSSL baseline                    captured
IPsec-MB baseline                   captured where applicable
multiple message sizes              captured
repeated samples                    captured
raw results                         retained
statistical summary                 generated
reproduction instructions           documented
public claims                       limited to measured evidence
```

VPP/CSIT and additional hardware platforms may follow as separate campaign
extensions rather than blocking the first primitive benchmark publication.

## 29. Relationship to future NGI541 architecture

The `0.1.x` API is primarily a correctness and consumer integration boundary.

Future NGI541 releases may add execution interfaces designed specifically for
higher-throughput use, including batching.

Such an API should not be introduced merely to improve benchmark numbers.

It should be driven by a defined workload model and validated independently for
correctness, ABI/API semantics, and performance.

Benchmark results from a future batch API must remain distinguishable from
`0.1.x` single-operation results.

## 30. Related documentation

See also:

- [`architecture.md`](architecture.md) for production and validation
  architecture;
- [`validation.md`](validation.md) for correctness and external validation
  evidence;
- [`API.md`](API.md) for the current public execution model;
- [`ABI.md`](ABI.md) for release compatibility policy;
- [`PLATFORMS.md`](PLATFORMS.md) for currently supported platforms and ISA
  policy;
- the future [`roadmap.md`](roadmap.md) for the planned benchmark and
  architecture milestones.
