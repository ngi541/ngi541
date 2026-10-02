# NGI541 Platform Support

This document defines the operating-system, architecture, compiler, and ISA
support status for the NGI541 `0.1.x` release line.

The purpose of this document is to distinguish between:

- platforms that are continuously exercised in CI;
- platforms that have been exercised through additional local or validation
  runs;
- implementation code that exists in the source tree but is not yet part of
  the supported platform contract;
- platforms that are planned but not currently supported.

The presence of architecture-specific source code does not by itself establish
a public support guarantee.

## 1. Support-status terminology

NGI541 uses the following terms:

| Status | Meaning |
| --- | --- |
| **Supported / CI-tested** | The platform is part of the regular project CI matrix and is expected to build and pass the applicable test suite. |
| **Tested** | The platform has been exercised successfully, but does not have the same CI coverage as a fully supported configuration. |
| **Experimental** | Some implementation support exists, but the platform contract is not yet complete. |
| **Planned** | Support is intended, but the platform is not currently part of the supported release surface. |
| **Not supported** | NGI541 `0.1.x` does not currently provide a supported build/runtime contract for the platform. |

A configuration should not be described as supported solely because it
compiles once or because architecture-specific headers exist in the source
tree.

## 2. Current platform matrix

The current `0.1.x` support matrix is:

| Operating system | Architecture | Compiler | Status | Current evidence |
| --- | --- | --- | --- | --- |
| Linux / Ubuntu 24.04 | x86-64 | GCC | **Supported / CI-tested** | Debug and Release core builds; public API tests; full test suite; differential correctness testing. |
| Linux / Ubuntu 24.04 | x86-64 | Clang | **Supported / CI-tested** | Debug and Release core builds; public API tests; full test suite; differential correctness testing; sanitizer campaigns. |
| macOS 15 | Intel x86-64 | AppleClang | **Supported / CI-tested** | Debug build; differential correctness suite; full test suite. |
| macOS 15 | Intel x86-64 | GCC 15 | **Supported / CI-tested** | Debug build; differential correctness suite; full test suite. |
| macOS 12.7.6 | Intel x86-64 | AppleClang | **Tested** | Local build/runtime validation and the frozen NGI541 `0.1.0` ACVTS Demo validation environment. |
| Linux | AArch64 | GCC / Clang | **Planned** | ARM/NEON-derived support code exists in the source tree, but no current CI-backed release support contract is declared. |
| macOS | Apple Silicon / arm64 | AppleClang | **Planned** | Not part of the current CI or validated release matrix. |
| Windows | x86-64 | MSVC / clang-cl | **Not supported** | No current Windows CI, packaging, DLL ABI, or validated runtime contract. |

This matrix describes the current project support policy, not every
configuration that may happen to compile.

## 3. Primary supported architecture

The current NGI541 `0.1.x` production and validation baseline is x86-64.

The supported x86-64 builds use architecture-specific compiler options required
by the current native cryptographic implementation.

Observed build configuration includes:

```text
-msse4.2
-maes
-mpclmul
```

These options correspond to the current SSE4.2, AES instruction, and
carry-less multiplication requirements used by the native x86 execution path.

A binary compiled with these options must not be assumed to run correctly on a
processor that does not provide the required instruction set.

NGI541 `0.1.x` does not currently promise a portable scalar fallback for CPUs
that lack the required x86 cryptographic/vector capabilities.

## 4. ISA-oriented implementation

NGI541 originates from selected FD.io VPP native crypto components and contains
architecture-specific vector support code.

The source tree includes implementation support associated with instruction
families such as:

```text
x86:
    SSE4.2
    AES instructions
    PCLMUL
    AVX2-related vector support
    AVX-512-related vector support

ARM:
    NEON-related vector support
```

However, the presence of those implementation files is not equivalent to a
supported runtime path.

For the `0.1.x` release line, only ISA behavior that is exercised by the
supported build and test matrix should be treated as part of the public
platform contract.

In particular, this document does **not** claim that NGI541 `0.1.x` currently
provides:

- a validated AVX2 execution tier;
- a validated AVX-512 execution tier;
- a validated VAES execution tier;
- a validated ARM NEON production build;
- automatic runtime dispatch across all available ISA levels;
- a scalar fallback for unsupported processors.

Those capabilities require dedicated build, runtime-dispatch, correctness, and
performance validation before they can be promoted into the supported matrix.

## 5. Linux support

The primary Linux CI environment is Ubuntu 24.04 on x86-64.

The regular core CI matrix exercises:

```text
GCC
    Debug
    Release

Clang
    Debug
    Release
```

with the engine and test suites enabled.

The Linux CI path includes:

- public API conformance tests;
- the full regular test suite;
- differential correctness testing;
- ACVP build and validation jobs where applicable;
- sanitizer-specific validation under Clang.

Linux/Clang is also the primary sanitizer environment for the current
hardening campaign.

### Sanitizers

The current Linux Clang validation includes:

```text
AddressSanitizer
LeakSanitizer
UndefinedBehaviorSanitizer
```

Sanitizer support is a validation configuration rather than a requirement for
normal production builds.

## 6. macOS support

Intel macOS is part of the current `0.1.x` support surface.

The CI matrix exercises:

```text
macOS 15 / Intel
    AppleClang
    GCC 15
```

with Debug builds, differential correctness testing, and the full applicable
test suite.

In addition, the NGI541 `0.1.0` externally validated baseline was exercised on
an Intel macOS environment running macOS 12.7.6.

The current packaging work has also been validated on Intel macOS, including:

- static-library installation;
- shared-library installation;
- versioned `.dylib` artifacts;
- CMake package discovery through `find_package(NGI541 CONFIG REQUIRED)`;
- the `NGI541::engine` installed target;
- the `NGI541::engine_shared` installed target;
- pkg-config consumption;
- custom installation prefixes;
- default `/usr/local` installation semantics through `DESTDIR` staging;
- relocatable CMake package discovery;
- Runtime, Development, and Documentation install components;
- manifest-based uninstall behavior.

This does not imply equivalent validation on Apple Silicon.

## 7. Apple Silicon

Apple Silicon / arm64 is not currently part of the supported NGI541 `0.1.x`
platform matrix.

The source tree contains ARM/NEON-derived support material, but the project has
not yet established the complete release contract required to declare Apple
Silicon support.

Before promotion to a supported status, the project should demonstrate at
least:

```text
clean arm64 build
        |
        v
public API test suite
        |
        v
differential correctness suite
        |
        v
sanitizer coverage where available
        |
        v
static/shared packaging
        |
        v
external consumer tests
```

ISA-specific correctness must also be verified on real ARM hardware.

## 8. Linux AArch64

Linux AArch64 is planned, but not currently declared supported for NGI541
`0.1.x`.

Support should not be inferred from the presence of NEON-related source files.

A future AArch64 support milestone should include:

- GCC and Clang builds;
- public API and full regression testing;
- differential correctness testing;
- sanitizer coverage where supported;
- static and shared package validation;
- CMake package consumption;
- platform-specific ISA verification;
- external hardware validation.

ARM64 / Neoverse systems are expected to be relevant to the later portability
and performance campaign.

## 9. Windows

Windows is not supported by the NGI541 `0.1.x` release line.

The current project does not claim a completed Windows contract for:

- MSVC builds;
- clang-cl builds;
- DLL export/import behavior;
- runtime library packaging;
- CMake package consumption on Windows;
- Windows-specific installation layout;
- CI validation;
- ABI verification.

CMake itself provides cross-platform installation mechanisms, but the presence
of cross-platform CMake code does not constitute Windows support.

Windows support should be introduced only after the public API visibility,
DLL ABI, compiler compatibility, tests, and packaging behavior have been
validated explicitly.

## 10. Compiler support

The current compiler support contract is:

| Compiler family | Platform | Status |
| --- | --- | --- |
| GCC | Linux x86-64 | Supported / CI-tested |
| Clang | Linux x86-64 | Supported / CI-tested |
| AppleClang | macOS Intel | Supported / CI-tested |
| GCC 15 | macOS Intel | Supported / CI-tested |
| MSVC | Windows | Not supported |
| clang-cl | Windows | Not supported |

NGI541 is written in C and currently requires C11 plus compiler extensions used
by the VPP-derived implementation.

The build system enables GNU/Clang extensions because the native crypto code
uses facilities such as:

- vector types;
- compiler attributes;
- architecture-specific intrinsics and extensions.

Therefore, generic ISO C11 compiler support should not be inferred from the
language version alone.

## 11. Build-system requirements

The current build system requires:

```text
CMake >= 3.20
```

The project uses:

```text
C11
C extensions enabled
```

Normal consumers do not need OpenSSL or libacvp to build or link the production
NGI541 engine.

Those dependencies belong to validation and differential-test configurations.

For the production/validation dependency boundary, see
[`architecture.md`](architecture.md).

## 12. Static and shared libraries

The supported packaging model provides both:

```text
static:
    NGI541::engine

shared:
    NGI541::engine_shared
```

On supported Unix-like platforms, the installation also provides
`pkg-config` metadata.

Shared-library filename and loader conventions are platform-specific.

For example, macOS uses versioned `.dylib` artifacts and an `@rpath` install
identity for the current shared-library ABI line.

The ABI compatibility policy is documented in
[`ABI.md`](ABI.md).

## 13. Installation layout

NGI541 uses CMake's standard installation-prefix model together with
`GNUInstallDirs`.

The project does not hardcode a distribution-specific installation location.

Conceptually:

```text
CMAKE_INSTALL_PREFIX
        |
        +--> bin/
        +--> lib/
        +--> include/
        +--> share/
```

On Unix-like systems, the default CMake prefix is normally used unless the user
or package manager provides an explicit prefix.

Distribution and package-manager builds are expected to override the prefix
and installation directories according to their own filesystem policy.

NGI541 supports `DESTDIR` staging for package construction.

## 14. Package-consumer support

For supported platforms, CMake is the canonical cross-platform package
interface:

```cmake
find_package(NGI541 CONFIG REQUIRED)

target_link_libraries(
    my_app
    PRIVATE
        NGI541::engine
)
```

On supported Unix-like systems, pkg-config is also available:

```bash
pkg-config --cflags --libs ngi541
```

The existence of pkg-config support does not define the Windows support
contract.

## 15. Endianness

The current supported execution matrix is based on the tested x86-64
environments listed above.

NGI541 `0.1.x` does not currently declare a general big-endian platform support
guarantee.

The presence of byte-order helpers in the implementation does not by itself
establish validated big-endian support.

Any future non-little-endian platform must be tested explicitly before being
added to the supported matrix.

## 16. Hardware support versus performance support

A platform being supported for correctness does not imply that its performance
characteristics have already been established.

For `0.1.x`:

```text
correctness / packaging support
    !=
completed performance characterization
```

The comparative benchmark campaign is still pending.

NGI541 therefore does not currently publish comparative throughput or latency
claims for the supported platforms.

Performance methodology is documented separately in
[`performance.md`](performance.md).

## 17. Adding a new supported platform

A new operating-system / architecture / compiler combination should not be
promoted to **Supported** until it has evidence covering the relevant release
surface.

The expected qualification path is:

```text
configure
    |
    v
build
    |
    v
public API tests
    |
    v
full regression tests
    |
    v
differential correctness
    |
    v
sanitizers where applicable
    |
    v
install/package validation
    |
    v
external consumer smoke test
    |
    v
CI coverage
```

Architecture-specific platforms additionally require real-hardware ISA
validation.

## 18. Current non-goals

The NGI541 `0.1.x` platform contract does not attempt to provide:

- universal CPU portability;
- a scalar implementation for every architecture;
- automatic support for every VPP-derived ISA helper present in the source;
- Windows binaries;
- Apple Silicon support without validation;
- Linux AArch64 support without validation;
- big-endian support without validation;
- performance guarantees based only on source-level ISA capabilities.

## 19. Planned platform work

Later platform work is expected to proceed in stages:

```text
current:
    Intel x86-64
        |
        v
additional x86-64:
    newer Intel
    AMD
        |
        v
ARM64:
    Linux AArch64 / Neoverse
    Apple Silicon where appropriate
```

The performance campaign should distinguish platform enablement from benchmark
results and should retain exact compiler, CPU, OS, and build metadata for each
measurement.

## 20. Related documentation

See also:

- [`architecture.md`](architecture.md) for the production architecture and
  internal/public boundary;
- [`API.md`](API.md) for the public source-level API contract;
- [`ABI.md`](ABI.md) for binary compatibility and shared-library versioning;
- [`validation.md`](validation.md) for correctness, sanitizer, and ACVP
  evidence;
- the future [`performance.md`](performance.md) for benchmark methodology and
  performance-status policy.
