# NGI541 ABI and Versioning Policy

This document defines the public ABI and version-compatibility policy for the
NGI541 `0.x` development series.

NGI541 is still in pre-1.0 development. The public API boundary has been
established, but the project does not promise indefinite ABI stability across
all `0.x` minor releases.

The purpose of this policy is to make the supported compatibility boundary
explicit for applications, package maintainers, and downstream integrations.

## 1. Versioning model

NGI541 uses semantic versioning-style release numbers:

```text
MAJOR.MINOR.PATCH
```

For the current development series:

```text
0.MINOR.PATCH
```

The `0.x` major version indicates that the project is still allowed to evolve
its public API and ABI before a future `1.0.0` stability commitment.

The current release line is:

```text
0.1.x
```

## 2. Compatibility policy for 0.x

Within the same `0.x` minor release line, patch releases are intended to remain
source- and ABI-compatible.

For example:

```text
0.1.0 -> 0.1.1   same compatibility line
0.1.1 -> 0.1.2   same compatibility line
```

Compatibility is not guaranteed across different `0.x` minor release lines.

For example:

```text
0.1.x -> 0.2.x   compatibility not guaranteed
0.2.x -> 0.3.x   compatibility not guaranteed
```

A minor-version transition in the `0.x` series may therefore include changes
to public data structures, function signatures, semantics, or binary
compatibility where such changes are justified by the project architecture.

## 3. What is part of the public ABI

The public ABI consists only of explicitly installed and documented
consumer-facing interfaces.

The installed public headers are:

```text
include/ngi541/
├── api.h
├── crypto.h
└── engine.h
```

Public C functions, public enums, public request structures, and public status
codes declared through these headers are part of the public ABI for the
release line in which they are documented.

The canonical installed CMake targets are:

```text
NGI541::engine
NGI541::engine_shared
```

These are public package interfaces.

## 4. What is not part of the public ABI

The following are explicitly outside the public ABI:

```text
src/*
```

including internal engine structures, providers, handlers, cryptographic core
types, support-layer types, and implementation-specific headers.

The following exported CMake targets are also implementation details:

```text
NGI541::_core
NGI541::_support
NGI541::_crypto_isa
```

They exist to preserve the transitive dependency graph of the installed
package.

Applications and downstream packages must not treat them as stable public
interfaces.

Validation-specific code is also outside the public ABI:

```text
validation/*
```

Likewise, test-only code and helpers under:

```text
tests/*
```

are not public interfaces.

## 5. Public API versus ABI

The terms API and ABI are related but distinct.

The public API describes the source-level contract:

```text
function names
function parameters
public structures
public enums
status values
documented behavior
```

The ABI describes the binary-level contract required for already compiled
applications to continue interoperating with a compatible NGI541 library.

ABI-sensitive elements include:

- exported symbol names;
- function calling conventions;
- public structure size and layout;
- enum and constant values where exposed through the binary contract;
- library SONAME;
- symbol visibility;
- architecture-specific binary compatibility.

An API-compatible source change is not automatically an ABI-compatible binary
change.

NGI541 therefore treats ABI policy as a separate release concern.

## 6. Request structure compatibility

NGI541 public request structures include:

```c
struct_size
```

Consumers initialize this field using:

```c
.struct_size = sizeof(request)
```

The field provides an explicit representation of the structure size supplied
by the caller.

The existence of `struct_size` does not by itself guarantee that every future
structure extension will be backward- or forward-compatible.

Compatibility remains governed by the release policy documented here and by
the validation performed for each release line.

Applications must initialize public request structures according to the
documented API and must not depend on undocumented trailing fields, padding,
or internal layout assumptions.

## 7. Shared-library versioning

The NGI541 shared library uses a release version and an ABI compatibility
version.

For the `0.1.x` release line, the conceptual relationship is:

```text
project version     0.1.x
ABI line            0.1
```

The shared library therefore uses a compatibility identity corresponding to
the `0.1` ABI line.

On macOS, a release such as `0.1.0` produces versioned artifacts of the form:

```text
libngi541_engine.0.1.0.dylib
libngi541_engine.0.1.dylib
libngi541_engine.dylib
```

with the dynamic-library identity using the ABI line:

```text
@rpath/libngi541_engine.0.1.dylib
```

On ELF-based Unix systems, the corresponding model is expected to use a
versioned shared object and SONAME associated with the same ABI line.

The exact platform filename syntax may differ, while the compatibility policy
remains the same.

## 8. CMake package compatibility

The installed CMake package exposes:

```cmake
find_package(NGI541 CONFIG REQUIRED)
```

The generated package version file uses compatibility semantics aligned with
the current `0.x` policy:

```text
SameMinorVersion
```

Therefore a consumer requesting a version within the same minor line may
accept a compatible patch release, while a different `0.x` minor line is not
implicitly treated as compatible.

Conceptually:

```text
requested 0.1.0
available 0.1.1
    -> same minor compatibility line

requested 0.1.x
available 0.2.x
    -> not implicitly compatible
```

This package-level behavior is intended to reflect the ABI policy rather than
replace it.

## 9. Static-library compatibility

Static libraries do not provide runtime ABI compatibility in the same way as a
versioned shared library.

Applications linking statically against NGI541 incorporate the selected object
code at link time.

For static consumers, source compatibility and link compatibility are still
governed by the public API and the release policy, but upgrading NGI541
requires relinking the application.

The canonical static CMake target is:

```text
NGI541::engine
```

## 10. Shared-library compatibility

The shared-library target is:

```text
NGI541::engine_shared
```

A consumer linked against a shared NGI541 `0.1.x` library is intended to remain
compatible with patch releases in the same ABI line unless a release explicitly
documents an exceptional compatibility break.

Such an exception should be treated as a release-management event and clearly
documented in the changelog and release notes.

No compatibility guarantee is made between different `0.x` minor ABI lines.

## 11. Symbol visibility

NGI541 keeps implementation visibility narrower than the internal source tree.

Internal implementation symbols are not intended to become part of the public
ABI merely because they exist in object files or source code.

Only symbols intentionally exposed through the public NGI541 API should be
treated as supported consumer entry points.

Applications must not use undocumented symbols discovered through binary
inspection.

A future ABI audit may introduce explicit exported-symbol verification or
symbol versioning if required by platform or distribution needs.

## 12. Header compatibility

Installed public headers are part of the development contract.

Applications should include only:

```c
#include <ngi541/api.h>
#include <ngi541/crypto.h>
#include <ngi541/engine.h>
```

as appropriate.

Applications must not include files through paths such as:

```text
src/...
engine/internal/...
support/...
```

Internal headers may change at any time without an ABI or source-compatibility
guarantee.

## 13. CMake target stability

The following installed target names are public package interfaces for the
`0.1.x` line:

```text
NGI541::engine
NGI541::engine_shared
```

The following are not public interfaces:

```text
NGI541::_core
NGI541::_support
NGI541::_crypto_isa
```

The leading underscore is intentional and indicates that these targets exist
for package implementation purposes.

Downstream projects should link only to the public targets.

## 14. pkg-config compatibility

On supported Unix-like installations, NGI541 also provides:

```text
ngi541.pc
```

The pkg-config module name is:

```text
ngi541
```

The pkg-config interface exposes the public engine library and the public
include directory.

Private implementation dependencies may be exposed through `Libs.private` for
static linking.

The pkg-config file is a consumer integration interface, but it does not expand
the public ABI beyond the headers and documented exported symbols.

## 15. Thread-safety and ABI

Thread-safety guarantees are behavioral API properties rather than purely
binary layout properties.

NGI541 `0.1.x` does not currently declare a public thread-safety guarantee.

A future release may strengthen the concurrency contract without necessarily
changing the binary ABI, provided the public structures and exported function
signatures remain compatible.

See [`API.md`](API.md) for the current API-level thread-safety statement.

## 16. Deprecation policy during 0.x

Because NGI541 remains in pre-1.0 development, the project may need to evolve
public interfaces more quickly than a mature `1.x` library.

Where practical, incompatible public changes should follow this process:

```text
identify required API/ABI change
        |
        v
document the change
        |
        v
update CHANGELOG / release notes
        |
        v
advance the 0.x minor release line
        |
        v
update SOVERSION where ABI compatibility changes
```

The project should avoid silent ABI breaks inside a patch release.

If an exceptional patch-level compatibility break becomes unavoidable, it
must be explicitly documented rather than hidden behind an unchanged
compatibility claim.

## 17. Planned 0.1.1 release relationship

The frozen `v0.1.0` tag represents the externally validated NGI541 baseline
associated with NIST ACVTS Demo validation identifier A11030.

The planned `0.1.1` release remains in the same `0.1` compatibility line and
primarily adds public-readiness work such as:

- installable CMake packaging;
- canonical public CMake targets;
- pkg-config integration;
- public API examples;
- installation components;
- documentation;
- release engineering improvements.

The `0.1.1` release must not imply that its entire source tree is the exact
artifact evaluated in the NIST ACVTS Demo workflow.

Validation provenance is documented separately in
[`validation.md`](validation.md).

## 18. Transition to 0.2.x

The `0.2.x` line is reserved for a future architectural evolution where public
execution interfaces may change.

Potential future work includes a batch-oriented API designed for
high-throughput networking and data-plane workloads.

Because this may affect public structures, request semantics, or execution
contracts, the project does not promise ABI compatibility between:

```text
0.1.x
```

and:

```text
0.2.x
```

Any such change must be documented as part of the `0.2.0` release contract.

## 19. Future 1.0 policy

NGI541 has not yet committed to a `1.0` ABI freeze.

A future `1.0.0` release should define a stronger long-term compatibility
policy before publication.

That policy may include:

- stable public structure rules;
- explicit symbol export lists;
- formal SONAME policy;
- deprecation windows;
- stronger source and binary compatibility guarantees;
- cross-platform ABI verification;
- compatibility testing against previous stable releases.

Until such a policy exists, consumers should follow the `0.x` rules documented
here.

## 20. Package-maintainer guidance

Package maintainers should treat the NGI541 compatibility line as part of the
runtime package identity.

For the `0.1.x` series:

```text
ABI compatibility line: 0.1
```

Development packages may expose headers, static libraries, CMake metadata, and
pkg-config metadata, while runtime packages should contain the versioned shared
library and required redistribution notices.

Exact distribution package names are outside the upstream ABI contract and may
follow the conventions of the target operating system or distribution.

## 21. Compatibility summary

The current policy can be summarized as:

| Change | Compatibility expectation |
| --- | --- |
| `0.1.0 -> 0.1.1` | Intended source and ABI compatibility |
| `0.1.1 -> 0.1.2` | Intended source and ABI compatibility |
| `0.1.x -> 0.2.x` | Compatibility not guaranteed |
| Internal `src/` changes | No public compatibility guarantee required |
| `NGI541::_*` target changes | No public compatibility guarantee required |
| Public header/function changes within patch line | Must preserve compatibility or be explicitly documented as an exception |
| Future `1.0` | Stronger policy to be defined before release |

## 22. Related documentation

See also:

- [`API.md`](API.md) for the public source-level API contract;
- [`architecture.md`](architecture.md) for public/internal architecture
  boundaries;
- [`validation.md`](validation.md) for the validation baseline and A11030;
- [`legal/PROVENANCE.md`](legal/PROVENANCE.md) for source provenance;
- the future `CHANGELOG.md` for release-specific compatibility changes.
