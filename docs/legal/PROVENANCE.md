# Source Provenance

This document records the origin and licensing provenance of source code
incorporated into NGI541.

The purpose of this record is to maintain a clear separation between:

- original NGI541 development;
- publicly available upstream open-source code;
- modifications derived from upstream open-source code;
- third-party dependencies.

## Repository origin

NGI541 is an independent open-source software project.

Initial development is performed independently using personal development
equipment and publicly available technical information.

At the time this provenance record was created, no source code from FD.io VPP
or any other third-party project had been imported into the NGI541 source tree.

## Project license

NGI541 is licensed under the Apache License, Version 2.0.

See the repository root `LICENSE` file.

## Planned upstream source

NGI541 may incorporate or derive portions of code from the publicly available
FD.io VPP project.

Upstream project:

- Project: FD.io VPP
- Repository: https://github.com/FDio/vpp
- License: Apache License 2.0

Any such source import must be recorded in this document before or together
with the commit that introduces the source code.

Each import record must identify:

1. upstream project;
2. exact repository URL;
3. exact upstream commit SHA;
4. original source path;
5. NGI541 destination path;
6. upstream license;
7. original copyright notices;
8. whether the file is copied, derived, or independently implemented;
9. material NGI541 modifications;
10. corresponding NGI541 Git commit.

## FD.io Gerrit development history

Publicly available FD.io Gerrit changes may also be used as upstream
open-source material where their licensing and contribution provenance are
compatible with the FD.io VPP project license.

A planned architectural reference is:

- FD.io Gerrit Change: 44827
- Subject: `crypto: unify per-thread key_data allocation`
- Author: Ivan Ivanets
- Public source: https://gerrit.fd.io/r/c/vpp/+/44827

No source code from this change is considered incorporated into NGI541 merely
by being referenced in this document. Actual incorporation must be recorded
when it occurs.

## Provenance log

No third-party source code has been imported yet.

Future entries must use the following format.

### YYYY-MM-DD — <component>

**Upstream**
- Project:
- Repository:
- Commit:
- Path:
- License:

**NGI541**
- Destination:
- Import commit:
- Classification: copied / derived / independently implemented

**Copyright notices preserved**
- ...

**Modifications**
- ...

**Notes**
- ...