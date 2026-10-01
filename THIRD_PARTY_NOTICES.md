# Third-Party Notices

NGI541 incorporates and uses source code and validation tooling from
third-party open-source projects.

This document records third-party attribution information relevant to the
NGI541 source distribution.

## FD.io VPP

Portions of the NGI541 cryptographic core, native engine, and low-level support
layer are derived from publicly available FD.io VPP source code.

Upstream project:

https://github.com/FDio/vpp

Source repository used for the recorded import:

https://gerrit.fd.io/r/vpp

Recorded upstream baseline:

- Gerrit Change: `44827`
- Patchset: `20`
- Commit: `d7ed54b83682e753e772274409696d8fa8f8108c`
- Parent: `48e1f751ef7726c7358a3315c69bb011a6fda946`

FD.io VPP is distributed under the Apache License, Version 2.0. Some retained
VPPInfra files carry the upstream SPDX expression `Apache-2.0 OR MIT`; those
file-level licensing notices are preserved.

The initial NGI541 source imports preserve applicable upstream copyright,
SPDX, licensing, and attribution notices.

Current VPP-derived files that have subsequently been changed for NGI541 carry
explicit modification or adaptation notices in their source headers.

Detailed source-level provenance, canonical import commits, and
upstream-to-current file mappings are recorded in:

`docs/legal/PROVENANCE.md`

## Intel GHASH material

`src/core/aes/ghash.h` contains GHASH implementation material carrying the
following retained upstream attribution and redistribution terms.

Copyright (c) 2018, Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Intel Corporation nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The original attribution, conditions, disclaimer, references, and authorship
notes remain embedded in `src/core/aes/ghash.h`.

## Cisco libacvp

NGI541 uses Cisco `libacvp` for ACVP/ACVTS validation integration.

Upstream project:

https://github.com/cisco/libacvp

Recorded dependency:

- Git submodule path: `third_party/libacvp`
- Version: `v2.3.1`
- Commit: `91a49ff512d14ffba6cc1ef52d8185c9e1f3735e`
- License: Apache License 2.0

The upstream license is available in the submodule at:

`third_party/libacvp/LICENSE`

`libacvp` is a validation dependency and is not linked into or required by the
NGI541 production cryptographic execution engine.
