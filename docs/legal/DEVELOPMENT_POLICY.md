# NGI541 Development Policy

## Purpose

This policy defines the development and source-provenance rules for NGI541.

Its purpose is to maintain a clear separation between NGI541 development and
any confidential, proprietary, employer-owned, customer-owned, or otherwise
restricted material.

## 1. Independent development environment

NGI541 development must be performed using independently controlled development
resources.

The project must not depend on access to any employer or customer internal
infrastructure.

Project development should use:

- personal development equipment;
- personal source-control accounts;
- personal authentication credentials;
- publicly available documentation;
- publicly available source code;
- publicly available standards and specifications.

## 2. Prohibited sources

The following material must not be copied, imported, reproduced, summarized
into source code, or otherwise incorporated into NGI541 unless it has been
separately made publicly available under terms compatible with NGI541:

- confidential source code;
- private repositories or branches;
- unpublished patches;
- internal design documents;
- internal issue trackers;
- internal email or messaging discussions;
- non-public benchmark data;
- non-public profiling data;
- customer information;
- proprietary test infrastructure;
- unpublished product roadmaps;
- credentials, secrets, tokens, certificates, or keys;
- third-party confidential information.

If the provenance or permission status of material is uncertain, it must not be
incorporated until its status has been resolved.

## 3. Public upstream material

Publicly available open-source material may be incorporated only after its
license has been verified.

For every source import:

1. identify the exact upstream repository;
2. record the exact commit SHA;
3. verify the applicable license;
4. preserve required copyright and attribution notices;
5. identify files modified by NGI541;
6. record the import in `PROVENANCE.md`;
7. record any applicable third-party notices.

## 4. Apache-2.0 derived files

When a file is derived from an Apache-2.0 licensed upstream file:

- its applicable license must remain Apache-2.0 compatible;
- existing relevant copyright, patent, trademark, and attribution notices must
  be preserved;
- the file must clearly indicate that it has been modified where required;
- the upstream origin must be traceable through project provenance records.

NGI541 must not imply ownership of upstream copyrights.

## 5. Original NGI541 source

Files written independently for NGI541 should use the SPDX identifier:

    SPDX-License-Identifier: Apache-2.0

Copyright notices may be added where appropriate.

## 6. Source-code provenance

Code must fall into one of the following provenance categories:

### Original

Written independently for NGI541 without copying third-party implementation
code.

### Derived

Based materially on identified publicly available third-party source code.

### Imported

Copied substantially from identified publicly available third-party source
code.

The applicable category must be recorded whenever third-party code is involved.

## 7. Performance data

Performance claims published by NGI541 must be based on independently
reproducible measurements generated using NGI541-controlled or publicly
available infrastructure.

Non-public employer, customer, or third-party performance results must not be
used.

Benchmark methodology should record:

- processor model;
- microarchitecture;
- compiler and version;
- compiler options;
- operating system;
- kernel version;
- CPU frequency policy;
- NUMA configuration where relevant;
- buffer sizes;
- batch size;
- number of cores/threads;
- exact source revisions.

## 8. Contributions

Contributors must have the legal right to submit their contribution.

Contributions must not contain confidential or proprietary information.

Unless explicitly stated otherwise, contributions submitted to NGI541 are
provided under the Apache License 2.0.

NGI541 uses Developer Certificate of Origin sign-off to document contributor
provenance.

## 9. Security-sensitive material

Real production secrets, private keys, credentials, access tokens, customer
data, or confidential cryptographic material must never be committed.

Cryptographic keys included in tests must be clearly identified as public test
vectors or generated test data and must never represent production secrets.

## 10. Uncertain provenance

When there is uncertainty concerning licensing, ownership, confidentiality,
patent provenance, or the right to incorporate material:

**do not commit the material.**

Resolve the provenance issue first and document the result.