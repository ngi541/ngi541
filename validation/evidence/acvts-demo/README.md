# NGI541 ACVTS Demo Evidence Pack

This directory contains sanitized evidence for the NGI541 0.1.0
validation performed against the NIST ACVTS Demo environment.

## Validation identity

- Module: NGI541
- Version: 0.1.0
- Vendor: NGI541 Project
- Website: https://ngi541.org
- Validation ID: A11030
- Validation resource: /acvp/v1/validations/42209
- Non-sample test session: /acvp/v1/testSessions/772630
- Module resource: /acvp/v1/modules/15504
- Operating environment resource: /acvp/v1/oes/34738
- Evidence collected: 2026-09-30T06:54:49+00:00

## Baseline

- Git tag: `v0.1.0`
- NGI541 commit: `be5b8db305b557bbf079dc262e34532dacc00ade`
- libacvp commit: `91a49ff512d14ffba6cc1ef52d8185c9e1f3735e`

## Non-sample ACVTS results

| Algorithm | Revision | vsId | Disposition |
| --- | --- | ---: | --- |
| ACVP-AES-CBC | 1.0 | 4066333 | passed |
| ACVP-AES-CTR | 1.0 | 4066334 | passed |
| ACVP-AES-GCM | 1.0 | 4066335 | passed |
| SHA2-256 | 1.0 | 4066336 | passed |
| SHA2-224 | 1.0 | 4066337 | passed |

The test session was retrieved from the NIST ACVTS Demo server with
`isSample=false`, `passed=true`, and `publishable=true`.

All five vector sets report the `passed` disposition.

## Operating environment

The validation is associated with:

- Intel Core i7-4770HQ @ 2.20 GHz, x86_64
- Apple macOS 12.7.6 / Darwin 21.6.0

The corresponding ACVP Operating Environment resource is:

`/acvp/v1/oes/34738`

## Implementation metadata

- Vendor: NGI541 Project
- Vendor resource: /acvp/v1/vendors/14566
- Contact: Ivan Ivanets
- Contact resource: /acvp/v1/persons/16786
- Module: NGI541 0.1.0
- Module resource: /acvp/v1/modules/15504

## Security and privacy

This evidence pack intentionally excludes:

- ACVTS JWT/access tokens
- TOTP seed and generated TOTP values
- private keys
- client certificate contents
- raw libacvp session state
- ACVTS test vectors
- IUT response vectors
- physical postal address

The module's `addressUrl` metadata reference is retained, but the
postal address itself is not copied into this repository.

## Validation scope

Validation ID `A11030` belongs to the NIST ACVTS Demo
environment.

It is evidence of successful ACVP algorithm validation in the Demo
environment. It must not be represented as a Production CAVP
certificate or as a FIPS 140 validation.

OpenSSL information in `baseline/environment.txt` documents
validation/reference tooling only. NGI541 0.1.0 has no production
OpenSSL runtime dependency.

## NIST references

- ACVP protocol:
  https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html
- CAVP:
  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
