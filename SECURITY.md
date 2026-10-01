# Security Policy

## Project status

NGI541 is currently under active `0.x` development.

The project has not reached a stable production release and has not undergone
an independent security audit.

NGI541 must not currently be treated as production-ready cryptographic
software.

## Reporting a vulnerability

Do not report suspected security vulnerabilities through public GitHub issues,
discussions, or pull requests.

Please report security concerns privately by email:

**contact@ngi541.org**

Use the subject prefix:

`[SECURITY]`

Please include, where possible:

- the affected NGI541 version or commit;
- the affected algorithm or API;
- a technical description of the issue;
- reproduction steps or a minimal reproducer;
- the expected and observed behavior;
- any known security impact.

Do not include real production credentials, private keys, customer data, or
other confidential material unless a secure exchange method has first been
agreed with the project maintainers.

## Disclosure

Security reports will be reviewed privately.

Confirmed vulnerabilities will be handled through a coordinated disclosure
process. Fixes, regression tests, and public advisories will be published when
appropriate after the issue has been analyzed and a remediation is available.

## Supported versions

NGI541 is currently in the `0.x` development series.

Security fixes are expected to target the current development line and, where
appropriate, the most recent published `0.x` release.

Historical validation baselines such as `v0.1.0` remain immutable. A security
fix affecting such a baseline will be released under a subsequent version
rather than by modifying the historical tag.

## Cryptographic assurance

NGI541 uses multiple correctness and robustness mechanisms, including
known-answer testing, differential validation, sanitizer-based testing,
buffer-geometry testing, and ACVP validation.

NGI541 0.1.0 also completed validation in the NIST ACVTS Demo environment under
Validation ID `A11030`.

These activities do not constitute an independent security audit, a Production
CAVP certificate, or a FIPS 140 validation.
