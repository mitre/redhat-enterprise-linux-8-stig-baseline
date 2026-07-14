# Changelog

All notable changes to the Red Hat Enterprise Linux 8 STIG InSpec profile are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), mirroring the DISA STIG Benchmark Version and
Release: a benchmark `V{x}R{y}` maps to profile version `{x}.{y}.{z}`, where `{z}` is the profile patch level.

## [2.7.0] - 2026-06-30

Uplift from DISA RHEL 8 STIG **V2R2** to **V2R7** (Benchmark Date: 01 Apr 2026). Profile now covers 366
controls (was 367).

### Added

- Nine controls introduced across benchmark releases V2R3–V2R7, principally the crypto-policies / FIPS 140-3
  consolidation that replaces several removed SSH/TLS controls:
  - `SV-279933` (RHEL-08-010015) — crypto-policies package must be installed.
  - `SV-279932` (RHEL-08-010270) — system-wide crypto policy must not be overridden.
  - `SV-279931` (RHEL-08-010275) — bind package must use a DOD-approved encryption policy.
  - `SV-279930` (RHEL-08-010280) — IP tunnels must use FIPS 140-3 algorithms.
  - `SV-279929` (RHEL-08-020360) — interactive shell must auto-exit after 10 minutes of inactivity (TMOUT).
  - `SV-274877` (RHEL-08-030655) — audit scripts/executables invoked by cron must run as root.
  - `SV-272484` — SELinux context must be elevated on `sudo`.
  - `SV-272483` (RHEL-08-010297) — SSH client ciphers must use FIPS 140-3 algorithms.
  - `SV-272482` (RHEL-08-010296) — SSH client MACs must use FIPS 140-3 algorithms.

### Changed

- 96 controls reconciled to V2R7: updated STIG metadata (title, description, check, fix), rule and fix IDs,
  CCI/NIST references and severity, plus check logic where the V2R7 check intent changed (e.g. drop-in /
  `sysctl` scope changes, single-command check rewrites, and severity reclassifications).
- `SV-230352` (RHEL-08-020060) — GNOME idle-delay check now also flags a value of `0` (never lock), not only
  values greater than 900.
- Severity reclassifications per V2R7: `SV-230251`/`SV-230252` → CAT I; `SV-230492` → CAT II.

### Removed

- Ten controls removed across V2R3–V2R7 (crypto-policies consolidation and de-duplication):
  `SV-230254`, `SV-230255`, `SV-230256`, `SV-244526`, `SV-255924`, `SV-230309`, `SV-230381`, `SV-230331`,
  `SV-251714`, `SV-251715`.

### Fixed

- Container applicability of the new SSH-client crypto controls `SV-272482` and `SV-272483`: both are now
  host-only and are correctly marked Not Applicable inside a container (matching the server-side analog
  `SV-230251`), preventing false findings when scanning container images.
