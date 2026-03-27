# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 2 NVIDIA RIM Validation**: GPU firmware integrity verification against NVIDIA's Reference Integrity Manifests
  - Fetches signed driver RIM from `rim.attestation.nvidia.com` using driver version extracted from SPDM OpaqueData
  - Parses SWID XML (ISO 19770-2) with SHA-384 reference hashes and multi-alternative support
  - Validates all active firmware measurement blocks (22 entries for GH100/H100 driver 570.x)
  - Correctly maps 1-based SPDM block indices to 0-based RIM indices
  - Hard-fails verification if any measurement hash mismatches (tampered firmware detected)
  - Graceful degradation: skips with warning if RIM service is unreachable or in offline mode
  - Verified against real production data: 8× NVIDIA H100, driver 570.172.08, 22/22 measurements matched
- **Phase 2b NVIDIA VBIOS RIM Validation**: GPU BIOS firmware integrity verification
  - Derives VBIOS RIM ID from OpaqueData fields (project, project SKU, chip SKU, VBIOS version bytes)
  - Version byte encoding: `bytes[3] || 00 || bytes[1] || 00 || bytes[4]` (e.g. `9600CF0002`)
  - Validates 11 active BIOS firmware measurement blocks per GPU
  - Same index mapping and validation logic as driver RIM
  - Verified against real production data: 8× NVIDIA H100, 11/11 measurements matched
- **SPDM OpaqueData Parsing**: Extracts driver version, VBIOS version, chip SKU, project, and project SKU from SPDM evidence
- **Phase 3 Model Identity Verification**: Self-discovering ECDSA signature verification
  - Probes 21 Ethereum signing formats (EIP-191 raw, text, keccak256, sha256, raw hash) across TDX quote, model signing address, nonce, and their combinations
  - Returns VERIFIED with detected format name when a match is found
  - Returns SKIPPED with formats-tried count when no format matches (unknown format, not a broken signature)
  - No external dependencies — fully self-contained format discovery
- **OCSP Status in CLI Output**: Certificate revocation status now displayed in text format
  - Shows "OCSP Status: Good (X/Y)" when all GPUs pass OCSP in online mode
  - Hidden in offline mode for consistency
  - Already available in JSON output

## [0.1.0] - 2026-03-23

### Added (0.1.0)

- Intel TDX DCAP Quote v4 parsing and verification
- NVIDIA GPU attestation certificate chain validation
- NVIDIA GPU SPDM evidence signature verification
- TDX-to-GPU session binding (nonce cross-check)
- OLLM receipt format adapter
- CLI tool: `tee-verify`
- JSON and text output formats
- Offline mode (`--offline`) for air-gapped verification
- Comprehensive test suite with real attestation data
