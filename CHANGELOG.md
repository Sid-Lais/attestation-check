# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-07

### Added

- **Intel TDX Verification**: Full DCAP Quote v4 parsing, ECDSA-P256 signature verification, PCK certificate chain validation against Intel Root CA, and TCB status check via Intel PCS
- **NVIDIA GPU Attestation**: Certificate chain validation (device to NVIDIA Root CA), OCSP revocation checks, SPDM evidence signature verification across multi-GPU clusters
- **NVIDIA Driver RIM Validation**: Firmware integrity verification against NVIDIA's Reference Integrity Manifests
  - Fetches signed driver RIM from `rim.attestation.nvidia.com` using driver version extracted from SPDM OpaqueData
  - Parses SWID XML (ISO 19770-2) with SHA-384 reference hashes and multi-alternative support
  - Validates all active firmware measurement blocks (22 entries for GH100/H100)
  - Hard-fails verification if any measurement hash mismatches (tampered firmware detected)
  - Graceful degradation: skips with warning if RIM service is unreachable or in offline mode
- **NVIDIA VBIOS RIM Validation**: GPU BIOS firmware integrity verification
  - Derives VBIOS RIM ID from OpaqueData fields (project, project SKU, chip SKU, VBIOS version bytes)
  - Validates active BIOS firmware measurement blocks per GPU (10-11 entries)
  - Same index mapping and validation logic as driver RIM
- **SPDM OpaqueData Parsing**: Extracts driver version, VBIOS version, chip SKU, project, and project SKU from SPDM evidence using 2-byte LE TLV format
- **Session Binding**: Cross-checks attestation nonce between TDX quote REPORT_DATA and every GPU evidence blob, proving all attestations were generated in the same TEE session
- **Model Identity Verification**: ECDSA signature verification over `EIP-191(model:sha256(request):sha256(response))`
  - Fast path: reads `request_hash` and `response_hash` from receipt, reconstructs signed message text, verifies in one step
  - Fallback: probes all known Ethereum signing formats (EIP-191 raw, text, keccak256, sha256, raw hash) across TDX quote fields and request/response body variants
  - Returns VERIFIED with detected format name when a match is found
  - Returns SKIPPED when no signature data is available in the receipt
  - CLI flags `--request-body` and `--response-body` for manual body-based probing
- **OLLM Receipt Parser**: Supports both the nested attestation format and the explorer API flat format with automatic detection
- **CLI Tool**: `tee-verify` command with text/JSON output, verbose mode, offline mode, and per-component verification flags
- **OCSP Status in CLI Output**: Certificate revocation status displayed in text and JSON formats
- **Comprehensive Test Suite**: Full test coverage for TDX parsing, NVIDIA verification, session binding, OLLM adapter, and integration tests

## [0.1.0] - 2026-03-23

### Added (initial release)

- Initial release with Intel TDX and NVIDIA GPU attestation verification
- OLLM receipt format adapter
- CLI tool with JSON and text output formats
- Offline mode for air-gapped verification
