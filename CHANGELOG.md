# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 3 Model Identity Verification**: ECDSA signature recovery from attestation data
  - Recovers Ethereum address from signature
  - Validates signer authority (signature mechanically valid)
  - Returns SKIPPED status awaiting message format specification
  - Ready for deployment once message encoding is documented
- **OCSP Status in CLI Output**: Certificate revocation status now displayed in text format
  - Shows "OCSP Status: Good (X/Y)" when all GPUs pass OCSP in online mode
  - Hidden in offline mode for consistency
  - Already available in JSON output

## [0.1.0] - 2024-12-01

### Added

- Intel TDX DCAP Quote v4 parsing and verification
- NVIDIA GPU attestation certificate chain validation
- NVIDIA GPU SPDM evidence signature verification
- TDX-to-GPU session binding (nonce cross-check)
- OLLM receipt format adapter
- CLI tool: `tee-verify`
- JSON and text output formats
- Offline mode (`--offline`) for air-gapped verification
- Comprehensive test suite with real attestation data
