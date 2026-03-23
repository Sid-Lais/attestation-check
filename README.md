# tee-verify

[![PyPI version](https://img.shields.io/pypi/v/tee-verify.svg)](https://pypi.org/project/tee-verify/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/Sid-Lais/attestation-check/blob/main/LICENSE)
[![CI](https://github.com/Sid-Lais/attestation-check/actions/workflows/ci.yml/badge.svg)](https://github.com/Sid-Lais/attestation-check/actions/workflows/ci.yml)

**Independent verification of TEE attestation receipts. No trust required.**

## The Problem

Every AI platform asks you to trust that their infrastructure is secure. But trust is not verification. If an AI provider runs models inside a Trusted Execution Environment and gives you a cryptographic attestation receipt, you should be able to verify it yourself — without relying on the provider's own tools.

## Quick Start

```bash
pip install tee-verify
```

```bash
# Verify an OLLM attestation receipt
tee-verify --ollm-json receipt.json

# Verify with JSON output
tee-verify --ollm-json receipt.json --output json

# Verify in offline mode (skip Intel PCS + NVIDIA OCSP)
tee-verify --ollm-json receipt.json --offline

# Verify individual components
tee-verify --tdx-quote quote.hex
tee-verify --tdx-quote quote.hex --nvidia-cert cert.b64 --nvidia-evidence ev.b64
```

## What It Verifies

- **Intel TDX** — Parses the TDX DCAP Quote v4, verifies the ECDSA-P256 signature, validates the PCK certificate chain against Intel's Root CA, and checks TCB status via Intel's Provisioning Certification Service.
- **NVIDIA GPU Attestation** — Validates the GPU certificate chain (device to NVIDIA Root CA), checks revocation via OCSP, and verifies the SPDM evidence signature using the device certificate.
- **Session Binding** — Cross-checks the attestation nonce between the TDX quote and every GPU evidence blob, proving they belong to the same TEE session.
- **Model Identity (Phase 3)** — Recovers the Ethereum address from the attestation signature and compares it against the declared model signer, verifying that the correct signing authority attested to this execution.

## What It Does NOT Verify (Yet)

- **RIM Measurement Validation** — Comparing GPU firmware measurements against NVIDIA's signed Reference Integrity Manifests (RIMs) is planned for Phase 2.
- **AMD SEV-SNP** — Support for AMD's confidential computing platform is on the roadmap.

## How It Works

A TEE attestation receipt contains two independent proofs:

1. The **Intel TDX quote** proves the CPU is running inside a genuine Trust Domain with a specific software measurement (MRTD). The quote is signed by Intel's Quoting Enclave using a Platform Certification Key traceable to Intel's root of trust.

2. The **NVIDIA GPU evidence** proves each GPU in the cluster is a genuine NVIDIA device running verified firmware. Each GPU produces an SPDM measurement report signed by its device-specific attestation key, with a certificate chain rooted in NVIDIA's PKI.

The receipts are cryptographically bound together by a shared nonce: the GPU attestation nonce must appear in the TDX quote's REPORT_DATA field, proving both attestations were generated in the same session.

`tee-verify` checks all of this independently — no vendor SDKs, no trust assumptions.

## Using as a Library

```python
from tee_verify.formats.ollm import from_file
from tee_verify.verifier import verify_from_receipt

# Load and verify an OLLM receipt
receipt = from_file("receipt.json")
result = verify_from_receipt(receipt, offline=False)

print(result.overall_status)        # "VERIFIED"
print(result.tdx.mrtd)              # TD measurement hash
print(result.tdx.nonce)             # Session nonce
print(result.nonce_binding_valid)   # True
print(len(result.nvidia_gpus))      # 8
print(result.model_identity.status) # "VERIFIED" or "SKIPPED"

# Get structured output
print(result.to_json())

# Or verify individual components
from tee_verify.tdx.verifier import verify_tdx_quote

tdx_result = verify_tdx_quote(quote_hex, offline=True)
print(tdx_result.status)  # "VERIFIED"
```

## CLI Reference

```
Usage: tee-verify [OPTIONS] [INPUT_PATH]

  Independently verify TEE attestation receipts. No trust required.

Options:
  --tdx-quote PATH             Path to TDX quote hex file
  --nvidia-cert PATH           Path to NVIDIA cert chain (base64)
  --nvidia-evidence PATH       Path to NVIDIA evidence (base64)
  --ollm-json PATH             Path to OLLM explorer JSON file
  --output [text|json]         Output format (default: text)
  --offline                    Skip online checks (Intel PCS, NVIDIA OCSP)
  --verbose                    Show detailed output
  --version                    Show version
  --help                       Show this message and exit
```

## Running Tests

```bash
git clone https://github.com/orgn/tee-verify.git
cd tee-verify
pip install -e ".[dev]"
pytest tests/ -v
```

## Background: What Is TEE Attestation?

A Trusted Execution Environment (TEE) is a hardware-enforced isolated execution context. Intel TDX creates Trust Domains — encrypted virtual machines where not even the hypervisor can read the memory. NVIDIA's Hopper GPUs extend this trust boundary to the GPU, enabling confidential AI inference where the model weights and user prompts are never exposed to the host.

Attestation is the cryptographic proof that a TEE is genuine and running expected software. The hardware generates a signed report (a "quote" in Intel terminology) containing measurements of the loaded software. Anyone can verify this signature against the hardware vendor's root of trust to confirm: this code is really running on that hardware, and no one — not even the cloud provider — can tamper with it.

## Roadmap

- **Phase 1** ✅ Complete: Hardware authenticity, certificate validation, session binding
- **Phase 2**: NVIDIA RIM measurement validation (firmware integrity verification)
- **Phase 3** ✅ In Progress: Model identity verification via signature recovery (signature recoverable, awaiting message format specification)
- **Phase 4**: AMD SEV-SNP attestation support
- **Phase 5**: TypeScript/browser port for client-side verification
- **Phase 6**: Ethereum on-chain receipt anchoring

## Built by ORGN

tee-verify is built and maintained by [ORGN](https://orgn.com), a secure AI development environment for regulated industries. ORGN's backend gateway [OLLM](https://ollm.com) runs AI models inside TEEs and produces the attestation receipts this tool verifies.

If you want an IDE where all of this is automatic — [orgn.com](https://orgn.com)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
