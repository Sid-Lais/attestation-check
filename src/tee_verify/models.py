"""Data models for TEE attestation verification results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class TDXQuote:
    """Parsed Intel TDX DCAP Quote v4."""

    version: int
    attest_key_type: int
    tee_type: int
    qe_vendor_id: str
    tee_tcb_svn: str
    mrseam: str
    mrsignerseam: str
    seam_attributes: str
    td_attributes: str
    xfam: str
    mrtd: str
    mrconfigid: str
    mrowner: str
    mrownerconfig: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    report_data: str
    signature: bytes
    attest_pub_key: bytes
    pck_cert_chain: List[bytes]
    raw_header: bytes
    raw_td_body: bytes


@dataclass
class TDXVerificationResult:
    """Result of Intel TDX quote verification."""

    status: str  # "VERIFIED" | "FAILED" | "TCB_OUT_OF_DATE"
    mrtd: str = ""
    rtmr: List[str] = field(default_factory=list)
    report_data: str = ""
    nonce: str = ""
    tcb_status: str = ""
    error: Optional[str] = None


@dataclass
class NvidiaGPUVerificationResult:
    """Result of a single NVIDIA GPU attestation verification."""

    status: str  # "VERIFIED" | "FAILED"
    gpu_index: int = 0
    architecture: str = ""
    cert_chain_valid: bool = False
    ocsp_status: str = ""
    evidence_signature_valid: bool = False
    nonce: str = ""
    measurement_count: int = 0
    error: Optional[str] = None


@dataclass
class NvidiaEvidence:
    """Parsed NVIDIA SPDM measurement evidence."""

    records: list = field(default_factory=list)
    nonce: str = ""
    signature: bytes = b""
    raw_signed_data: bytes = b""


@dataclass
class CompositeVerificationResult:
    """Combined verification result across all TEE components."""

    overall_status: str  # "VERIFIED" | "FAILED"
    tdx: Optional[TDXVerificationResult] = None
    nvidia_gpus: List[NvidiaGPUVerificationResult] = field(default_factory=list)
    nonce_binding_valid: bool = False
    verified_at: str = ""

    def __post_init__(self):
        if not self.verified_at:
            self.verified_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        d = self.to_dict()
        # Remove binary fields that aren't JSON-serializable
        return json.dumps(d, indent=2, default=str)


@dataclass
class OLLMReceipt:
    """Parsed OLLM attestation receipt."""

    request_id: str = ""
    tdx_quote_hex: str = ""
    nvidia_nonce: str = ""
    nvidia_architecture: str = ""
    gpu_certificates: List[str] = field(default_factory=list)  # base64 strings
    gpu_evidences: List[str] = field(default_factory=list)  # base64 strings
    ecdsa_signature: str = ""
    message_signer: str = ""
    model_signing_address: str = ""
