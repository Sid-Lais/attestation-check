"""OLLM attestation receipt adapter.

Parses the JSON structure from OLLM's public explorer into
the internal data formats used by tee-verify.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from tee_verify.models import OLLMReceipt

logger = logging.getLogger(__name__)


def from_file(path: str | Path) -> OLLMReceipt:
    """Load an OLLM attestation receipt from a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        Parsed OLLMReceipt.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON is invalid or missing required fields.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Receipt file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return from_dict(data)


def from_dict(data: Dict[str, Any]) -> OLLMReceipt:
    """Parse an OLLM receipt from a dictionary.

    Supports multiple JSON structures:
    - Direct field mapping
    - Nested under "attestation" key
    - OLLM explorer API response format

    Args:
        data: Dictionary with attestation data.

    Returns:
        Parsed OLLMReceipt.

    Raises:
        ValueError: If required fields are missing.
    """
    # Handle nested structures
    attestation = data.get("attestation", data)
    if isinstance(attestation, str):
        attestation = json.loads(attestation)

    receipt = OLLMReceipt()

    # Request ID
    receipt.request_id = data.get("request_id", data.get("requestId", ""))

    # TDX Quote
    tdx_data = attestation.get("tdx", attestation.get("intel_tdx", attestation))
    receipt.tdx_quote_hex = _extract_tdx_quote(tdx_data)

    # NVIDIA data
    nvidia_data = attestation.get("nvidia", attestation.get("nvidia_gpu", {}))
    receipt.nvidia_nonce = nvidia_data.get("nonce", "")
    receipt.nvidia_architecture = nvidia_data.get("architecture", "HOPPER")

    # GPU certificates and evidence
    gpus = nvidia_data.get("gpus", nvidia_data.get("gpu_data", []))
    if isinstance(gpus, list):
        for gpu in gpus:
            cert = gpu.get("certificate", gpu.get("cert", ""))
            evidence = gpu.get("evidence", gpu.get("attestation_report", ""))
            receipt.gpu_certificates.append(cert)
            receipt.gpu_evidences.append(evidence)

    # Message signature
    sig_data = attestation.get("message_signature", attestation.get("signature", {}))
    if isinstance(sig_data, dict):
        receipt.ecdsa_signature = sig_data.get(
            "ecdsa_signature", sig_data.get("signature", "")
        )
        receipt.message_signer = sig_data.get(
            "message_signer", sig_data.get("signer", "")
        )
        receipt.model_signing_address = sig_data.get(
            "model_signing_address", sig_data.get("signing_address", "")
        )

    return receipt


def from_request_id(request_id: str) -> OLLMReceipt:
    """Fetch an OLLM receipt by request ID.

    Note: The OLLM explorer is a React SPA, so direct HTTP fetch
    won't return the attestation data. Use `from_file` with a
    saved JSON export instead.

    Args:
        request_id: The OLLM request ID (e.g., "chatcmpl-8570e42b12e990bd").

    Raises:
        NotImplementedError: Direct API fetch is not supported yet.
    """
    raise NotImplementedError(
        f"Direct fetch for request '{request_id}' is not supported. "
        "The OLLM explorer is a React SPA. Please save the attestation "
        "JSON to a file and use 'tee-verify --ollm-json <file>' instead. "
        f"URL: https://console.ollm.com/explorer/request/{request_id}"
    )


def _extract_tdx_quote(tdx_data: dict) -> str:
    """Extract the TDX quote hex string from various field names."""
    if isinstance(tdx_data, str):
        return tdx_data

    for key in ["quote", "tdx_quote", "quote_hex", "raw_quote", "intel_tdx_quote"]:
        if key in tdx_data:
            val = tdx_data[key]
            if isinstance(val, str):
                return val.strip()

    return ""
