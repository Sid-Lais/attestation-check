"""Intel Provisioning Certification Service (PCS) API client."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography import x509

logger = logging.getLogger(__name__)

PCS_BASE_URL = "https://api.trustedservices.intel.com"
TCB_INFO_URL = f"{PCS_BASE_URL}/tdx/certification/v4/tcb"
CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

# Intel SGX PCK extension OIDs
_FMSPC_OID = x509.ObjectIdentifier("1.2.840.113741.1.13.1.4")
_SGX_EXTENSIONS_OID = x509.ObjectIdentifier("1.2.840.113741.1.13.1")


def extract_fmspc(pck_cert: x509.Certificate) -> str:
    """Extract the FMSPC value from a PCK certificate's SGX extensions.

    The FMSPC is a 6-byte value in OID 1.2.840.113741.1.13.1.4 within the
    SGX-specific certificate extension.

    Args:
        pck_cert: The parsed PCK certificate.

    Returns:
        FMSPC as a lowercase hex string.

    Raises:
        ValueError: If FMSPC cannot be extracted.
    """
    try:
        sgx_ext = pck_cert.extensions.get_extension_for_oid(_SGX_EXTENSIONS_OID)
        # The SGX extensions value is ASN.1 encoded - parse the raw bytes
        ext_value = sgx_ext.value.value
        fmspc = _parse_fmspc_from_sgx_extension(ext_value)
        if fmspc:
            return fmspc
    except x509.ExtensionNotFound:
        pass

    # Fallback: scan all extensions for the FMSPC OID
    for ext in pck_cert.extensions:
        raw = ext.value.value if hasattr(ext.value, "value") else b""
        fmspc = _parse_fmspc_from_sgx_extension(raw)
        if fmspc:
            return fmspc

    raise ValueError("FMSPC not found in PCK certificate extensions")


def _parse_fmspc_from_sgx_extension(data: bytes) -> Optional[str]:
    """Parse FMSPC from ASN.1-encoded SGX extension data.

    The SGX extension is a SEQUENCE of SEQUENCE items, each containing
    an OID and a value. We search for the FMSPC OID.

    OID 1.2.840.113741.1.13.1.4 DER encoding:
      06 0A 2A 86 48 86 F8 4D 01 0D 01 04
      - 2A       = 1.2 (first two arcs)
      - 86 48    = 840
      - 86 F8 4D = 113741 (base-128: 6*128^2 + 120*128 + 77)
      - 01 0D 01 = 1.13.1
      - 04       = .4
    """
    fmspc_oid_bytes = bytes([
        0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04
    ])
    idx = data.find(fmspc_oid_bytes)
    if idx == -1:
        return None

    # After the OID, expect an OCTET STRING tag (0x04) with the FMSPC value
    pos = idx + len(fmspc_oid_bytes)
    if pos >= len(data):
        return None

    # Skip tag and length bytes for OCTET STRING
    if data[pos] == 0x04:
        pos += 1
        length = data[pos]
        pos += 1
        fmspc_bytes = data[pos : pos + length]
        if len(fmspc_bytes) >= 6:
            return fmspc_bytes[:6].hex()

    return None


def fetch_tcb_info(fmspc: str, timeout: int = 30) -> Tuple[Dict[str, Any], str]:
    """Fetch TDX TCB info from Intel PCS API.

    Args:
        fmspc: FMSPC hex string extracted from the PCK certificate.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (tcb_info_dict, issuer_chain_header).

    Raises:
        requests.RequestException: On network errors.
        ValueError: On unexpected API response.
    """
    url = f"{TCB_INFO_URL}?fmspc={fmspc}"
    logger.info("Fetching TDX TCB info for FMSPC=%s", fmspc)

    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()

    tcb_info = resp.json()
    issuer_chain = resp.headers.get("TCB-Info-Issuer-Chain", "")

    return tcb_info, issuer_chain


def fetch_crl(timeout: int = 30) -> bytes:
    """Fetch the Intel SGX Root CA CRL.

    Returns:
        DER-encoded CRL bytes.
    """
    resp = requests.get(CRL_URL, timeout=timeout)
    resp.raise_for_status()
    return resp.content


def get_tcb_status(tcb_info: Dict[str, Any], tee_tcb_svn: str) -> str:
    """Determine the TCB status for a given TEE TCB SVN.

    Args:
        tcb_info: TCB info response from Intel PCS API.
        tee_tcb_svn: TEE TCB SVN hex string from the quote.

    Returns:
        TCB status string (e.g., "UpToDate", "OutOfDate", "Revoked").
    """
    tcb_levels = tcb_info.get("tcbInfo", {}).get("tcbLevels", [])
    svn_bytes = bytes.fromhex(tee_tcb_svn)

    for level in tcb_levels:
        tdx_components = level.get("tcb", {}).get("tdxtcbcomponents", [])
        if not tdx_components:
            sgx_components = level.get("tcb", {}).get("sgxtcbcomponents", [])
            tdx_components = sgx_components

        if _svn_meets_level(svn_bytes, tdx_components):
            return level.get("tcbStatus", "Unknown")

    return "Unknown"


def _svn_meets_level(svn_bytes: bytes, components: list) -> bool:
    """Check if the SVN bytes meet or exceed a TCB level's component values."""
    for i, component in enumerate(components):
        if i >= len(svn_bytes):
            break
        svn_val = component.get("svn", 0)
        if svn_bytes[i] < svn_val:
            return False
    return True
