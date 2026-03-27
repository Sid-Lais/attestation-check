"""NVIDIA RIM (Reference Integrity Manifest) fetching and validation.

NVIDIA publishes signed RIM files for each GPU firmware version via their
attestation service at rim.attestation.nvidia.com. A RIM contains the
expected SHA-384 hash for each firmware component (indexed by SPDM
measurement block index). Comparing evidence measurements against the RIM
detects tampered or unexpected firmware.

Reference: NVIDIA/nvtrust GitHub, DMTF DSP0274 SPDM 1.1 spec.
"""

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET
from typing import Optional

import requests
from cryptography import x509

logger = logging.getLogger(__name__)

# NVIDIA RIM service (Source: NVIDIA/nvtrust, config.py)
NVIDIA_RIM_SERVICE_URL = "https://rim.attestation.nvidia.com/v1/rim/"

# XML namespaces used in NVIDIA's SWID RIM files
_NS_SWID = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
_NS_HASH = "http://www.w3.org/2001/04/xmlenc#sha384"

# OpaqueData field type IDs
_OPAQUE_DRIVER_VERSION = 3
_OPAQUE_VBIOS_VERSION  = 6
_OPAQUE_CHIP_SKU       = 15
_OPAQUE_PROJECT        = 17
_OPAQUE_PROJECT_SKU    = 18


def fetch_rim(
    certs: list[x509.Certificate],
    opaque_fields: dict,
    timeout: int = 30,
) -> Optional[dict]:
    """Fetch the NVIDIA driver RIM for a GPU.

    Constructs the file ID from the driver version in OpaqueData, then
    fetches the SWID XML from NVIDIA's RIM service and parses it into
    a dict mapping measurement index → list of valid reference hashes.

    Args:
        certs: GPU certificate chain [leaf, ..., root] (used to identify chip).
        opaque_fields: Parsed SPDM OpaqueData fields from parse_evidence().
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict mapping measurement index (int) to list of valid hash strings,
        or None if the RIM could not be fetched.
    """
    try:
        file_id = _build_driver_rim_id(certs, opaque_fields)
        url = NVIDIA_RIM_SERVICE_URL + file_id
        logger.info("Fetching NVIDIA RIM: %s", url)

        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        xml_bytes = base64.b64decode(payload["rim"])
        return _parse_rim_xml(xml_bytes)

    except requests.HTTPError as e:
        logger.warning("RIM fetch HTTP error (%s): %s", e.response.status_code if e.response else "?", e)
    except requests.RequestException as e:
        logger.warning("RIM fetch network error: %s", e)
    except (KeyError, Exception) as e:
        logger.warning("RIM fetch/parse error: %s", e)

    return None


def validate_measurements(
    records: list,
    rim: dict,
) -> tuple[bool, list[dict]]:
    """Compare SPDM evidence measurement records against a RIM.

    For each active RIM entry, the evidence hash must match at least one
    of the reference hash alternatives (Hash0..HashN). Index entries with
    all-zero hashes are unmeasured slots and are skipped.

    Args:
        records: Parsed SPDM measurement records from parse_evidence().
        rim: Dict of {index: [hash0, hash1, ...]} from fetch_rim().

    Returns:
        (all_match, mismatches) where mismatches lists any failures.
    """
    # Build a fast lookup from index → evidence hash
    evidence_by_index: dict[int, str] = {}
    for record in records:
        idx = record.get("index")
        h = record.get("hash_value", "")
        if idx is not None and h:
            evidence_by_index[idx] = h.lower()

    mismatches = []
    checked = 0

    for idx, valid_hashes in rim.items():
        # RIM uses 0-based indices; SPDM GET_MEASUREMENTS block indices are 1-based.
        # Map RIM index → evidence index by adding 1.
        spdm_idx = idx + 1
        if spdm_idx not in evidence_by_index:
            continue  # no evidence for this RIM entry — skip

        evidence_hash = evidence_by_index[spdm_idx]

        # Skip unmeasured slots (all zeros in evidence)
        if not evidence_hash or all(c == "0" for c in evidence_hash):
            continue

        checked += 1
        # Accept if evidence matches any valid alternative
        if any(evidence_hash == h.lower() for h in valid_hashes if h):
            pass  # match
        else:
            mismatches.append({
                "index": idx,
                "expected_alternatives": valid_hashes,
                "actual": evidence_hash,
            })

    all_match = checked > 0 and len(mismatches) == 0
    return all_match, mismatches


def fetch_vbios_rim(
    opaque_fields: dict,
    timeout: int = 30,
) -> Optional[dict]:
    """Fetch the NVIDIA VBIOS RIM for a GPU.

    Constructs the VBIOS RIM file ID from OpaqueData fields (project, project_sku,
    chip_sku, vbios_version bytes) and fetches the SWID XML from NVIDIA's RIM service.

    VBIOS RIM ID format: NV_GPU_VBIOS_{PROJECT}_{PROJECT_SKU}_{CHIP_SKU}_{version}
    Example: NV_GPU_VBIOS_G520_0280_895_9600CF0002

    The version string is derived from VBIOS_VERSION bytes (field type 6):
      bytes[3] || "00" || bytes[1] || "00" || bytes[4]
      e.g. 00CF009602000000 → 96 + 00 + CF + 00 + 02 = 9600CF0002

    Args:
        opaque_fields: Parsed SPDM OpaqueData fields from parse_evidence().
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict mapping measurement index (int) to list of valid hash strings,
        or None if the VBIOS RIM could not be fetched.
    """
    try:
        file_id = _build_vbios_rim_id(opaque_fields)
        url = NVIDIA_RIM_SERVICE_URL + file_id
        logger.info("Fetching NVIDIA VBIOS RIM: %s", url)

        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        xml_bytes = base64.b64decode(payload["rim"])
        return _parse_rim_xml(xml_bytes)

    except requests.HTTPError as e:
        logger.warning("VBIOS RIM fetch HTTP error (%s): %s",
                       e.response.status_code if e.response else "?", e)
    except requests.RequestException as e:
        logger.warning("VBIOS RIM fetch network error: %s", e)
    except (KeyError, Exception) as e:
        logger.warning("VBIOS RIM fetch/parse error: %s", e)

    return None


def _build_driver_rim_id(
    certs: list[x509.Certificate],
    opaque_fields: dict,
) -> str:
    """Build the driver RIM file ID string.

    Format: NV_GPU_DRIVER_{CHIP}_{driver_version}
    Example: NV_GPU_DRIVER_GH100_570.172.08
    """
    chip = _detect_chip(certs)
    driver_ver = opaque_fields.get(_OPAQUE_DRIVER_VERSION, "")
    if not driver_ver:
        raise ValueError("Driver version not found in SPDM OpaqueData")
    return f"NV_GPU_DRIVER_{chip}_{driver_ver}"


def _build_vbios_rim_id(opaque_fields: dict) -> str:
    """Build the VBIOS RIM file ID string from OpaqueData fields.

    Format: NV_GPU_VBIOS_{PROJECT}_{PROJECT_SKU}_{CHIP_SKU}_{version}
    The version encodes bytes from VBIOS_VERSION field (type 6):
      bytes[3] || 00 || bytes[1] || 00 || bytes[4]
    e.g. 00CF009602000000 → 9600CF0002
    """
    project     = opaque_fields.get(_OPAQUE_PROJECT, "")
    project_sku = opaque_fields.get(_OPAQUE_PROJECT_SKU, "")
    chip_sku    = opaque_fields.get(_OPAQUE_CHIP_SKU, "")
    vbios_hex   = opaque_fields.get(_OPAQUE_VBIOS_VERSION, "")

    if not all([project, project_sku, chip_sku, vbios_hex]):
        raise ValueError("Missing required OpaqueData fields for VBIOS RIM ID")

    b = bytes.fromhex(vbios_hex)
    if len(b) < 5:
        raise ValueError(f"VBIOS_VERSION too short: {vbios_hex}")

    version = f"{b[3]:02X}00{b[1]:02X}00{b[4]:02X}"
    return f"NV_GPU_VBIOS_{project}_{project_sku}_{chip_sku}_{version}"


def _detect_chip(certs: list[x509.Certificate]) -> str:
    """Extract chip identifier (e.g. GH100) from the cert chain subject."""
    for cert in certs:
        subject = cert.subject.rfc4514_string()
        # Look for patterns like "GH100", "GA100", "GB200" in subject CNs
        for part in subject.split(","):
            for word in part.split():
                if len(word) == 5 and word[:2].isalpha() and word[2:].isdigit():
                    return word.upper()
    return "GH100"  # default to Hopper


def _parse_rim_xml(xml_bytes: bytes) -> dict:
    """Parse a NVIDIA SWID RIM XML into a measurement index → [hashes] map.

    Only active Resource elements (active="True") are included.
    Multiple alternatives are supported (Hash0, Hash1, ..., Hash{N-1}).

    Returns:
        Dict mapping index (int) → list of valid SHA-384 hex strings.
    """
    rim: dict[int, list[str]] = {}

    root = ET.fromstring(xml_bytes)
    resource_tag = f"{{{_NS_SWID}}}Resource"

    for elem in root.iter(resource_tag):
        if elem.get("type") != "Measurement":
            continue
        if elem.get("active") != "True":
            continue

        index_str = elem.get("index")
        if index_str is None:
            continue
        try:
            idx = int(index_str)
        except ValueError:
            continue

        alternatives = int(elem.get("alternatives", "1"))
        hashes = []
        for i in range(alternatives):
            h = elem.get(f"{{{_NS_HASH}}}Hash{i}", "")
            if h:
                hashes.append(h.lower())

        if hashes:
            rim[idx] = hashes

    logger.debug("Parsed RIM: %d active measurement entries", len(rim))
    return rim
