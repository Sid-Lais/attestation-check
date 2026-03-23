"""NVIDIA GPU attestation certificate and SPDM evidence parser."""

from __future__ import annotations

import base64
import logging
import struct
from typing import List, Tuple

from cryptography import x509

from tee_verify.models import NvidiaEvidence

logger = logging.getLogger(__name__)

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"

# SPDM 1.1 message types
_SPDM_VERSION_11 = 0x11
_SPDM_MEASUREMENTS_RESPONSE = 0x60

# ECDSA-P384 signature size
_ECDSA_P384_SIG_SIZE = 96

# SPDM nonce size
_SPDM_NONCE_SIZE = 32


def parse_cert_chain(cert_data: str | bytes) -> List[x509.Certificate]:
    """Parse an NVIDIA GPU certificate chain from base64 or raw PEM data.

    Args:
        cert_data: Base64-encoded string containing concatenated PEM certificates,
                   or raw bytes of the concatenated PEMs.

    Returns:
        List of x509.Certificate objects ordered as:
        [device_cert, intermediate1, intermediate2, nvidia_root]

    Raises:
        ValueError: If no certificates could be parsed.
    """
    if isinstance(cert_data, str):
        try:
            raw = base64.b64decode(cert_data)
        except Exception:
            raw = cert_data.encode("utf-8")
    else:
        raw = cert_data

    certs = []
    search_start = 0
    while True:
        begin_idx = raw.find(_PEM_BEGIN, search_start)
        if begin_idx == -1:
            break
        end_idx = raw.find(_PEM_END, begin_idx)
        if end_idx == -1:
            break
        end_idx += len(_PEM_END)
        # Include trailing newline
        if end_idx < len(raw) and raw[end_idx : end_idx + 1] == b"\n":
            end_idx += 1

        pem_block = raw[begin_idx:end_idx]
        try:
            cert = x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
        except Exception as e:
            logger.warning("Failed to parse certificate: %s", e)
        search_start = end_idx

    if not certs:
        raise ValueError("No valid certificates found in chain data")

    return certs


def parse_evidence(evidence_data: str | bytes) -> NvidiaEvidence:
    """Parse NVIDIA SPDM 1.1 measurement evidence.

    The evidence blob structure varies by size:
    - Small blobs (< 128 bytes): SPDM header with embedded nonce
    - Large blobs: Full SPDM MEASUREMENTS response with records + nonce + signature

    The SPDM header format:
    - Byte 0: SPDM version (0x11 = SPDM 1.1)
    - Byte 1: Request/response code (0xe0 = MEASUREMENTS response)
    - Byte 2: Param1 (flags)
    - Byte 3+: Nonce (32 bytes) followed by measurement data

    Args:
        evidence_data: Base64-encoded string or raw bytes of the SPDM evidence.

    Returns:
        NvidiaEvidence with parsed measurement records, nonce, and signature.

    Raises:
        ValueError: If the evidence format is invalid.
    """
    if isinstance(evidence_data, str):
        try:
            raw = base64.b64decode(evidence_data)
        except Exception:
            raise ValueError("Invalid base64 evidence data")
    else:
        raw = evidence_data

    if len(raw) < 4:
        raise ValueError(f"Evidence data too short: {len(raw)} bytes")

    records = []
    nonce = ""
    signature = b""
    raw_signed_data = b""

    if len(raw) > _ECDSA_P384_SIG_SIZE + _SPDM_NONCE_SIZE + 10:
        # Large evidence blob: nonce before signature at the end
        signature = raw[-_ECDSA_P384_SIG_SIZE:]
        nonce_bytes = raw[-(_ECDSA_P384_SIG_SIZE + _SPDM_NONCE_SIZE) : -_ECDSA_P384_SIG_SIZE]
        nonce = nonce_bytes.hex()
        raw_signed_data = raw[:-_ECDSA_P384_SIG_SIZE]
        records = _parse_measurement_records(
            raw, len(raw) - _ECDSA_P384_SIG_SIZE - _SPDM_NONCE_SIZE
        )
    else:
        # Small evidence blob: SPDM header with nonce embedded after header bytes
        # Try to find the nonce at a known offset
        nonce = _extract_nonce_from_header(raw)
        raw_signed_data = raw

    return NvidiaEvidence(
        records=records,
        nonce=nonce,
        signature=signature,
        raw_signed_data=raw_signed_data,
    )


def _extract_nonce_from_header(raw: bytes) -> str:
    """Extract the nonce from an SPDM evidence header.

    The nonce appears after a short header. We try multiple known offsets.
    """
    # Common header layouts: nonce at byte 4 (version + code + param1 + param2)
    for offset in [4, 3, 2]:
        if offset + _SPDM_NONCE_SIZE <= len(raw):
            candidate = raw[offset : offset + _SPDM_NONCE_SIZE]
            # Check if it looks like a valid nonce (not all zeros)
            if candidate != b"\x00" * _SPDM_NONCE_SIZE:
                return candidate.hex()

    # Fallback: last 32 bytes
    if len(raw) >= _SPDM_NONCE_SIZE:
        return raw[-_SPDM_NONCE_SIZE:].hex()
    return raw.hex()


def _parse_measurement_records(data: bytes, end_offset: int) -> list:
    """Parse SPDM measurement records from the evidence body.

    Each measurement record follows a TLV-like structure with:
    - index (1 byte)
    - measurement_spec (1 byte)
    - measurement_size (2 bytes LE)
    - measurement_data (variable)
    """
    records = []
    # Skip the SPDM header (variable length, typically 4-8 bytes)
    # Look for the measurement block after the header
    pos = _find_measurement_start(data)
    if pos < 0:
        return records

    record_count = 0
    while pos < end_offset and pos < len(data) - 4 and record_count < 128:
        try:
            index = data[pos]
            spec = data[pos + 1]
            meas_size = struct.unpack_from("<H", data, pos + 2)[0]
            pos += 4

            if meas_size == 0 or pos + meas_size > len(data):
                break

            meas_data = data[pos : pos + meas_size]
            pos += meas_size

            record = {
                "index": index,
                "measurement_spec": spec,
                "size": meas_size,
                "data": meas_data.hex(),
            }

            # Try to parse DMTF measurement format within the data
            if meas_size >= 5:
                dmtf_usage = meas_data[0]
                hash_alg = struct.unpack_from("<H", meas_data, 1)[0]
                hash_size = struct.unpack_from("<H", meas_data, 3)[0]
                if 5 + hash_size <= meas_size:
                    hash_value = meas_data[5 : 5 + hash_size]
                    record["dmtf_usage"] = dmtf_usage
                    record["hash_alg"] = hash_alg
                    record["hash_size"] = hash_size
                    record["hash_value"] = hash_value.hex()

            records.append(record)
            record_count += 1
        except (struct.error, IndexError):
            break

    return records


def _find_measurement_start(data: bytes) -> int:
    """Find the start of measurement records in SPDM data.

    The SPDM MEASUREMENTS response has a header, then a number-of-blocks
    field, followed by a measurement record length field.
    """
    if len(data) < 8:
        return -1

    # SPDM 1.1 MEASUREMENTS response format:
    # Byte 0: SPDM version (0x11)
    # Byte 1: Request response code (0x60)
    # Various header fields...
    # The measurement records start after the header

    # Try known header sizes
    for header_size in [8, 12, 16, 4]:
        if header_size < len(data):
            # Check if data at this offset looks like a measurement record
            candidate = data[header_size]
            if 0 < candidate < 128:  # reasonable index
                return header_size

    return 4  # default fallback
