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

# SPDM 1.1 message codes
_SPDM_VERSION_11 = 0x11
_SPDM_GET_MEASUREMENTS_CODE = 0xE0   # request
_SPDM_MEASUREMENTS_CODE = 0x60       # response

# GET_MEASUREMENTS request size: 4-byte header + 32-byte nonce + 1-byte SlotID
_GET_MEASUREMENTS_REQ_SIZE = 37

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

    NVIDIA's evidence blob is a concatenation of:
      1. GET_MEASUREMENTS request  (37 bytes):
           [0]   SPDM version  (0x11)
           [1]   Code          (0xE0 = GET_MEASUREMENTS)
           [2]   Param1        (0x01 = signature requested)
           [3]   Param2        (0xFF = all measurements)
           [4:36] Nonce        (32 bytes, same nonce as in the response)
           [36]  SlotID        (1 byte)
      2. MEASUREMENTS response (remainder):
           [0]   SPDM version  (0x11)
           [1]   Code          (0x60 = MEASUREMENTS)
           [2]   Param1
           [3]   Param2
           [4]   NumberOfBlocks (1 byte)
           [5:8]  MeasurementRecordLength (3 bytes LE)
           [8:8+MRL] MeasurementRecord
           [+32] Nonce (32 bytes — same as in request)
           [+2]  OpaqueDataLength (2 bytes LE)
           [+N]  OpaqueData
           [-96] Signature (96 bytes ECDSA-P384)

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

    # Detect concatenated GET_MEASUREMENTS request + MEASUREMENTS response format
    if (
        len(raw) > _GET_MEASUREMENTS_REQ_SIZE + 8
        and raw[1] == _SPDM_GET_MEASUREMENTS_CODE
    ):
        return _parse_request_response_blob(raw)

    # Legacy: pure MEASUREMENTS response blob (no request prefix)
    return _parse_response_only_blob(raw)


def _parse_request_response_blob(raw: bytes) -> NvidiaEvidence:
    """Parse evidence that starts with a GET_MEASUREMENTS request prefix."""
    # Nonce is embedded in the request at offset 4
    nonce_bytes = raw[4 : 4 + _SPDM_NONCE_SIZE]
    nonce = nonce_bytes.hex()

    # Signature is always the last 96 bytes of the full blob
    signature = raw[-_ECDSA_P384_SIG_SIZE:]
    raw_signed_data = raw[:-_ECDSA_P384_SIG_SIZE]

    # MEASUREMENTS response starts after the request prefix
    resp = raw[_GET_MEASUREMENTS_REQ_SIZE:]

    records = []
    opaque_fields: dict = {}

    if len(resp) >= 8 and resp[1] == _SPDM_MEASUREMENTS_CODE:
        # resp[4]   = NumberOfBlocks
        # resp[5:8] = MeasurementRecordLength (3 bytes LE)
        num_blocks = resp[4]
        mrl = int.from_bytes(resp[5:8], "little")
        rec_start = 8
        rec_end = rec_start + mrl
        if rec_end + _SPDM_NONCE_SIZE + 2 <= len(resp):
            records = _parse_measurement_records(resp[rec_start:rec_end], num_blocks)
            logger.debug("Parsed %d/%d measurement records", len(records), num_blocks)

            # OpaqueData: 2 bytes LE length at rec_end + nonce_size, then value
            opaque_offset = rec_end + _SPDM_NONCE_SIZE
            opaque_len = int.from_bytes(resp[opaque_offset:opaque_offset + 2], "little")
            opaque_data = resp[opaque_offset + 2 : opaque_offset + 2 + opaque_len]
            opaque_fields = _parse_opaque_fields(opaque_data)

    return NvidiaEvidence(
        records=records,
        nonce=nonce,
        signature=signature,
        raw_signed_data=raw_signed_data,
        opaque_fields=opaque_fields,
    )


def _parse_response_only_blob(raw: bytes) -> NvidiaEvidence:
    """Parse a standalone MEASUREMENTS response blob (no request prefix)."""
    signature = b""
    nonce = ""
    raw_signed_data = b""
    records = []

    if len(raw) > _ECDSA_P384_SIG_SIZE + _SPDM_NONCE_SIZE + 10:
        signature = raw[-_ECDSA_P384_SIG_SIZE:]
        raw_signed_data = raw[:-_ECDSA_P384_SIG_SIZE]

        if len(raw) >= 8 and raw[1] == _SPDM_MEASUREMENTS_CODE:
            num_blocks = raw[4]
            mrl = int.from_bytes(raw[5:8], "little")
            rec_start = 8
            rec_end = rec_start + mrl
            if rec_end <= len(raw):
                records = _parse_measurement_records(raw[rec_start:rec_end], num_blocks)

        # Nonce is at offset 4 in the header (fallback)
        nonce_bytes = raw[4 : 4 + _SPDM_NONCE_SIZE]
        nonce = nonce_bytes.hex()
    else:
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


def _parse_opaque_fields(opaque: bytes) -> dict:
    """Parse NVIDIA SPDM OpaqueData TLV fields.

    Format: repeated (type: 2 bytes LE, length: 2 bytes LE, value: N bytes).

    Known types:
      3  = DRIVER_VERSION  (UTF-8 string, e.g. "570.172.08")
      6  = VBIOS_VERSION   (raw bytes, hex-encode for RIM ID)
      15 = CHIP_SKU        (UTF-8 string, e.g. "895")
      17 = PROJECT         (UTF-8 string, e.g. "G520")
      18 = PROJECT_SKU     (UTF-8 string, e.g. "0280")
    """
    import struct as _struct
    fields: dict = {}
    pos = 0
    _STRING_TYPES = {3, 15, 17, 18}  # types whose values are UTF-8 strings

    while pos + 4 <= len(opaque):
        ftype = _struct.unpack_from("<H", opaque, pos)[0]
        flen  = _struct.unpack_from("<H", opaque, pos + 2)[0]
        fval  = opaque[pos + 4 : pos + 4 + flen]

        if ftype in _STRING_TYPES:
            try:
                fields[ftype] = fval.rstrip(b"\x00").decode("utf-8")
            except UnicodeDecodeError:
                fields[ftype] = fval.hex()
        else:
            fields[ftype] = fval.hex()

        pos += 4 + flen

    return fields


def _parse_measurement_records(record_bytes: bytes, expected_count: int) -> list:
    """Parse SPDM measurement records from a pre-sliced record buffer.

    Each record:
      index          (1 byte)
      measurement_spec (1 byte)  — 0x01 = DMTF
      measurement_size (2 bytes LE) — size of the measurement value field
      measurement_data (measurement_size bytes)

    DMTF measurement value field:
      type     (1 byte)  — bits[6:0] = component type, bit[7] = raw/digest
      val_size (2 bytes LE) — byte length of the hash/value
      value    (val_size bytes) — SHA-384 digest (48 bytes for P-384)
    """
    records = []
    pos = 0

    for _ in range(expected_count):
        if pos + 4 > len(record_bytes):
            break

        index = record_bytes[pos]
        spec = record_bytes[pos + 1]
        meas_size = struct.unpack_from("<H", record_bytes, pos + 2)[0]
        pos += 4

        if meas_size == 0 or pos + meas_size > len(record_bytes):
            break

        meas_data = record_bytes[pos : pos + meas_size]
        pos += meas_size

        record: dict = {
            "index": index,
            "measurement_spec": spec,
            "size": meas_size,
            "data": meas_data.hex(),
        }

        # Parse DMTF format (spec == 0x01)
        if spec == 0x01 and meas_size >= 3:
            dtype = meas_data[0]
            val_size = struct.unpack_from("<H", meas_data, 1)[0]
            if 3 + val_size <= meas_size:
                hash_value = meas_data[3 : 3 + val_size]
                record["dmtf_type"] = dtype
                record["hash_size"] = val_size
                record["hash_value"] = hash_value.hex()

        records.append(record)

    return records
