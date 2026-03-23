"""Intel TDX DCAP Quote v4 binary parser."""

from __future__ import annotations

import struct
from typing import List

from tee_verify.models import TDXQuote


# TDX Quote v4 structure offsets
_HEADER_SIZE = 48
_TD_BODY_SIZE = 584
_TD_BODY_START = _HEADER_SIZE
_TD_BODY_END = _TD_BODY_START + _TD_BODY_SIZE

# TD Quote Body field offsets (relative to body start)
_TEE_TCB_SVN_OFF = 0
_TEE_TCB_SVN_LEN = 16
_MRSEAM_OFF = 16
_MRSEAM_LEN = 48
_MRSIGNERSEAM_OFF = 64
_MRSIGNERSEAM_LEN = 48
_SEAM_ATTRIBUTES_OFF = 112
_SEAM_ATTRIBUTES_LEN = 8
_TD_ATTRIBUTES_OFF = 120
_TD_ATTRIBUTES_LEN = 8
_XFAM_OFF = 128
_XFAM_LEN = 8
_MRTD_OFF = 136
_MRTD_LEN = 48
_MRCONFIGID_OFF = 184
_MRCONFIGID_LEN = 48
_MROWNER_OFF = 232
_MROWNER_LEN = 48
_MROWNERCONFIG_OFF = 280
_MROWNERCONFIG_LEN = 48
_RTMR0_OFF = 328
_RTMR1_OFF = 376
_RTMR2_OFF = 424
_RTMR3_OFF = 472
_RTMR_LEN = 48
_REPORT_DATA_OFF = 520
_REPORT_DATA_LEN = 64

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"


def parse_quote(data: str | bytes) -> TDXQuote:
    """Parse a TDX DCAP Quote v4 from hex string or raw bytes.

    Args:
        data: Hex-encoded string or raw bytes of the TDX quote.

    Returns:
        Parsed TDXQuote dataclass.

    Raises:
        ValueError: If the quote is malformed or too short.
    """
    if isinstance(data, str):
        data = data.strip()
        try:
            raw = bytes.fromhex(data)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e
    else:
        raw = data

    if len(raw) < _TD_BODY_END + 4:
        raise ValueError(
            f"Quote too short: {len(raw)} bytes, need at least {_TD_BODY_END + 4}"
        )

    # Parse header
    version = struct.unpack_from("<H", raw, 0)[0]
    attest_key_type = struct.unpack_from("<H", raw, 2)[0]
    tee_type = struct.unpack_from("<I", raw, 4)[0]

    if version != 4:
        raise ValueError(f"Expected quote version 4, got {version}")

    qe_vendor_id = raw[32:48].hex()

    # Parse TD Quote Body
    body = raw[_TD_BODY_START:_TD_BODY_END]

    def _hex(offset: int, length: int) -> str:
        return body[offset : offset + length].hex()

    tee_tcb_svn = _hex(_TEE_TCB_SVN_OFF, _TEE_TCB_SVN_LEN)
    mrseam = _hex(_MRSEAM_OFF, _MRSEAM_LEN)
    mrsignerseam = _hex(_MRSIGNERSEAM_OFF, _MRSIGNERSEAM_LEN)
    seam_attributes = _hex(_SEAM_ATTRIBUTES_OFF, _SEAM_ATTRIBUTES_LEN)
    td_attributes = _hex(_TD_ATTRIBUTES_OFF, _TD_ATTRIBUTES_LEN)
    xfam = _hex(_XFAM_OFF, _XFAM_LEN)
    mrtd = _hex(_MRTD_OFF, _MRTD_LEN)
    mrconfigid = _hex(_MRCONFIGID_OFF, _MRCONFIGID_LEN)
    mrowner = _hex(_MROWNER_OFF, _MROWNER_LEN)
    mrownerconfig = _hex(_MROWNERCONFIG_OFF, _MROWNERCONFIG_LEN)
    rtmr0 = _hex(_RTMR0_OFF, _RTMR_LEN)
    rtmr1 = _hex(_RTMR1_OFF, _RTMR_LEN)
    rtmr2 = _hex(_RTMR2_OFF, _RTMR_LEN)
    rtmr3 = _hex(_RTMR3_OFF, _RTMR_LEN)
    report_data = _hex(_REPORT_DATA_OFF, _REPORT_DATA_LEN)

    # Parse signature data section
    sig_data_offset = _TD_BODY_END
    sig_data_len = struct.unpack_from("<I", raw, sig_data_offset)[0]
    sig_start = sig_data_offset + 4

    # ECDSA-256 signature (64 bytes) + attestation public key (64 bytes)
    signature = raw[sig_start : sig_start + 64]
    attest_pub_key = raw[sig_start + 64 : sig_start + 128]

    # Extract PCK certificate chain from the quote
    pck_cert_chain = _extract_pem_certs(raw)

    raw_header = raw[:_HEADER_SIZE]
    raw_td_body = raw[_TD_BODY_START:_TD_BODY_END]

    return TDXQuote(
        version=version,
        attest_key_type=attest_key_type,
        tee_type=tee_type,
        qe_vendor_id=qe_vendor_id,
        tee_tcb_svn=tee_tcb_svn,
        mrseam=mrseam,
        mrsignerseam=mrsignerseam,
        seam_attributes=seam_attributes,
        td_attributes=td_attributes,
        xfam=xfam,
        mrtd=mrtd,
        mrconfigid=mrconfigid,
        mrowner=mrowner,
        mrownerconfig=mrownerconfig,
        rtmr0=rtmr0,
        rtmr1=rtmr1,
        rtmr2=rtmr2,
        rtmr3=rtmr3,
        report_data=report_data,
        signature=signature,
        attest_pub_key=attest_pub_key,
        pck_cert_chain=pck_cert_chain,
        raw_header=raw_header,
        raw_td_body=raw_td_body,
    )


def _extract_pem_certs(raw: bytes) -> List[bytes]:
    """Extract PEM certificates embedded in the quote binary."""
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
        # Include trailing newline if present
        if end_idx < len(raw) and raw[end_idx : end_idx + 1] == b"\n":
            end_idx += 1
        certs.append(raw[begin_idx:end_idx])
        search_start = end_idx
    return certs
