"""NVIDIA OCSP certificate revocation checking."""

from __future__ import annotations

import logging
from typing import Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

logger = logging.getLogger(__name__)

NVIDIA_OCSP_URL = "https://ocsp.ndis.nvidia.com/"


def check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    timeout: int = 15,
) -> Tuple[str, str]:
    """Check certificate revocation status via NVIDIA OCSP.

    Args:
        cert: The certificate to check.
        issuer: The issuer certificate.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (status, detail) where status is "good", "revoked", or "unknown".
    """
    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()
        ocsp_request_data = ocsp_request.public_bytes(serialization.Encoding.DER)

        resp = requests.post(
            NVIDIA_OCSP_URL,
            data=ocsp_request_data,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=timeout,
        )
        resp.raise_for_status()

        ocsp_response = ocsp.load_der_ocsp_response(resp.content)

        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return "unknown", f"OCSP response status: {ocsp_response.response_status.name}"

        cert_status = ocsp_response.certificate_status
        if cert_status == ocsp.OCSPCertStatus.GOOD:
            return "good", "Certificate is valid"
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            return "revoked", f"Certificate revoked at {ocsp_response.revocation_time}"
        else:
            return "unknown", "OCSP status unknown"

    except requests.RequestException as e:
        logger.warning("OCSP request failed: %s", e)
        return "unknown", f"OCSP request failed: {e}"
    except Exception as e:
        logger.warning("OCSP check error: %s", e)
        return "unknown", f"OCSP check error: {e}"


def check_chain_ocsp(
    certs: list[x509.Certificate],
    timeout: int = 15,
) -> list[Tuple[str, str]]:
    """Check OCSP status for each certificate in a chain (except the root).

    Args:
        certs: Certificate chain ordered [leaf, intermediate..., root].
        timeout: Request timeout in seconds.

    Returns:
        List of (status, detail) tuples for each cert except root.
    """
    results = []
    for i in range(len(certs) - 1):
        status, detail = check_ocsp(certs[i], certs[i + 1], timeout=timeout)
        results.append((status, detail))
    return results
