"""NVIDIA OCSP certificate revocation checking."""

from __future__ import annotations

import logging
from typing import Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

logger = logging.getLogger(__name__)

NVIDIA_OCSP_URL = "https://ocsp.ndis.nvidia.com/"


def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    """Extract OCSP URL from cert's AIA extension, or return None."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except Exception:
        pass
    return None


def check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    timeout: int = 15,
) -> Tuple[str, str]:
    """Check certificate revocation status via OCSP.

    Uses the OCSP URL from the cert's AIA extension. If no AIA OCSP URL is
    present, returns ("skipped", ...) rather than guessing a URL.

    Args:
        cert: The certificate to check.
        issuer: The issuer certificate.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (status, detail) where status is "good", "revoked", "unknown",
        or "skipped".
    """
    ocsp_url = _get_ocsp_url(cert)
    if not ocsp_url:
        return "skipped", "No OCSP URL in certificate"

    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()
        ocsp_request_data = ocsp_request.public_bytes(serialization.Encoding.DER)

        resp = requests.post(
            ocsp_url,
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
    """Check OCSP revocation status for the leaf certificate only.

    NVIDIA's OCSP responder (ocsp.ndis.nvidia.com) handles device-level
    (leaf) certificates. Intermediate and root CAs use CRL instead of OCSP.

    Args:
        certs: Certificate chain ordered [leaf, intermediate..., root].
        timeout: Request timeout in seconds.

    Returns:
        List with a single (status, detail) tuple for the leaf cert, or
        empty list if the chain has fewer than 2 certificates.
    """
    if len(certs) < 2:
        return []
    status, detail = check_ocsp(certs[0], certs[1], timeout=timeout)
    return [(status, detail)]
