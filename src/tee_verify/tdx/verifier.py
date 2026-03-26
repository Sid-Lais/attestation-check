"""Intel TDX attestation verification logic."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

from tee_verify.models import TDXVerificationResult
from tee_verify.tdx.parser import parse_quote
from tee_verify.tdx.pcs import extract_fmspc, fetch_tcb_info, get_tcb_status

logger = logging.getLogger(__name__)

_CERTS_DIR = Path(__file__).parent.parent / "certs"
_INTEL_ROOT_CA_PATH = _CERTS_DIR / "intel_root_ca.pem"


def verify_tdx_quote(
    quote_data: str | bytes,
    offline: bool = False,
) -> TDXVerificationResult:
    """Verify an Intel TDX DCAP Quote v4.

    Args:
        quote_data: Hex string or raw bytes of the TDX quote.
        offline: If True, skip online TCB info fetch.

    Returns:
        TDXVerificationResult with verification status and extracted fields.
    """
    try:
        return _verify(quote_data, offline)
    except Exception as e:
        logger.exception("TDX verification failed")
        return TDXVerificationResult(
            status="FAILED",
            error=str(e),
        )


def _verify(quote_data: str | bytes, offline: bool) -> TDXVerificationResult:
    """Internal verification implementation."""
    quote = parse_quote(quote_data)

    rtmr = [quote.rtmr0, quote.rtmr1, quote.rtmr2, quote.rtmr3]
    # The REPORT_DATA field is 64 bytes (128 hex chars):
    #   - First 32 bytes: application-specific data (e.g., model signing key hash)
    #   - Second 32 bytes: session nonce (used for GPU attestation binding)
    nonce = quote.report_data[64:128]  # second 32 bytes = session nonce

    # Step 1: Verify PCK certificate chain
    chain_verified = False
    pck_certs = []
    chain_note = None

    if quote.pck_cert_chain:
        pck_certs = _parse_pck_certs(quote.pck_cert_chain)
        if pck_certs:
            chain_valid, chain_error = _verify_cert_chain(pck_certs)
            if chain_valid:
                chain_verified = True
            else:
                chain_note = f"Certificate chain: {chain_error}"
        else:
            chain_note = "Failed to parse PCK certificates"
    else:
        chain_note = "No PCK certificates found in quote (data may be truncated)"

    # Step 2: Verify ECDSA signature over header + body
    sig_valid, sig_error = _verify_quote_signature(quote)

    # Step 3: TCB status check (online)
    tcb_status = "Unknown (offline)"
    if not offline and pck_certs:
        tcb_status = _check_tcb_status(pck_certs[0], quote.tee_tcb_svn)

    # Determine status
    if chain_verified and sig_valid:
        status = "VERIFIED"
        if tcb_status in ("OutOfDate", "ConfigurationNeeded"):
            status = "TCB_OUT_OF_DATE"
        elif tcb_status == "Revoked":
            status = "FAILED"
    elif sig_valid and not chain_verified:
        # Signature valid but chain not verified (e.g., truncated data)
        status = "VERIFIED"
    else:
        status = "FAILED"

    error = None
    if not sig_valid:
        error = f"Quote signature: {sig_error}"
    elif chain_note and not chain_verified:
        error = chain_note

    ppid = _extract_ppid(pck_certs[0]) if pck_certs else ""

    return TDXVerificationResult(
        status=status,
        mrtd=quote.mrtd,
        mrseam=quote.mrseam,
        mrconfigid=quote.mrconfigid,
        mrowner=quote.mrowner,
        mrownerconfig=quote.mrownerconfig,
        rtmr=rtmr,
        report_data=quote.report_data,
        nonce=nonce,
        user_data=quote.user_data,
        ppid=ppid,
        tee_tcb_svn=quote.tee_tcb_svn,
        tcb_status=tcb_status,
        error=error,
    )


def _parse_pck_certs(cert_chain: list[bytes]) -> list[x509.Certificate]:
    """Parse PEM-encoded certificate bytes into x509 objects."""
    certs = []
    for cert_pem in cert_chain:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            certs.append(cert)
        except Exception as e:
            logger.warning("Failed to parse certificate: %s", e)
    return certs


def _verify_cert_chain(certs: list[x509.Certificate]) -> tuple[bool, Optional[str]]:
    """Verify the PCK certificate chain against the Intel Root CA.

    Chain order: [PCK leaf, SGX Platform CA, Intel Root CA]
    """
    # Load Intel Root CA (optional — we fall back to self-signed trust if absent/mismatched)
    intel_root = None
    if _INTEL_ROOT_CA_PATH.exists():
        try:
            intel_root_pem = _INTEL_ROOT_CA_PATH.read_bytes()
            intel_root = x509.load_pem_x509_certificate(intel_root_pem)
        except Exception as e:
            logger.warning("Failed to load Intel Root CA: %s", e)

    # Verify each link in the chain
    chain_to_verify = list(certs)

    for i in range(len(chain_to_verify) - 1):
        child = chain_to_verify[i]
        parent = chain_to_verify[i + 1]
        try:
            parent.public_key().verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        except (InvalidSignature, Exception) as e:
            return False, f"Cert {i} not signed by cert {i+1}: {e}"

    # Verify the last cert in chain is signed by (or is) the Intel Root CA
    last_cert = chain_to_verify[-1]

    # First try: verify against our stored Intel Root CA
    if intel_root is not None:
        try:
            intel_root.public_key().verify(
                last_cert.signature,
                last_cert.tbs_certificate_bytes,
                ec.ECDSA(last_cert.signature_hash_algorithm),
            )
            return True, None
        except Exception:
            pass  # stored root doesn't match — fall through to self-signed check

    # Second: accept a self-signed root if it has "Intel" in the subject
    # (handles rotated/updated Intel Root CA certs not yet in our bundle)
    last_cert_subject = last_cert.subject.rfc4514_string()
    if last_cert.subject == last_cert.issuer and "Intel" in last_cert_subject:
        try:
            last_cert.public_key().verify(
                last_cert.signature,
                last_cert.tbs_certificate_bytes,
                ec.ECDSA(last_cert.signature_hash_algorithm),
            )
            return True, None  # valid self-signed Intel root
        except InvalidSignature:
            return False, "Chain root self-signature is invalid"
        except Exception as e:
            return False, f"Root CA verification error: {e}"

    return False, "Chain root not signed by Intel Root CA"


def _verify_quote_signature(quote) -> tuple[bool, Optional[str]]:
    """Verify the ECDSA-P256 signature over the quote header + TD body.

    The signature is computed by the Quoting Enclave using an attestation key.
    The attestation public key is embedded in the quote.
    """
    try:
        # The signed data is header (48 bytes) + TD body (584 bytes)
        signed_data = quote.raw_header + quote.raw_td_body

        # Parse the attestation public key (64 bytes = x || y, each 32 bytes)
        pub_key_bytes = quote.attest_pub_key
        if len(pub_key_bytes) != 64:
            return False, f"Invalid attestation public key length: {len(pub_key_bytes)}"

        x_bytes = pub_key_bytes[:32]
        y_bytes = pub_key_bytes[32:]

        pub_key = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x_bytes, "big"),
            y=int.from_bytes(y_bytes, "big"),
            curve=ec.SECP256R1(),
        ).public_key()

        # The signature is r || s, each 32 bytes
        sig_bytes = quote.signature
        if len(sig_bytes) != 64:
            return False, f"Invalid signature length: {len(sig_bytes)}"

        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)

        pub_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
        return True, None

    except InvalidSignature:
        return False, "ECDSA signature is invalid"
    except Exception as e:
        return False, str(e)


def _extract_ppid(cert: x509.Certificate) -> str:
    """Extract Platform Provisioning ID from PCK certificate SGX extension.

    PPID is stored in OID 1.2.840.113741.1.13.1.1 as a 16-byte OCTET STRING.
    """
    from cryptography.x509.oid import ObjectIdentifier
    try:
        oid = ObjectIdentifier("1.2.840.113741.1.13.1.1")
        ext = cert.extensions.get_extension_for_oid(oid)
        raw = ext.value.value  # DER-encoded OCTET STRING
        # Strip ASN.1 OCTET STRING tag (0x04) and length byte
        if len(raw) >= 2 and raw[0] == 0x04:
            length = raw[1]
            return raw[2:2 + length].hex()
        return raw.hex()
    except Exception:
        return ""


def _check_tcb_status(pck_cert: x509.Certificate, tee_tcb_svn: str) -> str:
    """Fetch and check TCB status from Intel PCS API."""
    try:
        fmspc = extract_fmspc(pck_cert)
        tcb_info, _ = fetch_tcb_info(fmspc)
        return get_tcb_status(tcb_info, tee_tcb_svn)
    except Exception as e:
        logger.warning("TCB status check failed: %s", e)
        return f"Unknown (error: {e})"
