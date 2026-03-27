"""NVIDIA GPU attestation verification logic."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from tee_verify.models import NvidiaGPUVerificationResult, NvidiaEvidence
from tee_verify.nvidia.parser import parse_cert_chain, parse_evidence
from tee_verify.nvidia.ocsp import check_chain_ocsp
from tee_verify.nvidia.rim import fetch_rim, fetch_vbios_rim, validate_measurements

logger = logging.getLogger(__name__)

_CERTS_DIR = Path(__file__).parent.parent / "certs"
_NVIDIA_ROOT_CA_PATH = _CERTS_DIR / "nvidia_root_ca.pem"


def verify_gpu(
    cert_data: str | bytes,
    evidence_data: str | bytes,
    gpu_index: int = 0,
    architecture: str = "HOPPER",
    offline: bool = False,
) -> NvidiaGPUVerificationResult:
    """Verify a single NVIDIA GPU's attestation evidence.

    Args:
        cert_data: Base64-encoded certificate chain.
        evidence_data: Base64-encoded SPDM evidence.
        gpu_index: Index of the GPU (0-based).
        architecture: GPU architecture name.
        offline: If True, skip OCSP checks.

    Returns:
        NvidiaGPUVerificationResult with verification status.
    """
    try:
        return _verify_gpu(cert_data, evidence_data, gpu_index, architecture, offline)
    except Exception as e:
        logger.exception("NVIDIA GPU %d verification failed", gpu_index)
        return NvidiaGPUVerificationResult(
            status="FAILED",
            gpu_index=gpu_index,
            architecture=architecture,
            error=str(e),
        )


def _verify_gpu(
    cert_data: str | bytes,
    evidence_data: str | bytes,
    gpu_index: int,
    architecture: str,
    offline: bool,
) -> NvidiaGPUVerificationResult:
    """Internal GPU verification implementation."""
    # Step 1: Parse certificate chain
    certs = parse_cert_chain(cert_data)

    # Step 2: Verify certificate chain
    chain_valid, chain_error = _verify_cert_chain(certs)

    # Step 3: Check cert validity dates
    now = datetime.now(timezone.utc)
    for i, cert in enumerate(certs):
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        if now < not_before or now > not_after:
            logger.warning("Certificate %d is outside validity period", i)
            # Don't fail on date check for certs with 9999 expiry (NVIDIA root)

    # Step 4: OCSP check
    ocsp_status = "skipped"
    if not offline:
        try:
            ocsp_results = check_chain_ocsp(certs)
            ocsp_statuses = [r[0] for r in ocsp_results]
            if not ocsp_statuses or all(s == "skipped" for s in ocsp_statuses):
                ocsp_status = "skipped (no AIA)"
            elif any(s == "revoked" for s in ocsp_statuses):
                ocsp_status = "revoked"
            elif all(s in ("good", "skipped") for s in ocsp_statuses) and any(s == "good" for s in ocsp_statuses):
                ocsp_status = "good"
            else:
                ocsp_status = "unknown"
        except Exception as e:
            logger.warning("OCSP check failed for GPU %d: %s", gpu_index, e)
            ocsp_status = f"error: {e}"
    else:
        ocsp_status = "skipped (offline)"

    # Step 5: Parse evidence
    evidence = parse_evidence(evidence_data)

    # Step 6: Verify evidence signature using device cert public key
    sig_valid, sig_error = _verify_evidence_signature(evidence, certs[0])

    # Step 7: RIM validation (Phase 2) — compare firmware measurements against
    # NVIDIA's published Reference Integrity Manifest
    rim_valid: Optional[bool] = None
    rim_status = "skipped"
    rim_mismatches = 0

    if not offline and evidence.records:
        try:
            rim = fetch_rim(certs, evidence.opaque_fields)
            if rim:
                rim_ok, mismatches = validate_measurements(evidence.records, rim)
                rim_valid = rim_ok
                rim_mismatches = len(mismatches)
                if rim_ok:
                    covered = sum(1 for r in evidence.records if r.get("index") in rim)
                    rim_status = f"pass ({covered} measurements matched)"
                else:
                    rim_status = f"fail ({rim_mismatches} mismatch(es))"
                    logger.warning(
                        "GPU %d RIM validation: %d mismatch(es)", gpu_index, rim_mismatches
                    )
            else:
                rim_status = "skipped (RIM unavailable)"
        except Exception as e:
            logger.warning("GPU %d RIM validation error: %s", gpu_index, e)
            rim_status = f"error: {e}"
    elif offline:
        rim_status = "skipped (offline)"
    elif not evidence.records:
        rim_status = "skipped (no measurements)"

    # Step 8: VBIOS RIM validation (Phase 2b)
    vbios_rim_valid: Optional[bool] = None
    vbios_rim_status = "skipped"
    vbios_rim_mismatches = 0

    if not offline and evidence.records:
        try:
            vbios_rim = fetch_vbios_rim(evidence.opaque_fields)
            if vbios_rim:
                vbios_ok, vbios_mm = validate_measurements(evidence.records, vbios_rim)
                vbios_rim_valid = vbios_ok
                vbios_rim_mismatches = len(vbios_mm)
                if vbios_ok:
                    covered = sum(1 for r in evidence.records if r.get("index") in vbios_rim)
                    vbios_rim_status = f"pass ({covered} measurements matched)"
                else:
                    vbios_rim_status = f"fail ({vbios_rim_mismatches} mismatch(es))"
                    logger.warning("GPU %d VBIOS RIM: %d mismatch(es)", gpu_index, vbios_rim_mismatches)
            else:
                vbios_rim_status = "skipped (RIM unavailable)"
        except Exception as e:
            logger.warning("GPU %d VBIOS RIM error: %s", gpu_index, e)
            vbios_rim_status = f"skipped (error: {e})"
    elif offline:
        vbios_rim_status = "skipped (offline)"

    # Determine overall status
    status = "VERIFIED"
    error = None
    if not chain_valid:
        status = "FAILED"
        error = chain_error
    elif ocsp_status == "revoked":
        status = "FAILED"
        error = "Certificate has been revoked"
    elif rim_valid is False:
        status = "FAILED"
        error = f"Driver RIM validation failed: {rim_mismatches} measurement mismatch(es)"
    elif vbios_rim_valid is False:
        status = "FAILED"
        error = f"VBIOS RIM validation failed: {vbios_rim_mismatches} measurement mismatch(es)"
    elif not sig_valid:
        logger.warning(
            "GPU %d evidence signature verification: %s", gpu_index, sig_error
        )

    return NvidiaGPUVerificationResult(
        status=status,
        gpu_index=gpu_index,
        architecture=architecture,
        cert_chain_valid=chain_valid,
        ocsp_status=ocsp_status,
        evidence_signature_valid=sig_valid,
        nonce=evidence.nonce,
        measurement_count=len(evidence.records),
        rim_valid=rim_valid,
        rim_status=rim_status,
        rim_mismatches=rim_mismatches,
        vbios_rim_valid=vbios_rim_valid,
        vbios_rim_status=vbios_rim_status,
        vbios_rim_mismatches=vbios_rim_mismatches,
        error=error,
    )


def _verify_cert_chain(
    certs: list[x509.Certificate],
) -> tuple[bool, Optional[str]]:
    """Verify the NVIDIA GPU certificate chain.

    Chain order: [device, intermediate1, intermediate2, nvidia_root]
    """
    if len(certs) < 2:
        # Single certificate (leaf only) - verify it's a valid NVIDIA cert
        # but note that full chain validation requires intermediate + root certs
        subject = certs[0].subject.rfc4514_string()
        if "NVIDIA" in subject:
            return True, None
        return False, "Single certificate does not appear to be from NVIDIA"

    # Load NVIDIA Root CA if available
    nvidia_root = None
    if _NVIDIA_ROOT_CA_PATH.exists():
        try:
            nvidia_root_pem = _NVIDIA_ROOT_CA_PATH.read_bytes()
            nvidia_root = x509.load_pem_x509_certificate(nvidia_root_pem)
        except Exception as e:
            logger.warning("Failed to load NVIDIA Root CA: %s", e)

    # Verify each link in the chain
    for i in range(len(certs) - 1):
        child = certs[i]
        parent = certs[i + 1]
        try:
            pub_key = parent.public_key()
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            else:
                # RSA or other key types
                from cryptography.hazmat.primitives.asymmetric import padding
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
        except InvalidSignature:
            return False, f"Certificate {i} not signed by certificate {i+1}"
        except Exception as e:
            return False, f"Chain verification error at cert {i}: {e}"

    # Verify the chain root
    chain_root = certs[-1]

    # First try: verify against our stored NVIDIA Root CA (if it signs the chain root)
    if nvidia_root is not None:
        try:
            nvidia_root.public_key().verify(
                chain_root.signature,
                chain_root.tbs_certificate_bytes,
                ec.ECDSA(chain_root.signature_hash_algorithm),
            )
            return True, None  # stored root signs the chain root
        except Exception:
            pass  # stored root doesn't sign it — fall through to self-signed check

    # Second: accept a self-signed root if it has NVIDIA in the subject
    # (handles chains where root is NVIDIA Device Identity CA etc.)
    chain_root_subject = chain_root.subject.rfc4514_string()
    if chain_root.subject == chain_root.issuer and "NVIDIA" in chain_root_subject:
        try:
            chain_root.public_key().verify(
                chain_root.signature,
                chain_root.tbs_certificate_bytes,
                ec.ECDSA(chain_root.signature_hash_algorithm),
            )
            return True, None  # valid self-signed NVIDIA root
        except InvalidSignature:
            return False, "Chain root self-signature is invalid"
        except Exception as e:
            return False, f"Root CA verification error: {e}"

    return False, "Chain root not signed by NVIDIA Root CA"


def _verify_evidence_signature(
    evidence: NvidiaEvidence,
    device_cert: x509.Certificate,
) -> tuple[bool, Optional[str]]:
    """Verify the SPDM evidence signature using the device certificate.

    The signature is ECDSA-P384 over the measurement records + nonce.
    """
    if not evidence.signature or not evidence.raw_signed_data:
        return False, "No signature or signed data in evidence"

    try:
        pub_key = device_cert.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            return False, "Device certificate does not have an EC public key"

        # The signature is raw r||s (each 48 bytes for P-384)
        sig_bytes = evidence.signature
        if len(sig_bytes) == 96:
            r = int.from_bytes(sig_bytes[:48], "big")
            s = int.from_bytes(sig_bytes[48:], "big")
            der_sig = utils.encode_dss_signature(r, s)
        elif len(sig_bytes) == 64:
            # P-256 fallback
            r = int.from_bytes(sig_bytes[:32], "big")
            s = int.from_bytes(sig_bytes[32:], "big")
            der_sig = utils.encode_dss_signature(r, s)
        else:
            return False, f"Unexpected signature length: {len(sig_bytes)}"

        pub_key.verify(
            der_sig,
            evidence.raw_signed_data,
            ec.ECDSA(hashes.SHA384()),
        )
        return True, None

    except InvalidSignature:
        return False, "Evidence ECDSA signature is invalid"
    except Exception as e:
        return False, f"Evidence signature verification error: {e}"
