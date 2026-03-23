"""Main verification orchestrator for composite TEE attestation."""

from __future__ import annotations

import logging
from typing import List, Optional

from tee_verify.models import (
    CompositeVerificationResult,
    NvidiaGPUVerificationResult,
    OLLMReceipt,
    TDXVerificationResult,
)
from tee_verify.tdx.verifier import verify_tdx_quote
from tee_verify.nvidia.verifier import verify_gpu
from tee_verify.binding import verify_nonce_binding

logger = logging.getLogger(__name__)


def verify_composite(
    tdx_quote_hex: Optional[str] = None,
    nvidia_certs: Optional[List[str]] = None,
    nvidia_evidences: Optional[List[str]] = None,
    nvidia_architecture: str = "HOPPER",
    offline: bool = False,
) -> CompositeVerificationResult:
    """Run full composite TEE attestation verification.

    Args:
        tdx_quote_hex: Hex-encoded TDX DCAP Quote v4.
        nvidia_certs: List of base64-encoded GPU certificate chains.
        nvidia_evidences: List of base64-encoded GPU evidence blobs.
        nvidia_architecture: GPU architecture name.
        offline: If True, skip online checks (PCS API, OCSP).

    Returns:
        CompositeVerificationResult with all verification results.
    """
    tdx_result = None
    nvidia_results: List[NvidiaGPUVerificationResult] = []
    nonce_binding_valid = False

    # Step 1: Verify TDX quote
    if tdx_quote_hex:
        logger.info("Verifying Intel TDX quote...")
        tdx_result = verify_tdx_quote(tdx_quote_hex, offline=offline)
        logger.info("TDX verification: %s", tdx_result.status)

    # Step 2: Verify NVIDIA GPUs
    if nvidia_certs and nvidia_evidences:
        gpu_count = min(len(nvidia_certs), len(nvidia_evidences))
        logger.info("Verifying %d NVIDIA GPU attestations...", gpu_count)
        for i in range(gpu_count):
            gpu_result = verify_gpu(
                cert_data=nvidia_certs[i],
                evidence_data=nvidia_evidences[i],
                gpu_index=i,
                architecture=nvidia_architecture,
                offline=offline,
            )
            nvidia_results.append(gpu_result)
            logger.info("GPU %d verification: %s", i, gpu_result.status)

    # Step 3: Session binding check
    if tdx_result and nvidia_results:
        nonce_binding_valid, binding_detail = verify_nonce_binding(
            tdx_result, nvidia_results
        )
        logger.info("Session binding: %s - %s", nonce_binding_valid, binding_detail)

    # Determine overall status
    overall = _compute_overall_status(tdx_result, nvidia_results, nonce_binding_valid)

    return CompositeVerificationResult(
        overall_status=overall,
        tdx=tdx_result,
        nvidia_gpus=nvidia_results,
        nonce_binding_valid=nonce_binding_valid,
    )


def verify_from_receipt(
    receipt: OLLMReceipt,
    offline: bool = False,
) -> CompositeVerificationResult:
    """Run verification from a parsed OLLM receipt.

    Args:
        receipt: Parsed OLLM attestation receipt.
        offline: If True, skip online checks.

    Returns:
        CompositeVerificationResult.
    """
    return verify_composite(
        tdx_quote_hex=receipt.tdx_quote_hex or None,
        nvidia_certs=receipt.gpu_certificates or None,
        nvidia_evidences=receipt.gpu_evidences or None,
        nvidia_architecture=receipt.nvidia_architecture or "HOPPER",
        offline=offline,
    )


def _compute_overall_status(
    tdx: Optional[TDXVerificationResult],
    gpus: List[NvidiaGPUVerificationResult],
    nonce_ok: bool,
) -> str:
    """Compute the composite verification status."""
    has_tdx = tdx is not None
    has_gpus = len(gpus) > 0

    if not has_tdx and not has_gpus:
        return "FAILED"

    # Check TDX
    if has_tdx and tdx.status == "FAILED":
        return "FAILED"

    # Check all GPUs
    if has_gpus:
        failed_gpus = [g for g in gpus if g.status == "FAILED"]
        if failed_gpus:
            return "FAILED"

    # Check binding (only if both TDX and GPU present)
    if has_tdx and has_gpus and not nonce_ok:
        return "FAILED"

    # TCB out of date is a warning, not failure
    if has_tdx and tdx.status == "TCB_OUT_OF_DATE":
        return "TCB_OUT_OF_DATE"

    return "VERIFIED"
