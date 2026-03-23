"""Session binding verification: nonce cross-check between TDX and GPU attestations."""

from __future__ import annotations

from typing import List, Tuple

from tee_verify.models import TDXVerificationResult, NvidiaGPUVerificationResult


def verify_nonce_binding(
    tdx_result: TDXVerificationResult,
    nvidia_results: List[NvidiaGPUVerificationResult],
) -> Tuple[bool, str]:
    """Verify that all GPU nonces match the TDX session nonce.

    The nonce in every GPU's evidence must match the nonce in the TDX quote's
    REPORTDATA field (first 32 bytes). This proves the GPU attestations belong
    to the same TEE session as the TDX enclave.

    Args:
        tdx_result: Verified TDX quote result containing the session nonce.
        nvidia_results: List of verified GPU results containing their nonces.

    Returns:
        Tuple of (binding_valid, detail_message).
    """
    if not tdx_result.nonce:
        return False, "TDX nonce is empty"

    if not nvidia_results:
        return False, "No NVIDIA GPU results to bind"

    tdx_nonce = tdx_result.nonce.lower()

    for gpu in nvidia_results:
        if not gpu.nonce:
            return False, f"GPU {gpu.gpu_index} has no nonce"

        gpu_nonce = gpu.nonce.lower()
        if gpu_nonce != tdx_nonce:
            return False, (
                f"GPU {gpu.gpu_index} nonce mismatch: "
                f"expected {tdx_nonce[:16]}..., got {gpu_nonce[:16]}..."
            )

    return True, f"All GPU nonces match TDX session (n={len(nvidia_results)})"
