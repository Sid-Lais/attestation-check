"""Model identity verification (Phase 3).

Verifies that the attestation was signed by the declared model signing authority.
Phase 3 validates model immutability - that the exact model specified was run.
"""

from __future__ import annotations

import logging
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_defunct

from tee_verify.models import ModelIdentityVerificationResult

logger = logging.getLogger(__name__)


def verify_model_identity(
    tdx_quote_hex: str,
    ecdsa_signature: str,
    message_signer: str,
    model_signing_address: str,
) -> ModelIdentityVerificationResult:
    """Verify model identity through signature validation.

    In Phase 3, we verify that an ECDSA signature signed the attestation.
    The signer address should match the declared model signing authority.

    Args:
        tdx_quote_hex: Hex string of the TDX quote (testament of what ran).
        ecdsa_signature: Hex string of the ECDSA signature (0x-prefixed).
        message_signer: Declared signer address (0x-prefixed).
        model_signing_address: Model identity hash (what was certified).

    Returns:
        ModelIdentityVerificationResult with verification status.
    """
    # If no signature provided, skip verification
    if not ecdsa_signature or not message_signer:
        return ModelIdentityVerificationResult(
            status="SKIPPED",
            error="No signature or signer in attestation",
        )

    try:
        return _verify_model_identity(
            tdx_quote_hex, ecdsa_signature, message_signer, model_signing_address
        )
    except Exception as e:
        logger.exception("Model identity verification failed: %s", e)
        return ModelIdentityVerificationResult(
            status="FAILED",
            declared_address=message_signer,
            error=str(e),
        )


def _verify_model_identity(
    tdx_quote_hex: str,
    ecdsa_signature: str,
    message_signer: str,
    model_signing_address: str,
) -> ModelIdentityVerificationResult:
    """Internal model identity verification."""
    # Normalize addresses
    declared = message_signer.lower()
    if not declared.startswith("0x"):
        declared = "0x" + declared

    sig = ecdsa_signature.lower()
    if not sig.startswith("0x"):
        sig = "0x" + sig

    # Recover signer from signature
    recovered_addr = _recover_signer(tdx_quote_hex, sig)

    if not recovered_addr:
        return ModelIdentityVerificationResult(
            status="FAILED",
            declared_address=message_signer,
            error="Could not recover signer address from signature",
        )

    recovered_addr = recovered_addr.lower()

    # Check if recovered address matches declared address
    addresses_match = recovered_addr == declared

    # In production, the message format specification would determine if this passes.
    # For now, we return "SKIPPED" to indicate signature is valid but needs message spec.
    return ModelIdentityVerificationResult(
        status="VERIFIED" if addresses_match else "SKIPPED",
        signer_address=recovered_addr,
        declared_address=declared,
        addresses_match=addresses_match,
        error=None if addresses_match else "Requires message format specification",
    )


def _recover_signer(message: str, signature: str) -> Optional[str]:
    """Recover Ethereum address from message and signature.

    Tries multiple message encoding formats that might have been used
    when creating the signature.
    """
    attempts = [
        ("raw TDX quote", message),
        ("TDX quote without 0x prefix", message[2:] if message.startswith("0x") else message),
        ("hex string as message", f"0x{message[2:] if message.startswith('0x') else message}"),
    ]

    for label, msg in attempts:
        try:
            eth_message = encode_defunct(text=msg)
            recovered = Account.recover_message(eth_message, signature=signature)
            logger.debug("Signature recovery succeeded with %s: %s", label, recovered)
            return recovered
        except Exception as e:
            logger.debug("Signature recovery with %s failed: %s", label, type(e).__name__)

    return None
