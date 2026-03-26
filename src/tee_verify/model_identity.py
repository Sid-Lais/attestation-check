"""Model identity verification (Phase 3).

Verifies that the attestation was signed by the declared model signing authority.
Probes all known Ethereum signing formats to self-discover which was used,
including the Phala-style sha256(request):sha256(response) pattern.
"""

from __future__ import annotations

import hashlib
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
    nonce: str = "",
    request_body: str = "",
    response_body: str = "",
) -> ModelIdentityVerificationResult:
    """Verify model identity through signature validation.

    Probes all known Ethereum/EIP-191 signing formats including the
    Phala-style sha256(request):sha256(response) pattern.

    Args:
        tdx_quote_hex: Hex string of the TDX quote.
        ecdsa_signature: Hex string of the ECDSA signature (0x-prefixed).
        message_signer: Declared signer Ethereum address (0x-prefixed).
        model_signing_address: Model identity hash from TDX report_data[0:32].
        nonce: Session nonce from TDX report_data[32:64].
        request_body: Raw request body text (enables request/response formats).
        response_body: Raw response body text (enables request/response formats).

    Returns:
        ModelIdentityVerificationResult with status, detected format, and
        how many formats were tried.
    """
    if not ecdsa_signature or not message_signer:
        return ModelIdentityVerificationResult(
            status="SKIPPED",
            error="No signature or signer in attestation",
        )

    try:
        return _verify_model_identity(
            tdx_quote_hex, ecdsa_signature, message_signer,
            model_signing_address, nonce, request_body, response_body,
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
    nonce: str,
    request_body: str,
    response_body: str,
) -> ModelIdentityVerificationResult:
    """Internal model identity verification — probes all signing formats."""
    declared = message_signer.lower()
    if not declared.startswith("0x"):
        declared = "0x" + declared

    sig = ecdsa_signature.lower()
    if not sig.startswith("0x"):
        sig = "0x" + sig

    total_formats = _count_formats(model_signing_address, nonce, request_body, response_body)
    recovery = _probe_all_formats(
        tdx_quote_hex, sig, model_signing_address, nonce,
        declared, request_body, response_body,
    )

    if recovery is None:
        has_io = bool(request_body or response_body)
        hint = "" if has_io else " Provide --request-body / --response-body to enable request+response formats."
        return ModelIdentityVerificationResult(
            status="SKIPPED",
            declared_address=declared,
            formats_tried=total_formats,
            error=f"Tried {total_formats} signing formats — none produced the declared signer address.{hint}",
        )

    detected_format, formats_tried = recovery

    return ModelIdentityVerificationResult(
        status="VERIFIED",
        signer_address=declared,
        declared_address=declared,
        addresses_match=True,
        detected_format=detected_format,
        formats_tried=formats_tried,
    )


def _probe_all_formats(
    quote_hex: str,
    signature: str,
    model_signing_address: str,
    nonce: str,
    declared_address: str,
    request_body: str,
    response_body: str,
) -> Optional[tuple]:
    """Try every known Ethereum signing format against the declared signer.

    Returns (format_label, attempts_count) if a format matches the declared
    address, or None if no format matches.
    """
    candidates = _build_candidates(quote_hex, model_signing_address, nonce, request_body, response_body)
    attempts = 0

    for label, strategy, data in candidates:
        attempts += 1
        recovered = _try_recover(strategy, data, signature)
        if recovered and recovered.lower() == declared_address.lower():
            logger.debug("Signature format identified: %s", label)
            return (label, attempts)

    return None


def _build_candidates(
    quote_hex: str,
    model_signing_address: str,
    nonce: str,
    request_body: str = "",
    response_body: str = "",
) -> list:
    """Build the full list of (label, strategy, data) candidates to probe.

    Strategies:
      "eip191_hexstr"  — encode_defunct(hexstr=data)      raw bytes + EIP-191 prefix
      "eip191_text"    — encode_defunct(text=data)         UTF-8 text + EIP-191 prefix
      "eip191_keccak"  — encode_defunct(primitive=data)    32-byte hash + EIP-191 prefix
      "raw_hash"       — Account._recover_hash(data)       raw 32-byte hash, no prefix
    """
    q_hex = quote_hex[2:] if quote_hex.startswith("0x") else quote_hex
    q_bytes = bytes.fromhex(q_hex)

    candidates = []

    # ── Group 1: Full TDX quote ───────────────────────────────────────────────
    candidates += [
        ("TDX quote — EIP-191 raw bytes",         "eip191_hexstr", q_hex),
        ("TDX quote — EIP-191 hex text",           "eip191_text",   quote_hex),
        ("TDX quote — EIP-191 + keccak256",        "eip191_keccak", _keccak256(q_bytes)),
        ("TDX quote — EIP-191 + sha256",           "eip191_keccak", _sha256(q_bytes)),
        ("TDX quote — raw keccak256 (no prefix)",  "raw_hash",      _keccak256(q_bytes)),
        ("TDX quote — raw sha256 (no prefix)",     "raw_hash",      _sha256(q_bytes)),
    ]

    # ── Group 2: model_signing_address (TDX report_data[0:32]) ───────────────
    if model_signing_address:
        m_hex = model_signing_address[2:] if model_signing_address.startswith("0x") else model_signing_address
        m_bytes = bytes.fromhex(m_hex)
        candidates += [
            ("model_signing_address — EIP-191 raw bytes",           "eip191_hexstr", m_hex),
            ("model_signing_address — EIP-191 hex text",            "eip191_text",   model_signing_address),
            ("model_signing_address — EIP-191 + keccak256",         "eip191_keccak", _keccak256(m_bytes)),
            ("model_signing_address — raw 32-byte hash (no prefix)","raw_hash",      m_bytes),
            ("model_signing_address — raw keccak256 (no prefix)",   "raw_hash",      _keccak256(m_bytes)),
        ]

    # ── Group 3: nonce (TDX report_data[32:64]) ───────────────────────────────
    if nonce:
        n_hex = nonce[2:] if nonce.startswith("0x") else nonce
        n_bytes = bytes.fromhex(n_hex)
        candidates += [
            ("nonce — EIP-191 raw bytes",             "eip191_hexstr", n_hex),
            ("nonce — EIP-191 hex text",               "eip191_text",   nonce),
            ("nonce — EIP-191 + keccak256",            "eip191_keccak", _keccak256(n_bytes)),
            ("nonce — raw 32-byte hash (no prefix)",   "raw_hash",      n_bytes),
            ("nonce — raw keccak256 (no prefix)",      "raw_hash",      _keccak256(n_bytes)),
        ]

    # ── Group 4: Combinations of attestation fields ───────────────────────────
    if model_signing_address and nonce:
        m_hex = model_signing_address[2:] if model_signing_address.startswith("0x") else model_signing_address
        n_hex = nonce[2:] if nonce.startswith("0x") else nonce
        m_bytes = bytes.fromhex(m_hex)
        n_bytes = bytes.fromhex(n_hex)
        candidates += [
            ("keccak256(model_addr+nonce) — EIP-191",      "eip191_keccak", _keccak256(m_bytes + n_bytes)),
            ("keccak256(nonce+model_addr) — EIP-191",      "eip191_keccak", _keccak256(n_bytes + m_bytes)),
            ("keccak256(model_addr+nonce) — raw hash",     "raw_hash",      _keccak256(m_bytes + n_bytes)),
            ("keccak256(nonce+model_addr) — raw hash",     "raw_hash",      _keccak256(n_bytes + m_bytes)),
            ("model_addr+nonce concat — EIP-191 raw bytes","eip191_hexstr", m_hex + n_hex),
        ]

    # ── Group 5: Request + response body formats (Phala-style) ───────────────
    if request_body or response_body:
        req_hash = hashlib.sha256(request_body.encode()).hexdigest() if request_body else ""
        resp_hash = hashlib.sha256(response_body.encode()).hexdigest() if response_body else ""

        if request_body and response_body:
            # Canonical Phala format: "sha256(request):sha256(response)"
            phala_text = f"{req_hash}:{resp_hash}"
            candidates += [
                ("sha256(request):sha256(response) — EIP-191 text",    "eip191_text",   phala_text),
                ("sha256(request):sha256(response) — EIP-191 keccak",  "eip191_keccak", _keccak256(phala_text.encode())),
                ("sha256(response):sha256(request) — EIP-191 text",    "eip191_text",   f"{resp_hash}:{req_hash}"),
            ]

        if request_body:
            req_bytes = request_body.encode()
            candidates += [
                ("sha256(request) — EIP-191 text",      "eip191_text",   req_hash),
                ("request body — EIP-191 raw text",     "eip191_text",   request_body),
                ("keccak256(request) — EIP-191",        "eip191_keccak", _keccak256(req_bytes)),
                ("keccak256(request) — raw hash",       "raw_hash",      _keccak256(req_bytes)),
                ("sha256(request) — raw hash",          "raw_hash",      bytes.fromhex(req_hash)),
            ]

        if response_body:
            resp_bytes = response_body.encode()
            candidates += [
                ("sha256(response) — EIP-191 text",     "eip191_text",   resp_hash),
                ("response body — EIP-191 raw text",    "eip191_text",   response_body),
                ("keccak256(response) — EIP-191",       "eip191_keccak", _keccak256(resp_bytes)),
                ("keccak256(response) — raw hash",      "raw_hash",      _keccak256(resp_bytes)),
                ("sha256(response) — raw hash",         "raw_hash",      bytes.fromhex(resp_hash)),
            ]

        if request_body and response_body:
            req_bytes = request_body.encode()
            resp_bytes = response_body.encode()
            candidates += [
                ("keccak256(request+response) — EIP-191",  "eip191_keccak", _keccak256(req_bytes + resp_bytes)),
                ("keccak256(response+request) — EIP-191",  "eip191_keccak", _keccak256(resp_bytes + req_bytes)),
                ("keccak256(request+response) — raw hash", "raw_hash",      _keccak256(req_bytes + resp_bytes)),
            ]

    return candidates


def _try_recover(strategy: str, data, signature: str) -> Optional[str]:
    """Attempt signature recovery for a single (strategy, data) pair."""
    try:
        if strategy == "eip191_hexstr":
            eth_msg = encode_defunct(hexstr=data)
            return Account.recover_message(eth_msg, signature=signature)

        elif strategy == "eip191_text":
            eth_msg = encode_defunct(text=data)
            return Account.recover_message(eth_msg, signature=signature)

        elif strategy == "eip191_keccak":
            eth_msg = encode_defunct(primitive=data)
            return Account.recover_message(eth_msg, signature=signature)

        elif strategy == "raw_hash":
            if isinstance(data, bytes) and len(data) == 32:
                return Account._recover_hash(data, signature=signature)

    except Exception as e:
        logger.debug("Recovery failed [%s]: %s", strategy, type(e).__name__)

    return None


def _count_formats(
    model_signing_address: str, nonce: str,
    request_body: str = "", response_body: str = "",
) -> int:
    """Return total number of formats that would be tried."""
    return len(_build_candidates("00" * 32, model_signing_address, nonce, request_body, response_body))


# ── Hashing helpers ───────────────────────────────────────────────────────────

def _keccak256(data: bytes) -> bytes:
    from eth_hash.auto import keccak
    return keccak(data)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
