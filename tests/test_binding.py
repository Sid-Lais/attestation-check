"""Tests for session binding (nonce cross-check)."""

from tee_verify.binding import verify_nonce_binding
from tee_verify.models import TDXVerificationResult, NvidiaGPUVerificationResult

NONCE = "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"


def _make_tdx(nonce: str = NONCE) -> TDXVerificationResult:
    return TDXVerificationResult(
        status="VERIFIED",
        mrtd="f06dfda6" + "0" * 88,
        rtmr=["0" * 96] * 4,
        report_data="0" * 64 + nonce,
        nonce=nonce,
    )


def _make_gpu(index: int, nonce: str = NONCE) -> NvidiaGPUVerificationResult:
    return NvidiaGPUVerificationResult(
        status="VERIFIED",
        gpu_index=index,
        architecture="HOPPER",
        cert_chain_valid=True,
        ocsp_status="good",
        evidence_signature_valid=True,
        nonce=nonce,
        measurement_count=64,
    )


def test_nonce_match():
    """All GPUs match TDX nonce -> binding valid."""
    tdx = _make_tdx()
    gpus = [_make_gpu(i) for i in range(8)]
    valid, msg = verify_nonce_binding(tdx, gpus)
    assert valid is True
    assert "match" in msg.lower()


def test_nonce_mismatch_fails():
    """One GPU with different nonce -> binding fails."""
    tdx = _make_tdx()
    gpus = [_make_gpu(i) for i in range(8)]
    gpus[3] = _make_gpu(3, nonce="00" * 32)
    valid, msg = verify_nonce_binding(tdx, gpus)
    assert valid is False
    assert "GPU 3" in msg


def test_empty_gpu_list():
    """No GPUs -> binding fails."""
    tdx = _make_tdx()
    valid, msg = verify_nonce_binding(tdx, [])
    assert valid is False


def test_empty_tdx_nonce():
    """Empty TDX nonce -> binding fails."""
    tdx = _make_tdx(nonce="")
    gpus = [_make_gpu(0)]
    valid, msg = verify_nonce_binding(tdx, gpus)
    assert valid is False


def test_case_insensitive():
    """Nonce comparison should be case-insensitive."""
    tdx = _make_tdx(nonce=NONCE.upper())
    gpus = [_make_gpu(0, nonce=NONCE.lower())]
    valid, _ = verify_nonce_binding(tdx, gpus)
    assert valid is True


def test_single_gpu():
    """Single GPU match should succeed."""
    tdx = _make_tdx()
    gpus = [_make_gpu(0)]
    valid, msg = verify_nonce_binding(tdx, gpus)
    assert valid is True
    assert "n=1" in msg
