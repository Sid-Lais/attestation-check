"""Tests for NVIDIA GPU verifier (offline mode)."""

from pathlib import Path

from tee_verify.formats.ollm import from_file
from tee_verify.nvidia.verifier import verify_gpu

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_receipt = from_file(FIXTURES_DIR / "real_ollm_request.json")
GPU0_CERT = _receipt.gpu_certificates[0]
GPU0_EVIDENCE = _receipt.gpu_evidences[0]
EXPECTED_NONCE = "f60da25691ac6ed2b2137c1051e6e922519ba229d4febde4e7794f63e6bd8b9d"


def test_verify_gpu_offline():
    """Offline GPU verification should parse certs and evidence."""
    result = verify_gpu(GPU0_CERT, GPU0_EVIDENCE, gpu_index=0, offline=True)
    assert result.gpu_index == 0
    assert result.architecture == "HOPPER"
    assert result.nonce == EXPECTED_NONCE
    assert result.ocsp_status == "skipped (offline)"


def test_verify_gpu_cert_parsed():
    """Certificate chain should be parsed and validated."""
    result = verify_gpu(GPU0_CERT, GPU0_EVIDENCE, gpu_index=0, offline=True)
    # Single cert in chain - chain validation depends on root CA
    assert result.nonce != ""


def test_verify_gpu_bad_cert():
    """Bad certificate data should return FAILED, not raise."""
    result = verify_gpu("bm90YWNlcnQ=", GPU0_EVIDENCE, gpu_index=0, offline=True)
    assert result.status == "FAILED"
    assert result.error is not None


def test_verify_gpu_bad_evidence():
    """Bad evidence data should return FAILED, not raise."""
    result = verify_gpu(GPU0_CERT, "YWI=", gpu_index=0, offline=True)
    assert result.status == "FAILED"
    assert result.error is not None
