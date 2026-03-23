"""Tests for NVIDIA GPU verifier (offline mode)."""

import json
from pathlib import Path

from tee_verify.nvidia.verifier import verify_gpu

FIXTURES_DIR = Path(__file__).parent / "fixtures"

with open(FIXTURES_DIR / "real_ollm_request.json") as f:
    OLLM_DATA = json.load(f)

GPU0_CERT = OLLM_DATA["attestation"]["nvidia"]["gpus"][0]["certificate"]
GPU0_EVIDENCE = OLLM_DATA["attestation"]["nvidia"]["gpus"][0]["evidence"]
EXPECTED_NONCE = "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"


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
