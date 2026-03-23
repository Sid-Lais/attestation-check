"""End-to-end integration test using real OLLM attestation data."""

import json
from pathlib import Path

from tee_verify.formats.ollm import from_file
from tee_verify.verifier import verify_from_receipt, verify_composite

FIXTURES_DIR = Path(__file__).parent / "fixtures"
OLLM_JSON_PATH = FIXTURES_DIR / "real_ollm_request.json"

EXPECTED_NONCE = "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"


def test_full_composite_verification_offline():
    """Full composite verification in offline mode against real data."""
    receipt = from_file(OLLM_JSON_PATH)
    result = verify_from_receipt(receipt, offline=True)

    # TDX results
    assert result.tdx is not None
    assert result.tdx.mrtd != ""
    assert result.tdx.nonce == EXPECTED_NONCE
    assert result.tdx.tcb_status is not None

    # NVIDIA GPU results
    assert len(result.nvidia_gpus) == 8
    for i, gpu in enumerate(result.nvidia_gpus):
        assert gpu.gpu_index == i
        assert gpu.architecture == "HOPPER"
        assert gpu.nonce == EXPECTED_NONCE

    # Session binding
    assert result.nonce_binding_valid is True

    # Verified timestamp
    assert result.verified_at != ""


def test_json_output():
    """Composite result should serialize to valid JSON."""
    receipt = from_file(OLLM_JSON_PATH)
    result = verify_from_receipt(receipt, offline=True)

    json_str = result.to_json()
    parsed = json.loads(json_str)

    assert "overall_status" in parsed
    assert "tdx" in parsed
    assert "nvidia_gpus" in parsed
    assert "nonce_binding_valid" in parsed
    assert "verified_at" in parsed


def test_dict_output():
    """Composite result should convert to dict."""
    receipt = from_file(OLLM_JSON_PATH)
    result = verify_from_receipt(receipt, offline=True)

    d = result.to_dict()
    assert isinstance(d, dict)
    assert d["nonce_binding_valid"] is True


def test_tdx_only_verification():
    """TDX-only verification (no NVIDIA data) should work."""
    with open(OLLM_JSON_PATH) as f:
        data = json.load(f)

    tdx_hex = data["attestation"]["tdx"]["quote"]
    result = verify_composite(tdx_quote_hex=tdx_hex, offline=True)

    assert result.tdx is not None
    assert result.nvidia_gpus == []
    assert result.nonce_binding_valid is False


def test_no_data_fails():
    """No attestation data should produce FAILED."""
    result = verify_composite(offline=True)
    assert result.overall_status == "FAILED"
