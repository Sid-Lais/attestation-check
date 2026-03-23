"""Tests for the OLLM receipt adapter."""

import json
from pathlib import Path

import pytest

from tee_verify.formats.ollm import from_file, from_dict, from_request_id

FIXTURES_DIR = Path(__file__).parent / "fixtures"
OLLM_JSON_PATH = FIXTURES_DIR / "real_ollm_request.json"


def test_from_file():
    """Load and parse OLLM receipt from file."""
    receipt = from_file(OLLM_JSON_PATH)
    assert receipt.request_id == "chatcmpl-8570e42b12e990bd"
    assert receipt.tdx_quote_hex != ""
    assert len(receipt.gpu_certificates) == 8
    assert len(receipt.gpu_evidences) == 8
    assert receipt.nvidia_nonce == "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"
    assert receipt.nvidia_architecture == "HOPPER"


def test_from_dict():
    """Parse receipt from a dictionary."""
    with open(OLLM_JSON_PATH) as f:
        data = json.load(f)
    receipt = from_dict(data)
    assert receipt.request_id == "chatcmpl-8570e42b12e990bd"
    assert receipt.tdx_quote_hex.startswith("04000200")


def test_message_signature_fields():
    """Message signature fields should be extracted."""
    receipt = from_file(OLLM_JSON_PATH)
    assert receipt.ecdsa_signature.startswith("0x")
    assert receipt.message_signer.startswith("0x")


def test_from_file_not_found():
    """Missing file should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        from_file("/nonexistent/receipt.json")


def test_from_request_id_not_implemented():
    """Direct fetch is not supported yet."""
    with pytest.raises(NotImplementedError):
        from_request_id("chatcmpl-test123")


def test_from_dict_empty():
    """Empty dict should return receipt with empty fields."""
    receipt = from_dict({})
    assert receipt.tdx_quote_hex == ""
    assert receipt.gpu_certificates == []
