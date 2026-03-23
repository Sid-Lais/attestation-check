"""Tests for NVIDIA GPU attestation parser."""

import base64
from pathlib import Path

import pytest

from tee_verify.nvidia.parser import parse_cert_chain, parse_evidence

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Load GPU1 certificate from fixture
GPU1_CERT_PEM = (FIXTURES_DIR / "gpu1_cert.pem").read_bytes()
GPU1_CERT_B64 = base64.b64encode(GPU1_CERT_PEM).decode()

# Load GPU1 evidence from fixture
GPU1_EVIDENCE_BIN = (FIXTURES_DIR / "gpu1_evidence.bin").read_bytes()
GPU1_EVIDENCE_B64 = base64.b64encode(GPU1_EVIDENCE_BIN).decode()

EXPECTED_NONCE = "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"


def test_parse_cert_chain():
    """Should parse at least 1 certificate from the chain."""
    certs = parse_cert_chain(GPU1_CERT_B64)
    assert len(certs) >= 1


def test_cert_subject():
    """Leaf cert subject should contain NVIDIA fields."""
    certs = parse_cert_chain(GPU1_CERT_B64)
    subject = certs[0].subject.rfc4514_string()
    assert "NVIDIA" in subject


def test_parse_cert_from_raw_pem():
    """Should parse certificates from raw PEM bytes."""
    certs = parse_cert_chain(GPU1_CERT_PEM)
    assert len(certs) >= 1


def test_parse_evidence_nonce():
    """Evidence nonce should match expected value."""
    evidence = parse_evidence(GPU1_EVIDENCE_B64)
    assert evidence.nonce == EXPECTED_NONCE


def test_parse_evidence_from_bytes():
    """Should parse evidence from raw bytes."""
    evidence = parse_evidence(GPU1_EVIDENCE_BIN)
    assert evidence.nonce == EXPECTED_NONCE


def test_invalid_cert_raises():
    """Invalid certificate data should raise ValueError."""
    with pytest.raises(ValueError):
        parse_cert_chain(base64.b64encode(b"not a cert").decode())


def test_invalid_evidence_raises():
    """Evidence too short should raise ValueError."""
    with pytest.raises(ValueError):
        parse_evidence(base64.b64encode(b"ab").decode())
