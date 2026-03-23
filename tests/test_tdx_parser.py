"""Tests for TDX DCAP Quote v4 parser."""

import pytest
from pathlib import Path

from tee_verify.tdx.parser import parse_quote

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TDX_QUOTE_HEX = (FIXTURES_DIR / "tdx_quote.hex").read_text().strip()


def test_parse_quote_version():
    """Quote version must be 4 (TDX DCAP v4)."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert quote.version == 4


def test_parse_attest_key_type():
    """Attestation key type should be 2 (ECDSA-P256)."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert quote.attest_key_type == 2


def test_parse_mrtd():
    """MRTD (TD measurement) should be a 48-byte hex string."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.mrtd) == 96  # 48 bytes = 96 hex chars
    assert quote.mrtd.startswith("f06dfda6dce1cf90")


def test_parse_report_data():
    """Report data should be 64 bytes containing model signing key + nonce."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.report_data) == 128  # 64 bytes = 128 hex chars
    # Second 32 bytes should be the GPU attestation nonce
    nonce = quote.report_data[64:128]
    assert nonce == "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"


def test_parse_pck_certs():
    """PCK cert extraction from the quote (may be truncated in test data)."""
    quote = parse_quote(TDX_QUOTE_HEX)
    # The test fixture quote is truncated, so full PEM certs may not be present.
    # The parser should still succeed without them.
    assert isinstance(quote.pck_cert_chain, list)
    for cert in quote.pck_cert_chain:
        assert cert.startswith(b"-----BEGIN CERTIFICATE-----")


def test_parse_rtmrs():
    """All four RTMR values should be 48-byte hex strings."""
    quote = parse_quote(TDX_QUOTE_HEX)
    for rtmr_name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
        rtmr = getattr(quote, rtmr_name)
        assert len(rtmr) == 96, f"{rtmr_name} should be 96 hex chars"


def test_parse_raw_header():
    """Raw header should be exactly 48 bytes."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.raw_header) == 48


def test_parse_raw_td_body():
    """Raw TD body should be exactly 584 bytes."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.raw_td_body) == 584


def test_parse_signature():
    """ECDSA signature should be 64 bytes (r||s)."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.signature) == 64


def test_parse_attest_pub_key():
    """Attestation public key should be 64 bytes (x||y)."""
    quote = parse_quote(TDX_QUOTE_HEX)
    assert len(quote.attest_pub_key) == 64


def test_invalid_quote_raises():
    """Malformed input should raise ValueError."""
    with pytest.raises(ValueError):
        parse_quote("not-valid-hex")

    with pytest.raises(ValueError):
        parse_quote("deadbeef")  # too short

    with pytest.raises(ValueError):
        # Valid hex but wrong version
        bad = "0100" + "0" * 2600
        parse_quote(bad)


def test_parse_from_bytes():
    """Parser should accept raw bytes as well as hex strings."""
    raw = bytes.fromhex(TDX_QUOTE_HEX)
    quote = parse_quote(raw)
    assert quote.version == 4
    assert quote.mrtd.startswith("f06dfda6")
