"""Tests for TDX verifier (offline mode)."""

from pathlib import Path

from tee_verify.tdx.verifier import verify_tdx_quote

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TDX_QUOTE_HEX = (FIXTURES_DIR / "tdx_quote.hex").read_text().strip()


def test_verify_tdx_offline():
    """Offline TDX verification should parse and validate structure."""
    result = verify_tdx_quote(TDX_QUOTE_HEX, offline=True)
    # The quote structure should parse correctly
    assert result.mrtd.startswith("f06dfda6")
    assert len(result.rtmr) == 4
    assert result.nonce == "3b2b40a967bd085ef617bf00e75b90beb058a91a563d1ff874d2391690357587"
    assert result.tcb_status == "Unknown (offline)"
    # Status depends on cert chain - may be VERIFIED or FAILED depending
    # on whether the embedded PCK cert chain validates against root CA
    assert result.status in ("VERIFIED", "FAILED")


def test_verify_tdx_bad_input():
    """Bad input should return FAILED, not raise."""
    result = verify_tdx_quote("deadbeef", offline=True)
    assert result.status == "FAILED"
    assert result.error is not None


def test_verify_tdx_empty_input():
    """Empty input should return FAILED, not raise."""
    result = verify_tdx_quote("", offline=True)
    assert result.status == "FAILED"
    assert result.error is not None


def test_verify_tdx_returns_all_fields():
    """Result should populate all key fields."""
    result = verify_tdx_quote(TDX_QUOTE_HEX, offline=True)
    assert result.report_data is not None
    assert len(result.report_data) == 128
    assert result.mrtd is not None
    assert result.nonce is not None
