"""CLI entry point for tee-verify."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tee_verify import __version__
from tee_verify.formats.ollm import from_file as load_ollm_receipt
from tee_verify.verifier import verify_composite, verify_from_receipt

_BANNER = f"""\
\033[1m{'=' * 50}
  tee-verify v{__version__}  |  by ORGN
{'=' * 50}\033[0m"""

import sys as _sys


# Use Unicode symbols on terminals that support them, ASCII fallback otherwise
def _supports_unicode():
    try:
        "\u2713".encode(_sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False

if _supports_unicode():
    _CHECK = "\033[32m\u2713\033[0m"
    _CROSS = "\033[31m\u2717\033[0m"
    _WARN = "\033[33m\u26a0\033[0m"
else:
    _CHECK = "\033[32m[PASS]\033[0m"
    _CROSS = "\033[31m[FAIL]\033[0m"
    _WARN = "\033[33m[WARN]\033[0m"


@click.command()
@click.argument("input_path", required=False)
@click.option("--tdx-quote", type=click.Path(exists=True), help="Path to TDX quote hex file")
@click.option("--nvidia-cert", type=click.Path(exists=True), help="Path to NVIDIA cert chain (base64)")
@click.option("--nvidia-evidence", type=click.Path(exists=True), help="Path to NVIDIA evidence (base64)")
@click.option("--ollm-json", type=click.Path(exists=True), help="Path to OLLM explorer JSON file")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--offline", is_flag=True, help="Skip online checks (Intel PCS, NVIDIA OCSP)")
@click.option("--verbose", is_flag=True, help="Show detailed output")
@click.version_option(version=__version__)
def verify(input_path, tdx_quote, nvidia_cert, nvidia_evidence, ollm_json, output, offline, verbose):
    """Independently verify TEE attestation receipts. No trust required.

    \b
    Examples:
      tee-verify --ollm-json receipt.json
      tee-verify --tdx-quote quote.hex
      tee-verify --tdx-quote quote.hex --nvidia-cert cert.b64 --nvidia-evidence ev.b64
      tee-verify --ollm-json receipt.json --offline
    """
    # Resolve input
    ollm_path = ollm_json or input_path

    if ollm_path:
        result = _verify_ollm(ollm_path, offline)
    elif tdx_quote:
        result = _verify_components(tdx_quote, nvidia_cert, nvidia_evidence, offline)
    else:
        click.echo("Error: provide --ollm-json, --tdx-quote, or a file path.", err=True)
        click.echo("Run 'tee-verify --help' for usage.", err=True)
        sys.exit(1)

    # Output
    if output == "json":
        click.echo(result.to_json())
    else:
        _print_text_result(result, verbose, offline)

    # Exit code
    sys.exit(0 if result.overall_status in ("VERIFIED", "TCB_OUT_OF_DATE") else 1)


def _verify_ollm(path, offline):
    """Verify from an OLLM receipt JSON file."""
    receipt = load_ollm_receipt(path)
    return verify_from_receipt(receipt, offline=offline)


def _verify_components(tdx_quote_path, nvidia_cert_path, nvidia_evidence_path, offline):
    """Verify from individual component files."""
    tdx_hex = Path(tdx_quote_path).read_text().strip()

    nvidia_certs = None
    nvidia_evidences = None
    if nvidia_cert_path and nvidia_evidence_path:
        cert_data = Path(nvidia_cert_path).read_text().strip()
        evidence_data = Path(nvidia_evidence_path).read_text().strip()
        nvidia_certs = [cert_data]
        nvidia_evidences = [evidence_data]

    return verify_composite(
        tdx_quote_hex=tdx_hex,
        nvidia_certs=nvidia_certs,
        nvidia_evidences=nvidia_evidences,
        offline=offline,
    )


def _print_text_result(result, verbose, offline):
    """Print human-readable verification result."""
    click.echo(_BANNER)
    click.echo()

    # TDX section
    if result.tdx:
        tdx = result.tdx
        status_icon = _CHECK if tdx.status != "FAILED" else _CROSS
        click.echo(f"  INTEL TDX                     {status_icon} {tdx.status}")
        if tdx.tcb_status:
            click.echo(f"    TCB Status                  {tdx.tcb_status}")
        click.echo(f"    MRTD                        {tdx.mrtd[:32]}...")
        if verbose and tdx.rtmr:
            for i, rtmr in enumerate(tdx.rtmr):
                click.echo(f"    RTMR[{i}]                     {rtmr[:32]}...")
        click.echo(f"    Report Data (nonce)         {tdx.nonce[:32]}...")
        click.echo(f"    Platform                    Genuine Intel TDX")
        if tdx.error:
            click.echo(f"    Error                       {tdx.error}")
        click.echo()

    # NVIDIA section
    if result.nvidia_gpus:
        gpus = result.nvidia_gpus
        all_ok = all(g.status != "FAILED" for g in gpus)
        status_icon = _CHECK if all_ok else _CROSS
        click.echo(f"  NVIDIA GPU CLUSTER            {status_icon} {'VERIFIED' if all_ok else 'FAILED'}")

        arch = gpus[0].architecture if gpus else "Unknown"
        click.echo(f"    Architecture                {arch}")
        click.echo(f"    GPU Count                   {len(gpus)}")

        valid_chains = sum(1 for g in gpus if g.cert_chain_valid)
        click.echo(f"    Cert Chains                 Valid ({valid_chains}/{len(gpus)})")

        # OCSP status (only show if not offline/skipped)
        good_ocsp = sum(1 for g in gpus if g.ocsp_status == "good")
        all_skipped = all(g.ocsp_status in ("skipped", "skipped (offline)") for g in gpus)
        if not all_skipped:
            if good_ocsp == len(gpus):
                click.echo(f"    OCSP Status                 Good ({good_ocsp}/{len(gpus)})")
            else:
                # Show status for non-good cases
                revoked = sum(1 for g in gpus if g.ocsp_status == "revoked")
                if revoked > 0:
                    click.echo(f"    OCSP Status                 Revoked ({revoked}/{len(gpus)})")
                else:
                    # Show first GPU's status for error/unknown
                    click.echo(f"    OCSP Status                 {gpus[0].ocsp_status.capitalize() if gpus else 'Unknown'}")

        valid_sigs = sum(1 for g in gpus if g.evidence_signature_valid)
        click.echo(f"    Evidence Signatures         {valid_sigs}/{len(gpus)} verified")

        click.echo(f"    {_WARN}  RIM validation           Phase 2 (not performed)")

        if verbose:
            for g in gpus:
                status_icon = _CHECK if g.status != "FAILED" else _CROSS
                click.echo(f"      GPU {g.gpu_index}: {status_icon} {g.status} "
                          f"(cert={g.cert_chain_valid}, ocsp={g.ocsp_status}, "
                          f"sig={g.evidence_signature_valid}, "
                          f"measurements={g.measurement_count})")
                if g.error:
                    click.echo(f"        Error: {g.error}")
        click.echo()

    # Binding section
    if result.tdx and result.nvidia_gpus:
        binding_icon = _CHECK if result.nonce_binding_valid else _CROSS
        binding_status = "VERIFIED" if result.nonce_binding_valid else "FAILED"
        click.echo(f"  SESSION BINDING               {binding_icon} {binding_status}")
        gpu_count = len(result.nvidia_gpus)
        match_text = f"Yes (all {gpu_count} GPUs)" if result.nonce_binding_valid else "No"
        click.echo(f"    TDX <-> GPU nonce match     {match_text}")
        click.echo()

    # Model identity section (Phase 3)
    if result.model_identity:
        model = result.model_identity
        status_icon = _CHECK if model.status == "VERIFIED" else _CROSS if model.status == "FAILED" else _WARN
        click.echo(f"  MODEL IDENTITY                {status_icon} {model.status}")
        if model.signer_address:
            click.echo(f"    Signature recoverable       Yes")
            click.echo(f"    Recovered signer            {model.signer_address}")
        if model.status == "SKIPPED":
            click.echo(f"    {_WARN}  Phase 3 Status: Signature is valid but needs message format specification")
            click.echo(f"         to verify signer authorization for this specific attestation.")
        elif model.status == "VERIFIED":
            click.echo(f"    Model signer verified       {model.declared_address}")
        if model.error and model.status not in ("SKIPPED",):
            click.echo(f"    Error                       {model.error}")
        click.echo()

    if offline:
        click.echo(f"  {_WARN}  Offline mode: Intel PCS and NVIDIA OCSP checks skipped")
        click.echo()

    # Final result
    click.echo("=" * 50)
    if result.overall_status == "VERIFIED":
        click.echo(f"  RESULT: {_CHECK} COMPOSITE VERIFIED")
    elif result.overall_status == "TCB_OUT_OF_DATE":
        click.echo(f"  RESULT: {_WARN} VERIFIED (TCB out of date)")
    else:
        click.echo(f"  RESULT: {_CROSS} VERIFICATION FAILED")
    click.echo("=" * 50)


def main():
    """Entry point."""
    verify()


if __name__ == "__main__":
    main()
