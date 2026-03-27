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
@click.option("--request-body", type=click.Path(exists=True), help="Path to request body file (for model identity verification)")
@click.option("--response-body", type=click.Path(exists=True), help="Path to response body file (for model identity verification)")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--offline", is_flag=True, help="Skip online checks (Intel PCS, NVIDIA OCSP)")
@click.option("--verbose", is_flag=True, help="Show detailed output")
@click.version_option(version=__version__)
def verify(input_path, tdx_quote, nvidia_cert, nvidia_evidence, ollm_json, request_body, response_body, output, offline, verbose):
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
        result = _verify_ollm(ollm_path, offline, request_body, response_body)
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


def _verify_ollm(path, offline, request_body_path=None, response_body_path=None):
    """Verify from an OLLM receipt JSON file."""
    receipt = load_ollm_receipt(path)
    request_body = Path(request_body_path).read_text(encoding="utf-8") if request_body_path else ""
    response_body = Path(response_body_path).read_text(encoding="utf-8") if response_body_path else ""
    return verify_from_receipt(receipt, offline=offline, request_body=request_body, response_body=response_body)


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
        if tdx.tee_tcb_svn:
            click.echo(f"    TEE TCB SVN                 {tdx.tee_tcb_svn}")
        if tdx.ppid:
            click.echo(f"    PPID                        {tdx.ppid}")
        click.echo(f"    MRTD                        {tdx.mrtd[:32]}...")
        if verbose:
            if tdx.mrseam:
                click.echo(f"    MRSEAM                      {tdx.mrseam[:32]}...")
            if tdx.mrconfigid:
                click.echo(f"    MRCONFIG                    {tdx.mrconfigid[:32]}...")
            if tdx.mrowner and tdx.mrowner != '0' * len(tdx.mrowner):
                click.echo(f"    MROWNER                     {tdx.mrowner[:32]}...")
            if tdx.rtmr:
                for i, rtmr in enumerate(tdx.rtmr):
                    click.echo(f"    RTMR[{i}]                     {rtmr[:32]}...")
            if tdx.user_data:
                click.echo(f"    User Data                   {tdx.user_data}")
        click.echo(f"    Report Data                 {tdx.report_data[:64]}...")
        click.echo(f"    Nonce (report_data[32:64])  {tdx.nonce[:32]}...")
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
        all_skipped = all(g.ocsp_status in ("skipped", "skipped (offline)", "skipped (no AIA)") for g in gpus)
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

        # Driver RIM validation summary
        rim_attempted = [g for g in gpus if g.rim_valid is not None]
        rim_passed = [g for g in rim_attempted if g.rim_valid is True]
        rim_failed = [g for g in rim_attempted if g.rim_valid is False]
        if rim_attempted:
            if rim_failed:
                click.echo(f"    Driver RIM                  {_CROSS} {len(rim_failed)}/{len(gpus)} failed")
            else:
                click.echo(f"    Driver RIM                  {_CHECK} {len(rim_passed)}/{len(gpus)} passed")
        else:
            first_rim_status = gpus[0].rim_status if gpus else "skipped"
            click.echo(f"    Driver RIM                  {_WARN} {first_rim_status.capitalize()}")

        # VBIOS RIM validation summary
        vbios_attempted = [g for g in gpus if g.vbios_rim_valid is not None]
        vbios_passed = [g for g in vbios_attempted if g.vbios_rim_valid is True]
        vbios_failed = [g for g in vbios_attempted if g.vbios_rim_valid is False]
        if vbios_attempted:
            if vbios_failed:
                click.echo(f"    VBIOS RIM                   {_CROSS} {len(vbios_failed)}/{len(gpus)} failed")
            else:
                click.echo(f"    VBIOS RIM                   {_CHECK} {len(vbios_passed)}/{len(gpus)} passed")
        else:
            first_vbios_status = gpus[0].vbios_rim_status if gpus else "skipped"
            click.echo(f"    VBIOS RIM                   {_WARN} {first_vbios_status.capitalize()}")

        if verbose:
            for g in gpus:
                status_icon = _CHECK if g.status != "FAILED" else _CROSS
                rim_str = g.rim_status if g.rim_status else "skipped"
                vbios_str = g.vbios_rim_status if g.vbios_rim_status else "skipped"
                click.echo(f"      GPU {g.gpu_index}: {status_icon} {g.status} "
                          f"(cert={g.cert_chain_valid}, ocsp={g.ocsp_status}, "
                          f"sig={g.evidence_signature_valid}, "
                          f"measurements={g.measurement_count}, "
                          f"driver_rim={rim_str}, vbios_rim={vbios_str})")
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
        if model.status == "VERIFIED":
            click.echo(f"    Signer verified             {model.declared_address}")
            click.echo(f"    Signing format              {model.detected_format}")
            if model.formats_tried:
                click.echo(f"    Formats tried               {model.formats_tried}")
        elif model.status == "SKIPPED":
            if model.formats_tried:
                click.echo(f"    Formats tried               {model.formats_tried}")
                click.echo(f"    {_WARN}  None of {model.formats_tried} formats matched the declared signer")
                if model.error and "--request-body" in model.error:
                    click.echo(f"         Run with --request-body and --response-body to enable request+response formats")
            else:
                click.echo(f"    {_WARN}  No signature data in attestation")
        elif model.status == "FAILED":
            click.echo(f"    Recovered signer            {model.signer_address}")
            click.echo(f"    Declared signer             {model.declared_address}")
            if model.detected_format:
                click.echo(f"    Signing format              {model.detected_format}")
            if model.error:
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
