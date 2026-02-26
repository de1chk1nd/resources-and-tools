"""CLI entry point for s-certificate."""

import argparse
import os
import re
import sys

from s_certificate.config import load_config, parse_cert_config, parse_xc_config
from s_certificate.openssl import generate_pem, create_p12, cleanup_pem_files, prompt_ca_generation
from s_certificate.xc_upload import upload_to_xc


# Valid hostname: labels separated by dots, each label is alphanumeric (+ hyphens),
# no leading/trailing hyphens, max 253 chars total, max 63 chars per label.
_DOMAIN_RE = re.compile(
    r"^(?!-)"                                                  # no leading hyphen
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # labels
    r"[a-zA-Z]{2,63}$"                                        # TLD
)


MYDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CONFIG = os.path.join(MYDIR, "config", "config.yaml")


def validate_domain(domain: str) -> str:
    """
    Validate that a domain name contains only legal hostname characters.

    Returns the domain unchanged on success, or exits with an error.
    """
    if len(domain) > 253:
        print(f"Error: Domain name too long (max 253 chars): {domain}")
        sys.exit(1)

    if not _DOMAIN_RE.match(domain):
        print(f"Error: Invalid domain name: {domain}")
        print("  Domain must be a valid hostname (e.g. app.example.com).")
        sys.exit(1)

    return domain


def load_domain_list(path: str) -> list[str]:
    """
    Read a domain list file.

    Returns a list of domains. Blank lines and lines starting with # are skipped.
    """
    if not os.path.isfile(path):
        print(f"Error: Domain list file not found: {path}")
        sys.exit(1)

    domains: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                domains.append(stripped)

    if not domains:
        print(f"Error: Domain list file is empty: {path}")
        sys.exit(1)

    return domains


def process_domain(
    domain: str,
    cert_cfg,
    xc_cfg,
    *,
    upload_xc: bool,
    skip_p12: bool,
) -> bool:
    """
    Generate a certificate for a single domain.

    Returns True on success, False on failure.
    """
    try:
        print(f"\nGenerating certificate for: {domain}")
        pem_files = generate_pem(domain, cert_cfg, base_dir=MYDIR)
        print(f"  PEM files created: {pem_files['cert']}, {pem_files['key']}")

        if upload_xc:
            upload_to_xc(domain, pem_files, xc_cfg)

        if not skip_p12:
            p12_path = create_p12(domain, cert_cfg, base_dir=MYDIR)
            print(f"  .p12 file: {p12_path}")
        else:
            print("  Skipped .p12 creation (--no-p12).")

        cleanup_pem_files(pem_files)
        print("  PEM files cleaned up.")
        return True

    except Exception as exc:
        print(f"  Error processing {domain}: {exc}")
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Generate server certificates signed by your own CA, "
                    "with optional upload to F5 Distributed Cloud.",
        epilog="Examples:\n"
               "  %(prog)s myapp.example.com\n"
               "  %(prog)s myapp.example.com -xc\n"
               "  %(prog)s myapp.example.com --xc-upload --no-p12\n"
               "  %(prog)s --domains config/domains.txt\n"
               "  %(prog)s --domains config/domains.txt -xc --no-p12\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="Domain name to generate a certificate for",
    )
    parser.add_argument(
        "--domains", "-d",
        default=None,
        metavar="FILE",
        help="Path to a file with domain names (one per line)",
    )
    parser.add_argument(
        "--xc-upload", "-xc",
        action="store_true",
        default=False,
        dest="xc_upload",
        help="Upload the certificate to F5 Distributed Cloud after generation",
    )
    parser.add_argument(
        "--no-p12",
        action="store_true",
        default=False,
        help="Skip .p12 bundle creation (useful with --xc-upload when only uploading)",
    )
    parser.add_argument(
        "--namespace", "-n",
        default=None,
        help="XC namespace override (only with --xc-upload; default: from config.yaml)",
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG,
        help="Path to YAML config file (default: config/config.yaml)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    upload_xc = args.xc_upload
    skip_p12 = args.no_p12
    ns_override = args.namespace

    # --- Resolve domain list ------------------------------------------------
    if args.domains and args.domain:
        print("Error: Provide either a domain argument or --domains, not both.")
        sys.exit(1)

    if args.domains:
        domains = load_domain_list(args.domains)
    elif args.domain:
        domains = [args.domain]
    else:
        print("Error: Provide a domain argument or --domains <file>.")
        sys.exit(1)

    # Validate all domain names before processing
    for domain in domains:
        validate_domain(domain)

    # --namespace only makes sense with --xc-upload
    if ns_override and not upload_xc:
        print("Error: --namespace / -n requires --xc-upload.")
        sys.exit(1)

    # --- Load config --------------------------------------------------------
    cfg = load_config(args.config)
    cert_cfg = parse_cert_config(cfg)

    xc_cfg = None
    if upload_xc:
        xc_cfg = parse_xc_config(cfg)
        if ns_override:
            xc_cfg.namespace = ns_override

    # --- Check for CA -------------------------------------------------------
    prompt_ca_generation(cert_cfg, base_dir=MYDIR)

    # --- Process domains ----------------------------------------------------
    total = len(domains)
    succeeded = 0
    failed = 0

    if total > 1:
        print(f"\nProcessing {total} domains...")

    for domain in domains:
        ok = process_domain(
            domain,
            cert_cfg,
            xc_cfg,
            upload_xc=upload_xc,
            skip_p12=skip_p12,
        )
        if ok:
            succeeded += 1
        else:
            failed += 1

    # --- Summary ------------------------------------------------------------
    if total > 1:
        print(f"\nDone — {succeeded}/{total} succeeded", end="")
        if failed:
            print(f", {failed} failed", end="")
        print(".")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
