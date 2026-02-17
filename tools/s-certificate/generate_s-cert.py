#!/usr/bin/env python3

"""
    Generate server certificates signed by your own Certificate Authority,
    with optional upload to F5 Distributed Cloud (XC).

    Local-only usage (generates .p12):
        python generate_s-cert.py <domain>

    Generate and upload to XC (then create .p12):
        python generate_s-cert.py <domain> --xc

    Upload to XC only, skip .p12:
        python generate_s-cert.py <domain> --xc --no-p12

    With custom config:
        python generate_s-cert.py <domain> --xc --config /path/to/config.yaml

    Before first use, create your CA files in the ca/ directory:
        mkdir -p ca
        openssl genrsa -out ca/ca.key 4096
        openssl req -new -x509 -days 3650 -key ca/ca.key -out ca/ca.cer

    Then copy etc/config.yaml.bk to etc/config.yaml and fill in your values.
"""

import argparse
import base64
import json
import os
import subprocess
import sys

import yaml
import requests


# ---------------------------------------------------------------------------
# Defaults (used when no config file is present)
# ---------------------------------------------------------------------------

MYDIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_CONFIG = os.path.join(MYDIR, "etc", "config.yaml")

OPENSSL_CONFIG_TEMPLATE = """\
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C                      = %(country)s
ST                     = %(state)s
L                      = %(locality)s
O                      = %(organization)s
OU                     = %(organizational_unit)s
CN                     = %(domain)s
emailAddress           = %(email)s

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = %(domain)s
DNS.2 = *.%(domain)s
"""

# Extra X509 args. Consider using e.g. ('-passin', 'pass:blah') if your
# CA password is 'blah'. For more information, see:
# http://www.openssl.org/docs/apps/openssl.html#PASS_PHRASE_ARGUMENTS
X509_EXTRA_ARGS = ()


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(config_path):
    """Load and return the YAML config, or exit with an error."""
    if not os.path.isfile(config_path):
        print(f"Error: Config file not found: {config_path}")
        print("Copy etc/config.yaml.bk to etc/config.yaml and fill in your values.")
        sys.exit(1)

    with open(config_path, "r") as fh:
        cfg = yaml.safe_load(fh)

    if not cfg:
        print(f"Error: Config file is empty: {config_path}")
        sys.exit(1)

    return cfg


def get_cert_config(cfg):
    """Extract certificate generation settings from config."""
    cert = cfg.get("certificate", {})
    return {
        "openssl_bin": cert.get("openssl_bin", "/usr/bin/openssl"),
        "key_size": cert.get("key_size", 2048),
        "validity_days": cert.get("validity_days", 365),
        "ca_cert": cert.get("ca_cert", "ca/ca.cer"),
        "ca_key": cert.get("ca_key", "ca/ca.key"),
        "output_dir": cert.get("output_dir", "domains"),
        "dn": cert.get("distinguished_name", {}),
    }


def get_xc_config(cfg):
    """Extract and validate XC settings from config."""
    xc = cfg.get("xc", {})

    tenant = xc.get("tenant", "")
    api_token = xc.get("api_token", "")
    api_url_template = xc.get("api_url_template", "https://%s.console.ves.volterra.io")
    namespace = xc.get("namespace", "default")
    api_endpoint = xc.get("api_endpoint", "/api/config/namespaces/%s/certificates")
    cert_name_prefix = xc.get("cert_name_prefix", "lab-cert")
    cert_description = xc.get("cert_description", "Auto-generated server certificate for %s")

    if not tenant or tenant == "your-tenant-name":
        print("Error: XC tenant name not configured in config.yaml.")
        sys.exit(1)
    if not api_token or "REPLACE" in api_token:
        print("Error: XC API token not configured in config.yaml.")
        sys.exit(1)

    base_url = api_url_template % tenant
    endpoint = api_endpoint % namespace

    return {
        "tenant": tenant,
        "api_token": api_token,
        "base_url": base_url,
        "namespace": namespace,
        "endpoint": endpoint,
        "cert_name_prefix": cert_name_prefix,
        "cert_description": cert_description,
    }


# ---------------------------------------------------------------------------
# OpenSSL helpers
# ---------------------------------------------------------------------------

def run_openssl(openssl_bin, *args):
    """Run an openssl command, raising on failure."""
    cmdline = [openssl_bin] + list(args)
    subprocess.check_call(cmdline)


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def generate_pem(domain, cert_cfg):
    """
    Generate a PEM private key and signed certificate.

    Returns a dict with paths: {"key": ..., "cert": ...}
    Intermediate files (CSR, config) are cleaned up.
    """
    openssl_bin = cert_cfg["openssl_bin"]
    key_size = cert_cfg["key_size"]
    days = cert_cfg["validity_days"]
    ca_cert = cert_cfg["ca_cert"]
    ca_key = cert_cfg["ca_key"]
    output_dir = cert_cfg["output_dir"]
    dn = cert_cfg["dn"]

    os.chdir(MYDIR)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    def dfile(ext):
        return os.path.join(output_dir, "%s.%s" % (domain, ext))

    # --- Generate private key ---
    if not os.path.exists(dfile("key")):
        run_openssl(openssl_bin, "genrsa", "-out", dfile("key"), str(key_size))

    # --- Write OpenSSL config ---
    template_vars = {
        "domain": domain,
        "country": dn.get("country", "XX"),
        "state": dn.get("state", "State"),
        "locality": dn.get("locality", "City"),
        "organization": dn.get("organization", "Org"),
        "organizational_unit": dn.get("organizational_unit", "Unit"),
        "email": dn.get("email", "admin@example.com"),
    }
    with open(dfile("config"), "w") as fh:
        fh.write(OPENSSL_CONFIG_TEMPLATE % template_vars)

    # --- Create CSR ---
    run_openssl(openssl_bin,
                "req", "-new",
                "-key", dfile("key"),
                "-out", dfile("request"),
                "-config", dfile("config"))

    # --- Sign with CA ---
    run_openssl(openssl_bin,
                "x509", "-req",
                "-days", str(days),
                "-in", dfile("request"),
                "-CA", ca_cert,
                "-CAkey", ca_key,
                "-CAcreateserial",
                "-out", dfile("cert"),
                "-extensions", "v3_req",
                "-extfile", dfile("config"),
                *X509_EXTRA_ARGS)

    # --- Cleanup intermediate files ---
    os.remove(dfile("request"))
    os.remove(dfile("config"))

    return {"key": dfile("key"), "cert": dfile("cert")}


def create_p12(domain, cert_cfg):
    """
    Package the PEM key + cert into a password-protected .p12 bundle.

    Expects the .key and .cert files to already exist in output_dir.
    Returns the path to the .p12 file.
    """
    openssl_bin = cert_cfg["openssl_bin"]
    output_dir = cert_cfg["output_dir"]

    os.chdir(MYDIR)

    def dfile(ext):
        return os.path.join(output_dir, "%s.%s" % (domain, ext))

    run_openssl(openssl_bin,
                "pkcs12", "-export",
                "-inkey", dfile("key"),
                "-in", dfile("cert"),
                "-out", dfile("p12"))

    return dfile("p12")


def cleanup_pem_files(pem_files):
    """Remove PEM key and cert files."""
    for path in pem_files.values():
        if path and os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------------------
# F5 XC upload
# ---------------------------------------------------------------------------

def upload_to_xc(domain, cert_files, xc_cfg):
    """
    Upload the certificate and private key to F5 Distributed Cloud.

    Uses the XC certificate API:
        POST {base_url}/api/config/namespaces/{ns}/certificates

    The certificate and key are sent as base64-encoded PEM via
    clear_secret_info (suitable for lab/demo environments).
    """
    cert_path = cert_files["cert"]
    key_path = cert_files["key"]

    if not cert_path or not key_path:
        print("Error: PEM cert/key files not available for upload.")
        sys.exit(1)

    # Read PEM contents
    with open(cert_path, "r") as fh:
        cert_pem = fh.read()
    with open(key_path, "r") as fh:
        key_pem = fh.read()

    # Base64-encode for the API payload
    cert_b64 = base64.b64encode(cert_pem.encode()).decode()
    key_b64 = base64.b64encode(key_pem.encode()).decode()

    # Build XC object name from prefix + domain (XC only allows lowercase + hyphens)
    safe_domain = domain.lower().replace(".", "-")
    obj_name = "%s-%s" % (xc_cfg["cert_name_prefix"], safe_domain)
    description = xc_cfg["cert_description"] % domain

    url = "%s%s" % (xc_cfg["base_url"], xc_cfg["endpoint"])

    payload = {
        "metadata": {
            "name": obj_name,
            "namespace": xc_cfg["namespace"],
            "description": description,
            "disable": False,
        },
        "spec": {
            "certificate_url": "string:///%s" % cert_b64,
            "private_key": {
                "clear_secret_info": {
                    "url": "string:///%s" % key_b64,
                    "provider": "",
                },
            },
        },
    }

    headers = {
        "Authorization": "APIToken %s" % xc_cfg["api_token"],
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    print("\nUploading certificate to F5 XC...")
    print("  Tenant:    %s" % xc_cfg["tenant"])
    print("  Namespace: %s" % xc_cfg["namespace"])
    print("  Object:    %s" % obj_name)
    print("  Endpoint:  %s" % url)

    resp = None
    try:
        resp = requests.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        print("\nSuccess — certificate '%s' created in XC." % obj_name)
    except requests.exceptions.HTTPError as exc:
        print("\nError uploading to XC: %s" % exc)
        if resp is not None:
            try:
                detail = resp.json()
                print("  Response: %s" % json.dumps(detail, indent=2))
            except Exception:
                print("  Response body: %s" % resp.text)
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        print("\nConnection error: %s" % exc)
        print("Check the tenant name and network connectivity.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate server certificates signed by your own CA, "
                    "with optional upload to F5 Distributed Cloud.",
        epilog="Examples:\n"
               "  %(prog)s myapp.example.com\n"
               "  %(prog)s myapp.example.com --xc\n"
               "  %(prog)s myapp.example.com --xc --no-p12\n"
               "  %(prog)s myapp.example.com --xc --config /path/to/config.yaml\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        help="Domain name to generate a certificate for",
    )
    parser.add_argument(
        "--xc",
        action="store_true",
        default=False,
        help="Upload the certificate to F5 Distributed Cloud after generation",
    )
    parser.add_argument(
        "--no-p12",
        action="store_true",
        default=False,
        help="Skip .p12 bundle creation (useful with --xc when only uploading)",
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG,
        help="Path to YAML config file (default: etc/config.yaml)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    domain = args.domain
    upload_xc = args.xc
    skip_p12 = args.no_p12

    # Load config
    cfg = load_config(args.config)
    cert_cfg = get_cert_config(cfg)

    # Step 1: Generate PEM key + signed certificate
    print("Generating certificate for: %s" % domain)
    pem_files = generate_pem(domain, cert_cfg)
    print("PEM files created: %s, %s" % (pem_files["cert"], pem_files["key"]))

    # Step 2: Upload to XC if requested (before .p12, no passphrase needed)
    if upload_xc:
        xc_cfg = get_xc_config(cfg)
        upload_to_xc(domain, pem_files, xc_cfg)

    # Step 3: Create .p12 bundle (prompts for passphrase) unless skipped
    if not skip_p12:
        p12_path = create_p12(domain, cert_cfg)
        print("Done — .p12 file: %s" % p12_path)
    else:
        print("Skipped .p12 creation (--no-p12).")

    # Step 4: Clean up PEM files
    cleanup_pem_files(pem_files)
    print("Local PEM files cleaned up.")


if __name__ == "__main__":
    main()
