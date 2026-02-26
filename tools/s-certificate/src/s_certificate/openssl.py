"""OpenSSL helpers for certificate generation."""

import os
import subprocess
import sys

from s_certificate.config import CertConfig, DistinguishedName


OPENSSL_CONFIG_TEMPLATE = """\
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C                      = {country}
ST                     = {state}
L                      = {locality}
O                      = {organization}
OU                     = {organizational_unit}
CN                     = {domain}
emailAddress           = {email}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = {domain}
DNS.2 = *.{domain}
"""


def run_openssl(openssl_bin: str, *args: str) -> None:
    """Run an openssl command, raising on failure.

    Stdout and stderr are captured to keep normal output clean.
    On failure, stderr is included in the raised exception message.
    """
    cmdline = [openssl_bin, *args]
    result = subprocess.run(
        cmdline,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"OpenSSL command failed (exit {result.returncode}): "
            f"{' '.join(cmdline)}\n{stderr}"
        )


CA_CONFIG_TEMPLATE = """\
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C                      = {country}
ST                     = {state}
L                      = {locality}
O                      = {organization}
OU                     = {organizational_unit}
emailAddress           = {email}
CN                     = {organization} CA
"""


def _resolve(base_dir: str, path: str) -> str:
    """Resolve a potentially relative path against base_dir."""
    if os.path.isabs(path):
        return path
    return os.path.join(base_dir, path)


def check_ca(cert_cfg: CertConfig, base_dir: str) -> bool:
    """
    Check whether the CA key and certificate exist.

    Returns True if both files are present, False otherwise.
    """
    ca_key = _resolve(base_dir, cert_cfg.ca_key)
    ca_cert = _resolve(base_dir, cert_cfg.ca_cert)
    return os.path.isfile(ca_key) and os.path.isfile(ca_cert)


def generate_ca(cert_cfg: CertConfig, base_dir: str) -> None:
    """
    Generate a new CA key and self-signed CA certificate.

    Uses ca.key_size (default 4096) and ca.validity_days (default 3650).
    The CA distinguished name falls back to the certificate DN if not
    explicitly configured under certificate.ca.distinguished_name.
    """
    ca_key = _resolve(base_dir, cert_cfg.ca_key)
    ca_cert = _resolve(base_dir, cert_cfg.ca_cert)

    ca_dir = os.path.dirname(ca_key)
    if ca_dir and not os.path.exists(ca_dir):
        os.makedirs(ca_dir)

    ca_cfg = cert_cfg.ca
    dn = ca_cfg.dn if ca_cfg.dn is not None else cert_cfg.dn

    print(f"\nGenerating CA key ({ca_cfg.key_size} bit)...")
    run_openssl(
        cert_cfg.openssl_bin,
        "genrsa", "-out", ca_key, str(ca_cfg.key_size),
    )

    # Write a temporary config so the CA cert gets a proper subject
    # without an interactive prompt
    ca_config_path = ca_key + ".cnf"
    config_content = CA_CONFIG_TEMPLATE.format(
        country=dn.country,
        state=dn.state,
        locality=dn.locality,
        organization=dn.organization,
        organizational_unit=dn.organizational_unit,
        email=dn.email,
    )
    with open(ca_config_path, "w", encoding="utf-8") as fh:
        fh.write(config_content)

    print(f"Generating CA certificate (valid {ca_cfg.validity_days} days)...")
    run_openssl(
        cert_cfg.openssl_bin,
        "req", "-new", "-x509",
        "-days", str(ca_cfg.validity_days),
        "-key", ca_key,
        "-out", ca_cert,
        "-config", ca_config_path,
    )

    # Cleanup temporary config
    os.remove(ca_config_path)

    print(f"CA created:")
    print(f"  Key:  {ca_key}")
    print(f"  Cert: {ca_cert}")


def prompt_ca_generation(cert_cfg: CertConfig, base_dir: str) -> None:
    """
    Check for CA files. If missing, prompt the user to auto-generate or exit.

    Called before certificate generation to ensure the CA is available.
    """
    if check_ca(cert_cfg, base_dir):
        return

    ca_key = _resolve(base_dir, cert_cfg.ca_key)
    ca_cert = _resolve(base_dir, cert_cfg.ca_cert)

    print(f"CA not found at: {ca_key}, {ca_cert}")
    print()
    print("The tool can auto-generate a CA for you, or you can create one manually.")
    print()

    ca_cfg = cert_cfg.ca
    dn = ca_cfg.dn if ca_cfg.dn is not None else cert_cfg.dn
    print(f"  Auto-generate settings:")
    print(f"    Key size:    {ca_cfg.key_size} bit")
    print(f"    Validity:    {ca_cfg.validity_days} days")
    print(f"    Subject:     C={dn.country}, ST={dn.state}, L={dn.locality}, "
          f"O={dn.organization}, OU={dn.organizational_unit}")
    print()

    try:
        answer = input("Generate CA now? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        answer = ""

    if answer in ("y", "yes"):
        generate_ca(cert_cfg, base_dir)
        print()
    else:
        print()
        print("CA generation skipped. Create the CA manually before running again:")
        print()
        print(f"  mkdir -p {os.path.dirname(ca_key)}")
        print(f"  openssl genrsa -out {ca_key} {ca_cfg.key_size}")
        print(f"  openssl req -new -x509 -days {ca_cfg.validity_days} "
              f"-key {ca_key} -out {ca_cert}")
        print()
        sys.exit(1)


def _domain_file(output_dir: str, domain: str, ext: str) -> str:
    """Return the path for a domain-specific file."""
    return os.path.join(output_dir, f"{domain}.{ext}")


def generate_pem(
    domain: str,
    cert_cfg: CertConfig,
    base_dir: str,
) -> dict[str, str]:
    """
    Generate a PEM private key and signed certificate.

    Returns a dict with absolute paths: {"key": ..., "cert": ...}.
    Intermediate files (CSR, config) are cleaned up.
    """
    openssl_bin = cert_cfg.openssl_bin
    key_size = cert_cfg.key_size
    days = cert_cfg.validity_days
    ca_cert = _resolve(base_dir, cert_cfg.ca_cert)
    ca_key = _resolve(base_dir, cert_cfg.ca_key)
    output_dir = _resolve(base_dir, cert_cfg.output_dir)
    dn = cert_cfg.dn

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    def dfile(ext: str) -> str:
        return _domain_file(output_dir, domain, ext)

    # Generate private key
    if not os.path.exists(dfile("key")):
        run_openssl(openssl_bin, "genrsa", "-out", dfile("key"), str(key_size))

    # Write OpenSSL config
    config_content = OPENSSL_CONFIG_TEMPLATE.format(
        domain=domain,
        country=dn.country,
        state=dn.state,
        locality=dn.locality,
        organization=dn.organization,
        organizational_unit=dn.organizational_unit,
        email=dn.email,
    )
    with open(dfile("config"), "w", encoding="utf-8") as fh:
        fh.write(config_content)

    # Create CSR
    run_openssl(
        openssl_bin,
        "req", "-new",
        "-key", dfile("key"),
        "-out", dfile("request"),
        "-config", dfile("config"),
    )

    # Sign with CA
    run_openssl(
        openssl_bin,
        "x509", "-req",
        "-days", str(days),
        "-in", dfile("request"),
        "-CA", ca_cert,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", dfile("cert"),
        "-extensions", "v3_req",
        "-extfile", dfile("config"),
    )

    # Cleanup intermediate files
    os.remove(dfile("request"))
    os.remove(dfile("config"))

    return {"key": dfile("key"), "cert": dfile("cert")}


def create_p12(
    domain: str,
    cert_cfg: CertConfig,
    base_dir: str,
) -> str:
    """
    Package the PEM key + cert into a password-protected .p12 bundle.

    If cert_cfg.p12_password is set, it is passed to OpenSSL via -passout
    (no interactive prompt). Otherwise OpenSSL prompts for a passphrase.

    Expects the .key and .cert files to already exist in output_dir.
    Returns the path to the .p12 file.
    """
    openssl_bin = cert_cfg.openssl_bin
    output_dir = _resolve(base_dir, cert_cfg.output_dir)

    def dfile(ext: str) -> str:
        return _domain_file(output_dir, domain, ext)

    passout_args: tuple[str, ...] = ()
    if cert_cfg.p12_password:
        passout_args = ("-passout", f"pass:{cert_cfg.p12_password}")

    run_openssl(
        openssl_bin,
        "pkcs12", "-export",
        "-inkey", dfile("key"),
        "-in", dfile("cert"),
        "-out", dfile("p12"),
        *passout_args,
    )

    return dfile("p12")


def cleanup_pem_files(pem_files: dict[str, str]) -> None:
    """Remove PEM key and cert files."""
    for path in pem_files.values():
        if path and os.path.exists(path):
            os.remove(path)
