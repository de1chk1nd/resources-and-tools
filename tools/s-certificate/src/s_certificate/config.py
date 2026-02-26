"""Configuration loader and validation."""

import os
import sys
from dataclasses import dataclass, field

import yaml


@dataclass
class DistinguishedName:
    """CSR distinguished name fields."""

    country: str = "XX"
    state: str = "State"
    locality: str = "City"
    organization: str = "Org"
    organizational_unit: str = "Unit"
    email: str = "admin@example.com"


@dataclass
class CAConfig:
    """CA generation settings."""

    key_size: int = 4096
    validity_days: int = 3650

    # Distinguished name for the CA certificate (defaults to cert DN if not set)
    dn: DistinguishedName | None = None


@dataclass
class CertConfig:
    """Certificate generation settings."""

    openssl_bin: str = "/usr/bin/openssl"
    key_size: int = 2048
    validity_days: int = 365
    ca_cert: str = "ca/ca.cer"
    ca_key: str = "ca/ca.key"
    output_dir: str = "domains"
    p12_password: str = ""
    dn: DistinguishedName = field(default_factory=DistinguishedName)
    ca: CAConfig = field(default_factory=CAConfig)


XC_BASE_URL = "https://{tenant}.console.ves.volterra.io"
XC_API_ENDPOINT = "/api/config/namespaces/{namespace}/certificates"


@dataclass
class XCConfig:
    """F5 Distributed Cloud upload settings."""

    tenant: str = ""
    api_token: str = ""
    namespace: str = "default"
    cert_name_prefix: str = "lab-cert"
    cert_description: str = "Auto-generated server certificate for %s"

    @property
    def base_url(self) -> str:
        return XC_BASE_URL.format(tenant=self.tenant)

    @property
    def endpoint(self) -> str:
        return XC_API_ENDPOINT.format(namespace=self.namespace)

    def __repr__(self) -> str:
        """Redact the API token in repr output."""
        token_display = self.api_token[:4] + "..." if self.api_token else "(empty)"
        return (
            f"XCConfig(tenant={self.tenant!r}, api_token={token_display!r}, "
            f"namespace={self.namespace!r})"
        )


def load_config(config_path: str) -> dict:
    """Load and return the YAML config, or exit with an error."""
    if not os.path.isfile(config_path):
        print(f"Error: Config file not found: {config_path}")
        print("Copy config/config.yaml.example to config/config.yaml and fill in your values.")
        sys.exit(1)

    with open(config_path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    if not cfg:
        print(f"Error: Config file is empty: {config_path}")
        sys.exit(1)

    return cfg


def parse_cert_config(cfg: dict) -> CertConfig:
    """Extract certificate generation settings from config dict."""
    cert = cfg.get("certificate", {})
    dn_raw = cert.get("distinguished_name", {})
    ca_raw = cert.get("ca", {})
    ca_dn_raw = ca_raw.get("distinguished_name", {})

    dn = DistinguishedName(
        country=dn_raw.get("country", "XX"),
        state=dn_raw.get("state", "State"),
        locality=dn_raw.get("locality", "City"),
        organization=dn_raw.get("organization", "Org"),
        organizational_unit=dn_raw.get("organizational_unit", "Unit"),
        email=dn_raw.get("email", "admin@example.com"),
    )

    # CA DN: use explicit ca.distinguished_name if set, otherwise fall back to cert DN
    ca_dn: DistinguishedName | None = None
    if ca_dn_raw:
        ca_dn = DistinguishedName(
            country=ca_dn_raw.get("country", dn.country),
            state=ca_dn_raw.get("state", dn.state),
            locality=ca_dn_raw.get("locality", dn.locality),
            organization=ca_dn_raw.get("organization", dn.organization),
            organizational_unit=ca_dn_raw.get("organizational_unit", dn.organizational_unit),
            email=ca_dn_raw.get("email", dn.email),
        )

    return CertConfig(
        openssl_bin=cert.get("openssl_bin", "/usr/bin/openssl"),
        key_size=cert.get("key_size", 2048),
        validity_days=cert.get("validity_days", 365),
        ca_cert=cert.get("ca_cert", "ca/ca.cer"),
        ca_key=cert.get("ca_key", "ca/ca.key"),
        output_dir=cert.get("output_dir", "domains"),
        p12_password=cert.get("p12_password", ""),
        dn=dn,
        ca=CAConfig(
            key_size=ca_raw.get("key_size", 4096),
            validity_days=ca_raw.get("validity_days", 3650),
            dn=ca_dn,
        ),
    )


def parse_xc_config(cfg: dict) -> XCConfig:
    """Extract and validate XC upload settings from config dict."""
    xc = cfg.get("xc", {})

    xc_cfg = XCConfig(
        tenant=xc.get("tenant", ""),
        api_token=xc.get("api_token", ""),
        namespace=xc.get("namespace", "default"),
        cert_name_prefix=xc.get("cert_name_prefix", "lab-cert"),
        cert_description=xc.get("cert_description", "Auto-generated server certificate for %s"),
    )

    if not xc_cfg.tenant or xc_cfg.tenant == "your-tenant-name":
        print("Error: XC tenant name not configured in config.yaml.")
        sys.exit(1)

    if not xc_cfg.api_token or "REPLACE" in xc_cfg.api_token:
        print("Error: XC API token not configured in config.yaml.")
        sys.exit(1)

    return xc_cfg
