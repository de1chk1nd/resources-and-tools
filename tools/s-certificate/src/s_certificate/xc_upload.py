"""F5 Distributed Cloud certificate upload."""

import base64
import json
import sys

import requests

from s_certificate.config import XCConfig


def upload_to_xc(
    domain: str,
    cert_files: dict[str, str],
    xc_cfg: XCConfig,
) -> None:
    """
    Upload the certificate and private key to F5 Distributed Cloud.

    Uses the XC certificate API:
        POST {base_url}/api/config/namespaces/{ns}/certificates

    The certificate and key are sent as base64-encoded PEM via
    clear_secret_info (suitable for lab/demo environments).
    """
    cert_path = cert_files.get("cert")
    key_path = cert_files.get("key")

    if not cert_path or not key_path:
        print("Error: PEM cert/key files not available for upload.")
        sys.exit(1)

    # Read PEM contents
    with open(cert_path, encoding="utf-8") as fh:
        cert_pem = fh.read()
    with open(key_path, encoding="utf-8") as fh:
        key_pem = fh.read()

    # Base64-encode for the API payload
    cert_b64 = base64.b64encode(cert_pem.encode()).decode()
    key_b64 = base64.b64encode(key_pem.encode()).decode()

    # Build XC object name (XC only allows lowercase + hyphens)
    safe_domain = domain.lower().replace(".", "-")
    obj_name = f"{xc_cfg.cert_name_prefix}-{safe_domain}"
    description = xc_cfg.cert_description % domain

    url = f"{xc_cfg.base_url}{xc_cfg.endpoint}"

    payload = {
        "metadata": {
            "name": obj_name,
            "namespace": xc_cfg.namespace,
            "description": description,
            "disable": False,
        },
        "spec": {
            "certificate_url": f"string:///{cert_b64}",
            "private_key": {
                "clear_secret_info": {
                    "url": f"string:///{key_b64}",
                    "provider": "",
                },
            },
        },
    }

    headers = {
        "Authorization": f"APIToken {xc_cfg.api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    print(f"\nUploading certificate to F5 XC...")
    print(f"  Tenant:    {xc_cfg.tenant}")
    print(f"  Namespace: {xc_cfg.namespace}")
    print(f"  Object:    {obj_name}")
    print(f"  Endpoint:  {url}")

    resp = None
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        print(f"\nSuccess — certificate '{obj_name}' created in XC.")
    except requests.exceptions.HTTPError as exc:
        print(f"\nError uploading to XC: {exc}")
        if resp is not None:
            try:
                detail = resp.json()
                print(f"  Response: {json.dumps(detail, indent=2)}")
            except Exception:
                print(f"  Response body: {resp.text}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        print(f"\nConnection error: {exc}")
        print("Check the tenant name and network connectivity.")
        sys.exit(1)
