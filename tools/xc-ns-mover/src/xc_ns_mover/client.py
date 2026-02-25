"""
F5 Distributed Cloud API client for listing, reading, deleting,
and creating load balancers and their dependent objects.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__all__ = ["XCClient"]

logger = logging.getLogger(__name__)

# Re-export spec utilities under their old private names so that existing
# imports like ``from ..client import _find_ns_refs`` keep working.
from .spec_utils import (  # noqa: E402
    PATH_KEYWORD_TO_RESOURCE as _PATH_KEYWORD_TO_RESOURCE,
    SKIP_NAMESPACES as _SKIP_NAMESPACES,
    find_ns_refs as _find_ns_refs,
    guess_resource_type as _guess_resource_type,
    rewrite_namespace_refs as _rewrite_namespace_refs,
)

# Fields returned by GET that must be stripped before POSTing a new object.
# These are server-managed / read-only and will cause a 422 if included.
_SPEC_READONLY_FIELDS = frozenset(
    {
        # HTTP LB specific
        "auto_cert_info",
        "cert_state",
        "dns_info",
        "host_name",
        "internet_vip_info",
        "downstream_tls_certificate_expiration_timestamps",
        "state",
        "status",
        # Certificate specific (back-references)
        "http_loadbalancers",
        "tcp_loadbalancers",
        "infos",
    }
)

# Map of XC config object types to their API path segments.
# Used to construct GET/DELETE/POST URLs.
_RESOURCE_TYPE_MAP = {
    "origin_pools": "origin_pools",
    "healthchecks": "healthchecks",
    "certificates": "certificates",
    "service_policys": "service_policys",
    "api_definitions": "api_definitions",
    "app_firewalls": "app_firewalls",
    "ip_prefix_sets": "ip_prefix_sets",
    "rate_limiter_policys": "rate_limiter_policys",
    "user_identifications": "user_identifications",
}


class XCClient:
    """Client for the F5 Distributed Cloud API — namespace & LB operations."""

    # LB endpoint types to try.  After the first 404 for a given type we
    # stop querying it for subsequent namespaces (the endpoint simply does
    # not exist on this tenant).
    _LB_TYPES = ["http_loadbalancers", "https_loadbalancers"]

    # Default timeout for all HTTP requests: (connect, read) in seconds.
    DEFAULT_TIMEOUT = (10, 60)

    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"APIToken {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        # Retry on transient server errors and connection failures.
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self._disabled_lb_types: set[str] = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, url: str) -> dict:
        """Send a GET request and return the parsed JSON response."""
        logger.debug("GET %s", url)
        resp = self.session.get(url, timeout=self.DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _post(self, url: str, body: dict) -> dict:
        """Send a POST request with *body* and return the parsed JSON response."""
        logger.debug("POST %s", url)
        resp = self.session.post(url, json=body, timeout=self.DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, url: str, body: dict | None = None) -> dict:
        """Send a DELETE request and return the parsed JSON response."""
        logger.debug("DELETE %s", url)
        resp = self.session.delete(url, json=body or {}, timeout=self.DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _delete_raw(self, url: str, body: dict | None = None) -> requests.Response:
        """DELETE and return the raw Response (caller handles status)."""
        logger.debug("DELETE (raw) %s", url)
        return self.session.delete(url, json=body or {}, timeout=self.DEFAULT_TIMEOUT)

    # ------------------------------------------------------------------
    # Namespace listing
    # ------------------------------------------------------------------

    def list_namespaces(self) -> list[str]:
        url = f"{self.api_url}/api/web/namespaces"
        data = self._get(url)
        items = data.get("items", [])
        names = [item.get("name", "") for item in items if item.get("name")]
        names.sort()
        logger.info("Found %d namespaces", len(names))
        return names

    # ------------------------------------------------------------------
    # Load-balancer listing (per namespace)
    # ------------------------------------------------------------------

    def _list_lb_type(self, namespace: str, lb_type: str) -> list[dict[str, Any]]:
        if lb_type in self._disabled_lb_types:
            return []
        url = f"{self.api_url}/api/config/namespaces/{namespace}/{lb_type}"
        try:
            data = self._get(url)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status == 404:
                self._disabled_lb_types.add(lb_type)
                logger.info(
                    "Endpoint %s returned 404 — disabling for remaining namespaces",
                    lb_type,
                )
                return []
            if status == 403:
                logger.debug(
                    "No access to %s in namespace '%s' (403) — skipping",
                    lb_type, namespace,
                )
                return []
            raise
        return data.get("items", [])

    def list_all_loadbalancers(self, namespace: str) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        for lb_type in self._LB_TYPES:
            for lb in self._list_lb_type(namespace, lb_type):
                name = lb.get("name") or (lb.get("metadata") or {}).get("name") or "<unknown>"
                results.append((name, lb_type.rstrip("s")))
        return results

    # ------------------------------------------------------------------
    # Generic config object operations
    # ------------------------------------------------------------------

    def get_config_object(
        self, namespace: str, resource_type: str, name: str
    ) -> dict:
        """GET /api/config/namespaces/{ns}/{resource_type}/{name}"""
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/{resource_type}/{name}"
        )
        return self._get(url)

    def delete_config_object(
        self, namespace: str, resource_type: str, name: str
    ) -> dict:
        """DELETE /api/config/namespaces/{ns}/{resource_type}/{name}"""
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/{resource_type}/{name}"
        )
        body = {"fail_if_referred": False, "name": name, "namespace": namespace}
        return self._delete(url, body)

    def probe_delete_config_object(
        self,
        namespace: str,
        resource_type: str,
        name: str,
    ) -> list[dict]:
        """Probe whether a config object can be deleted safely.

        Sends a DELETE with ``fail_if_referred: True``.  If the API returns
        **409 Conflict**, there are active referrers blocking deletion — the
        response body usually contains a message listing them.

        Returns:
            An empty list if the object has no active referrers.
            **Important**: in this case the object IS actually deleted as a
            side effect (the probe succeeded).  The caller must track this.

            A non-empty list of referrer dicts parsed from the 409 response
            body if external referrers block the delete.  Each dict has at
            least ``kind``, ``name``, ``namespace`` (best-effort parsing;
            falls back to a raw-message dict if the format is unexpected).
            In this case the object is NOT deleted.
        """
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/{resource_type}/{name}"
        )
        body = {"fail_if_referred": True, "name": name, "namespace": namespace}
        resp = self._delete_raw(url, body)

        if resp.status_code == 409:
            return self._parse_409_referrers(resp)

        if resp.status_code < 300:
            # No referrers — the object was actually deleted.
            # The caller must account for this (e.g. track it in
            # deleted_deps so rollback and re-create work correctly).
            logger.info(
                "probe_delete succeeded for %s/%s/%s — object deleted "
                "(no active referrers).",
                namespace, resource_type, name,
            )
            return []

        # Any other error — raise as normal
        resp.raise_for_status()
        return []  # unreachable, but keeps the type checker happy

    @staticmethod
    def _parse_409_referrers(resp: requests.Response) -> list[dict]:
        """Best-effort parse of a 409 Conflict response from XC.

        The response body is typically JSON with a ``message`` field
        like::

            {
              "code": 9,
              "message": "referenced by origin_pool [ns/name], ...",
              ...
            }

        We try to extract structured referrer info from that message.
        Falls back to returning a single dict with the raw message.
        """
        referrers: list[dict] = []
        try:
            data = resp.json()
        except (ValueError, KeyError):
            return [{"kind": "?", "name": "?", "namespace": "?",
                     "raw": resp.text[:500]}]

        msg = data.get("message", "") or ""

        # Try to parse "referenced by <kind> [<ns>/<name>]" patterns
        # XC format: "... referred by {kind} {ns}/{name}, {kind} {ns}/{name} ..."
        # Pattern: kind namespace/name  (sometimes with square brackets)
        pattern = r'(?:referred\s+by|referenced\s+by|referencing)\s+(.*)'
        m = re.search(pattern, msg, re.IGNORECASE)
        if m:
            refs_part = m.group(1)
            # Each ref: "kind [ns/name]" or "kind ns/name"
            ref_pattern = r'(\w+)\s+\[?(\S+?)/(\S+?)\]?(?:,|$|\s)'
            for rm in re.finditer(ref_pattern, refs_part):
                referrers.append({
                    "kind": rm.group(1),
                    "namespace": rm.group(2),
                    "name": rm.group(3),
                })

        if not referrers:
            # Could not parse structured info — return raw
            referrers = [{"kind": "?", "name": "?", "namespace": "?",
                          "raw": msg[:500]}]

        return referrers

    def create_config_object(
        self, namespace: str, resource_type: str, metadata: dict, spec: dict
    ) -> dict:
        """POST /api/config/namespaces/{ns}/{resource_type}"""
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/{resource_type}"
        )
        body = {"metadata": metadata, "spec": spec}
        return self._post(url, body)

    # ------------------------------------------------------------------
    # List existing object names in a namespace (for conflict detection)
    # ------------------------------------------------------------------

    def list_config_object_names(
        self, namespace: str, resource_type: str
    ) -> set[str]:
        """List all object names of a given type in a namespace.

        Returns a set of object names.  Used to detect naming conflicts
        before creating objects in the target namespace.
        """
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/{resource_type}"
        )
        try:
            data = self._get(url)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (403, 404):
                logger.debug(
                    "Cannot list %s in namespace '%s' (HTTP %s) — assuming empty",
                    resource_type, namespace, status,
                )
                return set()
            raise
        items = data.get("items", [])
        names: set[str] = set()
        for item in items:
            name = item.get("name") or (item.get("metadata") or {}).get("name")
            if name:
                names.add(name)
        return names

    def list_http_loadbalancer_names(self, namespace: str) -> set[str]:
        """List all HTTP LB names in a namespace."""
        return self.list_config_object_names(namespace, "http_loadbalancers")

    # ------------------------------------------------------------------
    # Single HTTP LB operations (convenience wrappers)
    # ------------------------------------------------------------------

    def get_http_loadbalancer(self, namespace: str, name: str) -> dict:
        return self.get_config_object(namespace, "http_loadbalancers", name)

    def delete_http_loadbalancer(self, namespace: str, name: str) -> dict:
        return self.delete_config_object(namespace, "http_loadbalancers", name)

    def create_http_loadbalancer(
        self, namespace: str, metadata: dict, spec: dict
    ) -> dict:
        return self.create_config_object(
            namespace, "http_loadbalancers", metadata, spec
        )

    # ------------------------------------------------------------------
    # Prepare objects for move
    # ------------------------------------------------------------------

    @staticmethod
    def clean_metadata(raw_config: dict, target_namespace: str) -> dict:
        """Extract and clean metadata for a create call."""
        raw_meta = raw_config.get("metadata") or {}
        return {
            "name": raw_meta.get("name", ""),
            "namespace": target_namespace,
            "labels": raw_meta.get("labels") or {},
            "annotations": raw_meta.get("annotations") or {},
            "description": raw_meta.get("description", ""),
            "disable": raw_meta.get("disable", False),
        }

    @staticmethod
    def clean_spec(raw_config: dict) -> dict:
        """Strip read-only fields from spec."""
        raw_spec = raw_config.get("spec") or {}
        return {k: v for k, v in raw_spec.items() if k not in _SPEC_READONLY_FIELDS}

    @staticmethod
    def prepare_for_move(
        raw_config: dict,
        src_namespace: str,
        target_namespace: str,
    ) -> tuple[dict, dict]:
        """Take a full GET response and return (metadata, spec) ready for create.

        - Sets namespace to target_namespace in metadata
        - Strips read-only fields from spec
        - Rewrites all {name, namespace} references from src to target namespace
        """
        metadata = XCClient.clean_metadata(raw_config, target_namespace)
        spec = XCClient.clean_spec(raw_config)
        # Rewrite namespace references in spec
        spec = _rewrite_namespace_refs(spec, src_namespace, target_namespace)
        return metadata, spec

    # Keep backward compat
    prepare_lb_for_move = prepare_for_move

    # ------------------------------------------------------------------
    # Dependency discovery
    # ------------------------------------------------------------------

    def discover_dependencies(
        self,
        src_namespace: str,
        lb_config: dict,
    ) -> list[tuple[str, str, str]]:
        """Discover all objects in src_namespace that an LB depends on.

        Recursively walks the LB spec and any discovered dependent objects
        to find the full transitive dependency tree.

        Returns a de-duplicated list of (resource_type, name, namespace)
        in topological order — dependencies before dependents.
        Objects in other namespaces (e.g. system) are NOT included.
        """
        spec = lb_config.get("spec") or {}
        seen: set[tuple[str, str]] = set()  # (resource_type, name)
        ordered: list[tuple[str, str, str]] = []

        # BFS queue: (json_path, object_name, namespace)
        queue = _find_ns_refs(spec, src_namespace)

        while queue:
            path, obj_name, obj_ns = queue.pop(0)
            resource_type = _guess_resource_type(path)
            if resource_type is None:
                logger.debug(
                    "Cannot determine resource type for ref at %s (%s/%s) — skipping",
                    path, obj_ns, obj_name,
                )
                continue

            key = (resource_type, obj_name)
            if key in seen:
                continue
            seen.add(key)

            # Try to fetch the object to discover its own dependencies
            try:
                obj_config = self.get_config_object(obj_ns, resource_type, obj_name)
            except requests.RequestException as exc:
                logger.warning(
                    "Cannot fetch %s/%s/%s for dependency scan: %s",
                    obj_ns, resource_type, obj_name, exc,
                )
                ordered.append((resource_type, obj_name, obj_ns))
                continue

            # Scan this object's spec for further refs
            obj_spec = obj_config.get("spec") or {}
            sub_refs = _find_ns_refs(obj_spec, src_namespace)
            queue.extend(sub_refs)

            ordered.append((resource_type, obj_name, obj_ns))

        return ordered

    # ------------------------------------------------------------------
    # Referring-objects check
    # ------------------------------------------------------------------

    @staticmethod
    def extract_referring_objects(config: dict) -> list[dict]:
        """Extract the list of referring objects from a GET response.

        The XC API returns a top-level ``referring_objects`` list on every
        config GET.  Each entry looks like::

            {
                "kind": "http_loadbalancer",
                "name": "my-lb",
                "namespace": "my-ns",
                "uid": "...",
                "tenant": "..."
            }

        Returns the raw list (may be empty).
        """
        return config.get("referring_objects") or []

    @staticmethod
    def filter_external_referrers(
        referring_objects: list[dict],
        move_set: set[tuple[str, str]],
        src_namespace: str,
    ) -> list[dict]:
        """Return only those referrers that are NOT part of the current move.

        *move_set* is a set of ``(namespace, lb_name)`` tuples — the LBs
        that are being moved in this run.

        A referrer is considered "external" if:
        - it lives in a different namespace than *src_namespace*, or
        - it lives in *src_namespace* but is not in the move set.

        Referrers from ``system`` / ``shared`` namespaces are ignored
        (they are system-managed back-refs, not real consumers).
        """
        external: list[dict] = []
        for ref in referring_objects:
            ref_ns = ref.get("namespace", "")
            ref_name = ref.get("name", "")

            # Ignore system / shared back-references
            if ref_ns in _SKIP_NAMESPACES:
                continue

            # Check if this referrer is in the move set
            if (ref_ns, ref_name) not in move_set:
                external.append(ref)

        return external

    # ------------------------------------------------------------------
    # LB info extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_tls_mode(lb_config: dict) -> str:
        spec = lb_config.get("spec") or {}
        if "https_auto_cert" in spec:
            return "Let's Encrypt"
        if "https" in spec:
            return "Manual TLS"
        if "http" in spec:
            return "No TLS"
        return "Unknown"

    @staticmethod
    def extract_cname(lb_config: dict) -> str:
        """Extract the host CNAME from ``spec.dns_info[0].dns_name``
        or fall back to ``spec.host_name``."""
        spec = lb_config.get("spec") or {}
        dns_info = spec.get("dns_info") or []
        if dns_info and isinstance(dns_info, list):
            first = dns_info[0] if dns_info else {}
            cname = (first.get("dns_name") or "").strip()
            if cname:
                return cname
        return spec.get("host_name", "") or ""

    @staticmethod
    def extract_acme_cname(lb_config: dict) -> str:
        """Extract the ACME challenge CNAME from
        ``spec.auto_cert_info.dns_records`` (type=CNAME)."""
        spec = lb_config.get("spec") or {}
        auto_cert = spec.get("auto_cert_info") or {}
        dns_records = auto_cert.get("dns_records") or []
        for rec in dns_records:
            if isinstance(rec, dict) and rec.get("type", "").upper() == "CNAME":
                val = (rec.get("value") or "").strip()
                if val:
                    return val
        return ""

    # ------------------------------------------------------------------
    # Certificate portability helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_cert_portable(cert_config: dict) -> tuple[bool, str]:
        """Check if a certificate can be moved via API extract-and-recreate.

        Returns ``(True, "")`` if the certificate is fully portable.
        Returns ``(False, reason)`` if the private key contains secret
        material that cannot be extracted via the API.

        Non-portable private key types:

        - ``blindfold_secret_info`` — encrypted with the Volterra blindfold key
        - ``clear_secret_info`` — stored encrypted at rest, not returned in cleartext
        - ``vault_secret_info`` — reference to an external vault
        - ``wingman_secret_info`` — managed by wingman
        """
        spec = cert_config.get("spec") or {}
        pk = spec.get("private_key") or {}

        secret_types = {
            "blindfold_secret_info": "private key (blindfolded)",
            "clear_secret_info": "private key (clear secret)",
            "vault_secret_info": "private key (vault reference)",
            "wingman_secret_info": "private key (wingman)",
        }
        for field_name, description in secret_types.items():
            if field_name in pk and pk[field_name]:
                return False, description

        # Fallback: any non-empty private_key dict with unknown structure
        if pk:
            return False, "private key (unknown type)"

        return True, ""

    @staticmethod
    def extract_cert_domains(cert_config: dict) -> list[str]:
        """Extract all domains (CN + SANs) covered by a certificate.

        Reads from the ``spec.infos`` field which is populated by XC
        after certificate upload.  This field is always available, even
        when the private key is blindfolded — blindfold only encrypts
        the private key, not the certificate properties.

        Returns a deduplicated, lowercased, sorted list of domain
        strings (may include wildcards like ``*.example.com``).
        """
        domains: set[str] = set()
        spec = cert_config.get("spec") or {}

        for info in spec.get("infos") or []:
            # DNS SANs — the field may be called "dns_names" (documented)
            # or "subject_alternative_names" (observed in real API responses).
            for dns in info.get("dns_names") or []:
                if dns:
                    domains.add(dns.lower().strip("."))
            for san in info.get("subject_alternative_names") or []:
                if san:
                    domains.add(san.lower().strip("."))
            # Subject CN — may be nested under "subject" (documented)
            # or directly on the info object (observed in real API responses).
            subject = info.get("subject") or {}
            cn = subject.get("common_name", "")
            if not cn:
                cn = info.get("common_name", "")
            if cn:
                domains.add(cn.lower().strip("."))

        return sorted(domains)

    @staticmethod
    def extract_lb_domains(lb_config: dict) -> list[str]:
        """Extract the domain list from an HTTP load balancer config.

        Reads ``spec.domains`` which corresponds to the *Domains* field
        in the XC Console UI.

        Returns a lowercased list of domain strings.
        """
        spec = lb_config.get("spec") or {}
        raw = spec.get("domains") or []
        return [d.lower().strip(".") for d in raw if d]

    @staticmethod
    def domain_matches_cert(domain: str, cert_domains: list[str]) -> bool:
        """Check if *domain* is covered by any of *cert_domains*.

        Supports wildcard matching per RFC 6125:

        - ``*.example.com`` matches ``app.example.com``
        - ``*.example.com`` does **not** match ``sub.app.example.com``
        - ``*.example.com`` does **not** match ``example.com`` itself
        """
        domain = domain.lower().strip(".")
        for cert_domain in cert_domains:
            cd = cert_domain.lower().strip(".")
            if cd == domain:
                return True
            # Wildcard: *.example.com
            if cd.startswith("*."):
                wildcard_base = cd[2:]  # "example.com"
                if domain.endswith("." + wildcard_base):
                    prefix = domain[: -(len(wildcard_base) + 1)]
                    if prefix and "." not in prefix:
                        return True
        return False

    def list_certificates_full(self, namespace: str) -> list[dict]:
        """List all certificate objects in *namespace* with full config.

        The list endpoint may not include the ``infos`` field, so each
        certificate is fetched individually via GET to ensure we have
        the complete response including parsed certificate details.

        Returns an empty list (no error) when the namespace is
        inaccessible (403) or the endpoint does not exist (404).
        """
        url = (
            f"{self.api_url}/api/config/namespaces/{namespace}"
            f"/certificates"
        )
        try:
            data = self._get(url)
        except requests.HTTPError as exc:
            status = (
                exc.response.status_code if exc.response is not None else None
            )
            if status in (403, 404):
                logger.debug(
                    "Cannot list certificates in '%s' (HTTP %s)",
                    namespace,
                    status,
                )
                return []
            raise

        items = data.get("items", [])
        full_configs: list[dict] = []
        for item in items:
            name = item.get("name") or (
                (item.get("metadata") or {}).get("name")
            )
            if not name:
                continue
            try:
                full_config = self.get_config_object(
                    namespace, "certificates", name,
                )
                full_configs.append(full_config)
            except requests.RequestException as exc:
                logger.debug(
                    "Cannot fetch cert '%s/%s': %s", namespace, name, exc,
                )
        return full_configs

    # ------------------------------------------------------------------
    # DNS zone inspection (Phase 0e — managed DNS detection)
    # ------------------------------------------------------------------

    def list_dns_zones(self) -> list[dict]:
        """List all DNS zones in the 'system' namespace with full config.

        Calls GET /api/config/dns/namespaces/system/dns_zones to get the
        list, then fetches each zone individually to get the full spec
        (the list endpoint may omit nested fields).

        Dumps the FULL JSON response at DEBUG level so we can discover
        the exact field names for managed-records settings on first run.

        Returns an empty list on 403/404 (no permission or endpoint
        not available) with a WARNING logged.
        """
        url = f"{self.api_url}/api/config/dns/namespaces/system/dns_zones"
        try:
            data = self._get(url)
        except requests.HTTPError as exc:
            status = (
                exc.response.status_code if exc.response is not None else None
            )
            if status in (403, 404):
                logger.warning(
                    "Cannot list DNS zones (HTTP %s) — managed DNS detection unavailable",
                    status,
                )
                return []
            raise

        logger.debug("DNS zones list response: %s", json.dumps(data, indent=2))

        items = data.get("items", [])
        full_configs: list[dict] = []
        for item in items:
            name = item.get("name") or (
                (item.get("metadata") or {}).get("name")
            )
            if not name:
                continue
            zone_url = f"{self.api_url}/api/config/dns/namespaces/system/dns_zones/{name}"
            try:
                zone_data = self._get(zone_url)
                logger.debug(
                    "DNS zone '%s' full config: %s",
                    name,
                    json.dumps(zone_data, indent=2),
                )
                full_configs.append(zone_data)
            except requests.RequestException as exc:
                logger.debug(
                    "Cannot fetch DNS zone '%s': %s", name, exc,
                )
        return full_configs

    @staticmethod
    def extract_managed_zone_domains(zone_configs: list[dict]) -> set[str]:
        """Extract zone domains that have 'Allow LB Managed Records' enabled.

        Tries multiple candidate field paths for the managed-records
        flag (the exact API field name varies) and logs zone details
        for diagnostics.  Returns lowercased zone domain strings.
        """
        managed_domains: set[str] = set()

        for zone in zone_configs:
            metadata = zone.get("metadata") or {}
            spec = zone.get("spec") or {}
            zone_name = metadata.get("name") or zone.get("name") or "(unknown)"

            # Try to find the zone domain from multiple candidate paths
            primary = spec.get("primary") or {}
            soa = primary.get("soa_parameters") or {}
            zone_domain = (
                soa.get("domain")
                or primary.get("domain")
                or metadata.get("name")
                or ""
            ).lower().strip(".")

            # Log for discovery on first real run
            logger.info(
                "DNS zone '%s' (domain: %s) — spec.primary keys: %s",
                zone_name,
                zone_domain or "(not found)",
                sorted(primary.keys()) if primary else "(empty)",
            )

            # Try multiple candidate field paths for managed DNS flag
            managed = False
            candidate_paths = [
                primary.get("allow_http_lb_managed_dns_records"),
                primary.get("allow_lb_managed_records"),
            ]
            for candidate in candidate_paths:
                if candidate is not None:
                    # The field might be a dict (presence = enabled) or a bool
                    if isinstance(candidate, dict) or candidate is True:
                        managed = True
                        break

            # Also check for default_rr_set_group sub-fields
            default_group = primary.get("default_rr_set_group")
            if default_group and isinstance(default_group, list):
                # If there's a default RR set group, log it for inspection
                logger.info(
                    "DNS zone '%s' has default_rr_set_group: %s",
                    zone_name,
                    json.dumps(default_group, indent=2),
                )

            if managed and zone_domain:
                logger.info(
                    "DNS zone '%s' (domain: %s) has LB managed records ENABLED",
                    zone_name,
                    zone_domain,
                )
                managed_domains.add(zone_domain)
            elif zone_domain:
                logger.info(
                    "DNS zone '%s' (domain: %s) — managed records NOT detected",
                    zone_name,
                    zone_domain,
                )

        return managed_domains

    @staticmethod
    def domain_is_under_zone(domain: str, zone_domain: str) -> bool:
        """Check if domain equals or is a subdomain of zone_domain.

        Examples:
            'app.example.com' under 'example.com' -> True
            'example.com' under 'example.com' -> True
            'sub.app.example.com' under 'example.com' -> True
            'other.com' under 'example.com' -> False
            'notexample.com' under 'example.com' -> False
        """
        domain = domain.lower().strip(".")
        zone_domain = zone_domain.lower().strip(".")
        return domain == zone_domain or domain.endswith("." + zone_domain)
