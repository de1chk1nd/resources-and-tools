"""
F5 Distributed Cloud API client and query builder.

Features:
  - Input validation before query construction
  - Automatic retry with backoff on transient failures (429, 5xx)
  - Token redaction in __repr__
  - Dependency injection for session (testability)
"""

from __future__ import annotations

import logging
import re as _re
from datetime import datetime, timezone, timedelta
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .validation import (
    sanitize_query_value,
    sanitize_lb_name,
)

__all__ = ["build_query", "XCClient"]

logger = logging.getLogger(__name__)

# Default retry strategy: retry on 429, 500, 502, 503, 504
_DEFAULT_RETRY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["POST", "GET"],
    raise_on_status=False,
)


# ---------------------------------------------------------------------------
# Query Builder
# ---------------------------------------------------------------------------

def build_query(
    req_id: str = "",
    src_ip: str = "",
    fqdn: str = "",
    load_balancer: str = "",
) -> str:
    """
    Build a LogQL-style query string for the F5 XC API.

    All values are validated before embedding to prevent query injection.
    Supports filtering by req_id, src_ip, fqdn, or any combination.
    Optionally narrows by load balancer (vh_name).
    """
    filters = []

    if req_id:
        req_id = sanitize_query_value(req_id, "req_id")
        filters.append(f'req_id="{req_id}"')
    if src_ip:
        src_ip = sanitize_query_value(src_ip, "src_ip")
        filters.append(f'src_ip="{src_ip}"')
    if fqdn:
        fqdn = sanitize_query_value(fqdn, "fqdn")
        filters.append(f'authority="{fqdn}"')
    if load_balancer:
        load_balancer = sanitize_lb_name(load_balancer)
        filters.append(f'vh_name=~".*{_re.escape(load_balancer)}.*"')

    return "{" + ", ".join(filters) + "}"


# ---------------------------------------------------------------------------
# F5 XC API Client
# ---------------------------------------------------------------------------

def _build_session(api_token: str, retry: Retry | None = None) -> requests.Session:
    """Create a requests.Session with auth headers and retry adapter."""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"APIToken {api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    adapter = HTTPAdapter(max_retries=retry or _DEFAULT_RETRY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class XCClient:
    """HTTP client for the F5 Distributed Cloud API.

    Supports dependency injection for the session (for testing) and
    automatic retry with backoff on transient HTTP errors.
    """

    def __init__(
        self,
        api_url: str,
        api_token: str,
        session: requests.Session | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.api_url = api_url.rstrip("/")
        self._token_hint = api_token[:4] + "***" if len(api_token) > 4 else "***"
        self.session = session or _build_session(api_token)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"XCClient(api_url={self.api_url!r}, token={self._token_hint!r})"

    def _time_range(self, search_window_hours: int) -> tuple[str, str]:
        end = self._clock()
        start = end - timedelta(hours=search_window_hours)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        return start.strftime(fmt), end.strftime(fmt)

    def _post(self, url: str, body: dict) -> dict:
        """Send a POST request and return JSON, logging the request."""
        logger.info("Querying: %s", url)
        logger.debug("Query filter: %s", body.get("query", ""))
        resp = self.session.post(url, json=body, verify=True)
        resp.raise_for_status()
        return resp.json()

    def _get(self, url: str) -> dict:
        """Send a GET request and return JSON, logging the request."""
        logger.info("Fetching: %s", url)
        resp = self.session.get(url, verify=True)
        resp.raise_for_status()
        return resp.json()

    def query_security_events(
        self,
        namespace: str,
        query: str,
        search_window_hours: int = 24,
        limit: int = 50,
    ) -> dict:
        """
        Query security events with an arbitrary filter query.

        Uses: POST /api/data/namespaces/{namespace}/app_security/events
        """
        start_time, end_time = self._time_range(search_window_hours)
        body = {
            "namespace": namespace,
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "sort": "DESCENDING",
            "limit": limit,
        }
        url = f"{self.api_url}/api/data/namespaces/{namespace}/app_security/events"
        return self._post(url, body)

    def query_access_logs(
        self,
        namespace: str,
        query: str,
        search_window_hours: int = 24,
        limit: int = 50,
    ) -> dict:
        """
        Query access logs with an arbitrary filter query.

        Uses: POST /api/data/namespaces/{namespace}/access_logs
        """
        start_time, end_time = self._time_range(search_window_hours)
        body = {
            "namespace": namespace,
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "sort": "DESCENDING",
            "limit": limit,
        }
        url = f"{self.api_url}/api/data/namespaces/{namespace}/access_logs"
        return self._post(url, body)

    def get_http_loadbalancer(
        self,
        namespace: str,
        name: str,
    ) -> dict:
        """
        Fetch the HTTP Load Balancer configuration.

        Uses: GET /api/config/namespaces/{namespace}/http_loadbalancers/{name}
        """
        url = f"{self.api_url}/api/config/namespaces/{namespace}/http_loadbalancers/{name}"
        return self._get(url)

    def get_user_identification(
        self,
        namespace: str,
        name: str,
    ) -> dict:
        """
        Fetch a User Identification policy configuration.

        Uses: GET /api/config/namespaces/{namespace}/user_identifications/{name}
        """
        url = f"{self.api_url}/api/config/namespaces/{namespace}/user_identifications/{name}"
        return self._get(url)
