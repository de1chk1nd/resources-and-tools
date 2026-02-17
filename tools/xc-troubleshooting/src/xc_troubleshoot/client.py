"""
F5 Distributed Cloud API client and query builder.
"""

from __future__ import annotations

import logging
import re as _re
from datetime import datetime, timezone, timedelta

import requests

__all__ = ["build_query", "XCClient"]

logger = logging.getLogger(__name__)


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

    Supports filtering by req_id, src_ip, fqdn, or any combination.
    Optionally narrows by load balancer (vh_name).
    """
    filters = []
    if req_id:
        filters.append(f'req_id="{req_id}"')
    if src_ip:
        filters.append(f'src_ip="{src_ip}"')
    if fqdn:
        filters.append(f'authority="{fqdn}"')
    if load_balancer:
        filters.append(f'vh_name=~".*{_re.escape(load_balancer)}.*"')

    return "{" + ", ".join(filters) + "}"


# ---------------------------------------------------------------------------
# F5 XC API Client
# ---------------------------------------------------------------------------

class XCClient:
    """Minimal client for the F5 Distributed Cloud API."""

    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"APIToken {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _time_range(self, search_window_hours: int) -> tuple[str, str]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=search_window_hours)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        return start.strftime(fmt), end.strftime(fmt)

    def _post(self, url: str, body: dict) -> dict:
        """Send a POST request and return JSON, logging the request."""
        logger.info("Querying: %s", url)
        logger.debug("Body: %s", body.get("query", ""))
        resp = self.session.post(url, json=body)
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
