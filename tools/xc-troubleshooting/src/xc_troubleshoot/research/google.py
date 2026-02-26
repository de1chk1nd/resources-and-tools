"""
Google search client — scrapes Google for F5 public documentation.

Scoped to F5 community, cloud docs, and MyF5 knowledge base.
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import unquote

import requests

from .queries import build_research_queries

__all__ = ["run_public_research"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

F5_SEARCH_SOURCES = [
    {"name": "F5 DevCentral (Community)", "site": "community.f5.com"},
    {"name": "F5 Cloud Docs",             "site": "docs.cloud.f5.com"},
    {"name": "F5 Support (MyF5)",         "site": "my.f5.com"},
]

GOOGLE_SEARCH_URL = "https://www.google.com/search"
GOOGLE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# Google search
# ---------------------------------------------------------------------------

def _search_google(
    query: str,
    sites: list[str],
    num_results: int = 3,
    session: requests.Session | None = None,
) -> list[dict]:
    """Search Google scoped to specific sites. Returns list of {title, url, snippet}.

    Accepts an optional ``session`` for dependency injection (testing).
    """
    site_filter = " OR ".join(f"site:{s}" for s in sites)
    full_query = f"{query} ({site_filter})"
    params = {"q": full_query, "num": num_results, "hl": "en"}

    http = session or requests
    try:
        resp = http.get(
            GOOGLE_SEARCH_URL, params=params,
            headers=GOOGLE_HEADERS, timeout=10,
        )
        resp.raise_for_status()
        return _parse_google_results(resp.text, num_results)
    except (requests.RequestException, ValueError) as e:
        logger.warning("Google search failed for query %r: %s", query, e)
        return [{"title": "Search failed", "url": "", "snippet": str(e)}]


def _parse_google_results(html: str, max_results: int) -> list[dict]:
    """Parse Google search results HTML to extract titles, URLs, and snippets."""
    results: list[dict] = []
    url_pattern = re.compile(
        r'<a[^>]+href="/url\?q=([^&"]+)[^"]*"[^>]*>(.*?)</a>', re.DOTALL,
    )

    seen_urls: set[str] = set()
    for raw_url, raw_title in url_pattern.findall(html):
        url = unquote(raw_url)
        if "google.com" in url or "googleapis.com" in url or url in seen_urls:
            continue
        seen_urls.add(url)
        title = re.sub(r'<[^>]+>', '', raw_title).strip()
        if not title or len(title) < 5:
            continue
        results.append({"title": title, "url": url, "snippet": ""})
        if len(results) >= max_results:
            break

    # Best-effort snippet extraction
    snippet_pattern = re.compile(
        r'<span[^>]*class="[^"]*"[^>]*>((?:(?!</span>).){40,300})</span>', re.DOTALL,
    )
    cleaned = [
        re.sub(r'<[^>]+>', '', s).strip()
        for s in snippet_pattern.findall(html)
    ]
    cleaned = [s for s in cleaned if len(s) > 40 and not s.startswith("http") and "Google" not in s]

    for i, result in enumerate(results):
        if i < len(cleaned):
            result["snippet"] = cleaned[i]

    return results


# ---------------------------------------------------------------------------
# Public research runner
# ---------------------------------------------------------------------------

def run_public_research(
    sec_events: list[dict],
    access_logs: list[dict],
    session: requests.Session | None = None,
) -> list[dict]:
    """Search F5 public docs for articles related to the events found.

    Accepts an optional ``session`` for dependency injection.
    """
    queries = build_research_queries(sec_events, access_logs)
    if not queries:
        logger.info("No research queries derived from events — skipping.")
        return []

    sites = [s["site"] for s in F5_SEARCH_SOURCES]
    all_results: list[dict] = []
    seen_urls: set[str] = set()

    logger.info("Running public research (%d queries)...", len(queries))
    for query in queries:
        for r in _search_google(query, sites, num_results=3, session=session):
            if r["url"] and r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                r["query"] = query
                all_results.append(r)
        time.sleep(1)  # rate-limit

    logger.info("Public research found %d unique result(s).", len(all_results))
    return all_results
