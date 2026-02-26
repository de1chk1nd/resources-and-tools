"""
Traffic flow analysis — determine the network path and per-segment latency.

Examines raw access log and security event data to classify the request
into one of three path types:

  1. Internet → RE → Internet → App   (no CE, origin via internet)
  2. Internet → RE → CE → App         (origin via Customer Edge)
  3. Internal → CE → App / CE          (site-local or CE-to-CE)

When multiple log entries are present (e.g. searching by IP or FQDN),
latency values are *averaged* across all entries and per-node metadata
is aggregated (unique IPs, FQDNs, sites) for tooltip display.
"""

from __future__ import annotations

import json as _json
import logging
import statistics
from dataclasses import dataclass, field

__all__ = [
    "FlowPath",
    "FlowSegment",
    "FlowNode",
    "build_traffic_flow",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FlowNode:
    """A node (box) in the traffic flow diagram."""

    label: str              # short display label ("Client", "RE", "App")
    icon: str = ""          # SVG icon identifier
    sublabel: str = ""      # secondary info line (IP, site name, FQDN …)
    detail: str = ""        # tertiary info (country, ASN …)
    tooltip: str = ""       # hover tooltip (full detail for aggregated data)


@dataclass
class FlowSegment:
    """An arrow between two nodes with optional latency annotation."""

    label: str = ""         # e.g. "TLS 1.3" or "tunnel"
    latency_ms: float | None = None    # average, in milliseconds
    latency_min: float | None = None   # minimum
    latency_max: float | None = None   # maximum
    sample_count: int = 0              # how many log entries contributed
    tooltip: str = ""                  # hover tooltip


@dataclass
class FlowPath:
    """Complete traffic flow for one or more requests."""

    path_type: str          # "internet-re-internet-app" | "internet-re-ce-app" | "internal-ce-app"
    path_label: str         # human-readable label
    nodes: list[FlowNode] = field(default_factory=list)
    segments: list[FlowSegment] = field(default_factory=list)   # len = len(nodes) - 1
    request_count: int = 1  # number of log entries aggregated


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ms(val) -> float | None:
    """Parse a seconds-string to milliseconds, returning None if unavailable."""
    if val is None or val == "N/A" or val == "":
        return None
    try:
        f = float(val)
        if f == 0.0:
            return None
        return round(f * 1000, 2)
    except (ValueError, TypeError):
        return None


def _aggregate_ms(values: list[float | None]) -> tuple[float | None, float | None, float | None, int]:
    """Return (avg, min, max, count) from a list of optional ms values."""
    valid = [v for v in values if v is not None]
    if not valid:
        return None, None, None, 0
    avg = round(statistics.mean(valid), 2)
    return avg, min(valid), max(valid), len(valid)


def _unique_nonempty(items: list[str]) -> list[str]:
    """Return unique non-empty strings, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen and item.lower() not in ("n/a", "none", "", "not-applicable"):
            seen.add(item)
            result.append(item)
    return result


def _is_public(src: str) -> bool:
    return "public" in src.lower() if src else True


def _has_ce(dst_site: str) -> bool:
    """True if traffic goes through a Customer Edge site."""
    if not dst_site:
        return False
    skip = {"", "not-applicable", "n/a", "none"}
    return dst_site.strip().lower() not in skip


def _majority(items: list[str]) -> str:
    """Return the most common non-empty value."""
    filtered = [i for i in items if i and i.lower() not in ("n/a", "none", "", "not-applicable")]
    if not filtered:
        return ""
    from collections import Counter
    return Counter(filtered).most_common(1)[0][0]


def _parse_raw_entries(raw_data: dict | None, list_key: str, fallback_key: str = "") -> list[dict]:
    """Parse raw API response entries into a list of dicts."""
    if not raw_data:
        return []
    entries = raw_data.get(list_key, [])
    if not entries and fallback_key:
        entries = raw_data.get(fallback_key, [])
    result: list[dict] = []
    for entry in entries:
        if isinstance(entry, dict):
            result.append(entry)
        elif isinstance(entry, str):
            try:
                result.append(_json.loads(entry))
            except (ValueError, TypeError):
                pass
    return result


def _build_latency_tooltip(avg: float | None, mn: float | None, mx: float | None, count: int) -> str:
    """Build a latency tooltip string with avg/min/max."""
    if avg is None:
        return ""
    parts = [f"avg: {_fmt_ms(avg)}"]
    if count > 1:
        if mn is not None:
            parts.append(f"min: {_fmt_ms(mn)}")
        if mx is not None:
            parts.append(f"max: {_fmt_ms(mx)}")
        parts.append(f"samples: {count}")
    return " | ".join(parts)


def _fmt_ms(ms: float) -> str:
    """Format milliseconds for display."""
    if ms < 1:
        return f"{ms * 1000:.0f} us"
    if ms < 1000:
        return f"{ms:.1f} ms"
    return f"{ms / 1000:.2f} s"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_traffic_flow(
    sec_events: list[dict],
    access_logs: list[dict],
    raw_sec: dict | None = None,
    raw_access: dict | None = None,
) -> FlowPath | None:
    """Analyse available data and return a FlowPath, or None if insufficient data.

    Aggregates across all log entries when multiple are present.
    """
    raw_logs = _parse_raw_entries(raw_access, "logs", "access_logs")
    raw_evts = _parse_raw_entries(raw_sec, "events")

    # Combine: raw entries have more fields, parsed entries are fallback
    all_entries = raw_logs or raw_evts
    if not all_entries:
        # Fall back to parsed data
        all_entries = access_logs or sec_events
    if not all_entries:
        logger.debug("Insufficient data for traffic flow diagram")
        return None

    n_entries = len(all_entries)

    # --- Collect per-entry values ---
    def _collect(key: str) -> list[str]:
        return [str(e.get(key, "") or "") for e in all_entries]

    def _collect_ms(key: str) -> list[float | None]:
        return [_ms(e.get(key)) for e in all_entries]

    src_ips = _collect("src_ip")
    srcs = _collect("src")
    _src_sites_raw = _collect("src_site")
    src_sites = _src_sites_raw if any(_src_sites_raw) else _collect("site")
    dst_sites = _collect("dst_site")
    dst_ips = _collect("dst_ip")
    authorities = _collect("authority")
    snis = _collect("sni")
    domains = _collect("domain")
    countries = _collect("country")
    cities = _collect("city")
    as_orgs = _collect("as_org")
    asns = _collect("asn")
    tls_versions = _collect("tls_version")
    cluster_names = _collect("cluster_name")
    upstream_clusters = _collect("upstream_cluster")
    x_fwd_fors = _collect("x_forwarded_for")
    waf_actions = _collect("waf_action")
    actions = _collect("action")
    vh_names = _collect("vh_name")

    # Latency series
    ttfb_series = _collect_ms("time_to_first_downstream_tx_byte")
    rx_series = _collect_ms("time_to_last_rx_byte")
    up_first_rx_series = _collect_ms("time_to_first_upstream_rx_byte")
    rtt_up_series = _collect_ms("rtt_upstream_seconds")
    rtt_down_series = _collect_ms("rtt_downstream_seconds")

    # --- Pick representative values (majority / unique lists) ---
    src_ip = _majority(src_ips)
    src = _majority(srcs)
    src_site = _majority(src_sites) or _majority(cluster_names)
    dst_site = _majority(dst_sites)
    authority = _majority(authorities) or _majority(snis) or _majority(domains)
    country = _majority(countries)
    city = _majority(cities)
    asn = _majority(as_orgs) or _majority(asns)
    tls_version = _majority(tls_versions)
    upstream_cluster = _majority(upstream_clusters)
    x_forwarded_for = _majority(x_fwd_fors)
    vh_name = _majority(vh_names)

    # Effective WAF action — "blocked" if ANY entry was blocked
    effective_waf = _majority(waf_actions) or _majority(actions)
    any_blocked = any(
        "block" in (str(e.get("waf_action", "") or e.get("action", ""))).lower()
        for e in all_entries
    )

    # Aggregate latencies
    ttfb_avg, ttfb_min, ttfb_max, ttfb_n = _aggregate_ms(ttfb_series)
    rx_avg, rx_min, rx_max, rx_n = _aggregate_ms(rx_series)
    up_rx_avg, up_rx_min, up_rx_max, up_rx_n = _aggregate_ms(up_first_rx_series)
    rtt_up_avg, rtt_up_min, rtt_up_max, rtt_up_n = _aggregate_ms(rtt_up_series)
    rtt_down_avg, rtt_down_min, rtt_down_max, rtt_down_n = _aggregate_ms(rtt_down_series)

    if not src_ip and not authority:
        logger.debug("Insufficient data for traffic flow diagram")
        return None

    # --- Classify path (based on majority of entries) ---
    is_internet = _is_public(src)
    has_customer_edge = _has_ce(dst_site)

    # --- Build unique-value lists for tooltips ---
    unique_src_ips = _unique_nonempty(src_ips)
    unique_authorities = _unique_nonempty(authorities + snis + domains)
    unique_src_sites = _unique_nonempty(src_sites)
    unique_dst_sites = _unique_nonempty(dst_sites)
    unique_dst_ips = _unique_nonempty(dst_ips)
    unique_countries = _unique_nonempty(countries)
    unique_asns = _unique_nonempty(as_orgs) or _unique_nonempty(asns)
    unique_upstream = _unique_nonempty(upstream_clusters)

    is_aggregated = n_entries > 1

    # --- Client node ---
    client_geo_parts = []
    if city and country:
        client_geo_parts.append(f"{city}, {country}")
    elif country:
        client_geo_parts.append(country)
    if asn:
        client_geo_parts.append(asn)

    client_sublabel = src_ip
    if is_aggregated and len(unique_src_ips) > 1:
        client_sublabel = f"{len(unique_src_ips)} unique IPs"
    elif x_forwarded_for and x_forwarded_for != src_ip:
        client_sublabel = f"{src_ip} (via {x_forwarded_for})"

    client_tooltip_lines = [f"Source IPs: {', '.join(unique_src_ips[:10])}"]
    if len(unique_src_ips) > 10:
        client_tooltip_lines[0] += f" (+{len(unique_src_ips) - 10} more)"
    if unique_countries:
        client_tooltip_lines.append(f"Countries: {', '.join(unique_countries[:5])}")
    if unique_asns:
        client_tooltip_lines.append(f"ASN: {', '.join(unique_asns[:3])}")
    client_tooltip_lines.append(f"Requests: {n_entries}")

    tls_label = ""
    if tls_version:
        tls_label = tls_version.replace("TLSv1_", "TLS 1.").replace("TLSv", "TLS ")

    # --- RE node ---
    re_sublabel = src_site
    if is_aggregated and len(unique_src_sites) > 1:
        re_sublabel = f"{len(unique_src_sites)} RE sites"

    re_tooltip_lines = []
    if unique_src_sites:
        re_tooltip_lines.append(f"RE sites: {', '.join(unique_src_sites[:5])}")
    if unique_authorities:
        re_tooltip_lines.append(f"FQDNs: {', '.join(unique_authorities[:5])}")
    if vh_name:
        re_tooltip_lines.append(f"VH: {vh_name}")

    # --- App node ---
    app_sublabel = upstream_cluster or _majority(dst_ips) or ""
    if is_aggregated and len(unique_upstream) > 1:
        app_sublabel = f"{len(unique_upstream)} upstreams"
    elif is_aggregated and len(unique_dst_ips) > 1:
        app_sublabel = f"{len(unique_dst_ips)} dest IPs"

    app_tooltip_lines = []
    if unique_upstream:
        app_tooltip_lines.append(f"Upstreams: {', '.join(unique_upstream[:5])}")
    if unique_dst_ips:
        app_tooltip_lines.append(f"Dest IPs: {', '.join(unique_dst_ips[:5])}")
    if unique_authorities:
        app_tooltip_lines.append(f"FQDNs: {', '.join(unique_authorities[:5])}")

    # --- Build path ---

    # Path type 3: Internal → CE → App
    if not is_internet:
        nodes = [
            FlowNode(label="Client", icon="internal",
                     sublabel=client_sublabel,
                     detail=" · ".join(client_geo_parts) if client_geo_parts else "",
                     tooltip="\n".join(client_tooltip_lines)),
            FlowNode(label="CE", icon="ce",
                     sublabel=re_sublabel,
                     detail="Customer Edge",
                     tooltip="\n".join(re_tooltip_lines)),
        ]
        segments = [
            FlowSegment(label=tls_label,
                        latency_ms=rx_avg, latency_min=rx_min, latency_max=rx_max,
                        sample_count=rx_n,
                        tooltip=_build_latency_tooltip(rx_avg, rx_min, rx_max, rx_n)),
        ]

        if has_customer_edge and dst_site != src_site:
            ce_tooltip = f"Destination CE: {dst_site}"
            if is_aggregated and len(unique_dst_sites) > 1:
                ce_tooltip = f"CE sites: {', '.join(unique_dst_sites[:5])}"
            nodes.append(FlowNode(label="CE", icon="ce",
                                  sublabel=dst_site if len(unique_dst_sites) <= 1 else f"{len(unique_dst_sites)} CE sites",
                                  detail="Destination site",
                                  tooltip=ce_tooltip))
            segments.append(FlowSegment(label="tunnel",
                                        latency_ms=rtt_up_avg, latency_min=rtt_up_min, latency_max=rtt_up_max,
                                        sample_count=rtt_up_n,
                                        tooltip=_build_latency_tooltip(rtt_up_avg, rtt_up_min, rtt_up_max, rtt_up_n)))

        nodes.append(FlowNode(label="App", icon="app",
                               sublabel=authority or app_sublabel,
                               detail=app_sublabel if authority else "",
                               tooltip="\n".join(app_tooltip_lines)))
        segments.append(FlowSegment(label="",
                                    latency_ms=up_rx_avg, latency_min=up_rx_min, latency_max=up_rx_max,
                                    sample_count=up_rx_n,
                                    tooltip=_build_latency_tooltip(up_rx_avg, up_rx_min, up_rx_max, up_rx_n)))

        return FlowPath(
            path_type="internal-ce-app",
            path_label="Internal → CE → App",
            nodes=nodes, segments=segments,
            request_count=n_entries,
        )

    # Path type 2: Internet → RE → CE → App
    if has_customer_edge:
        ce_sublabel = dst_site
        ce_tooltip = f"CE site: {dst_site}"
        if is_aggregated and len(unique_dst_sites) > 1:
            ce_sublabel = f"{len(unique_dst_sites)} CE sites"
            ce_tooltip = f"CE sites: {', '.join(unique_dst_sites[:5])}"

        nodes = [
            FlowNode(label="Client", icon="internet",
                     sublabel=client_sublabel,
                     detail=" · ".join(client_geo_parts) if client_geo_parts else "",
                     tooltip="\n".join(client_tooltip_lines)),
            FlowNode(label="RE", icon="re",
                     sublabel=re_sublabel,
                     detail=authority or "",
                     tooltip="\n".join(re_tooltip_lines)),
            FlowNode(label="CE", icon="ce",
                     sublabel=ce_sublabel,
                     detail="Customer Edge",
                     tooltip=ce_tooltip),
            FlowNode(label="App", icon="app",
                     sublabel=app_sublabel,
                     detail="",
                     tooltip="\n".join(app_tooltip_lines)),
        ]
        segments = [
            FlowSegment(label=tls_label,
                        latency_ms=rtt_down_avg, latency_min=rtt_down_min, latency_max=rtt_down_max,
                        sample_count=rtt_down_n,
                        tooltip=_build_latency_tooltip(rtt_down_avg, rtt_down_min, rtt_down_max, rtt_down_n)),
            FlowSegment(label="tunnel",
                        latency_ms=rtt_up_avg, latency_min=rtt_up_min, latency_max=rtt_up_max,
                        sample_count=rtt_up_n,
                        tooltip=_build_latency_tooltip(rtt_up_avg, rtt_up_min, rtt_up_max, rtt_up_n)),
            FlowSegment(label="",
                        latency_ms=up_rx_avg, latency_min=up_rx_min, latency_max=up_rx_max,
                        sample_count=up_rx_n,
                        tooltip=_build_latency_tooltip(up_rx_avg, up_rx_min, up_rx_max, up_rx_n)),
        ]
        return FlowPath(
            path_type="internet-re-ce-app",
            path_label="Internet → RE → CE → App",
            nodes=nodes, segments=segments,
            request_count=n_entries,
        )

    # Path type 1: Internet → RE → App (default)
    nodes = [
        FlowNode(label="Client", icon="internet",
                 sublabel=client_sublabel,
                 detail=" · ".join(client_geo_parts) if client_geo_parts else "",
                 tooltip="\n".join(client_tooltip_lines)),
        FlowNode(label="RE", icon="re",
                 sublabel=re_sublabel,
                 detail=authority or "",
                 tooltip="\n".join(re_tooltip_lines)),
    ]
    segments = [
        FlowSegment(label=tls_label,
                    latency_ms=rtt_down_avg, latency_min=rtt_down_min, latency_max=rtt_down_max,
                    sample_count=rtt_down_n,
                    tooltip=_build_latency_tooltip(rtt_down_avg, rtt_down_min, rtt_down_max, rtt_down_n)),
    ]

    if not any_blocked:
        nodes.append(FlowNode(label="App", icon="app",
                               sublabel=authority or app_sublabel,
                               detail=app_sublabel if authority else "Origin via internet",
                               tooltip="\n".join(app_tooltip_lines)))
        segments.append(FlowSegment(label="",
                                    latency_ms=ttfb_avg, latency_min=ttfb_min, latency_max=ttfb_max,
                                    sample_count=ttfb_n,
                                    tooltip=_build_latency_tooltip(ttfb_avg, ttfb_min, ttfb_max, ttfb_n)))
    else:
        n_blocked = sum(1 for e in all_entries
                        if "block" in str(e.get("waf_action", "") or e.get("action", "")).lower())
        block_detail = "Blocked by WAF"
        if is_aggregated:
            block_detail = f"{n_blocked}/{n_entries} blocked by WAF"

        nodes.append(FlowNode(label="App", icon="app_blocked",
                               sublabel=authority or app_sublabel,
                               detail=block_detail,
                               tooltip="\n".join(app_tooltip_lines + [block_detail])))
        segments.append(FlowSegment(label="blocked", latency_ms=None, tooltip=block_detail))

    return FlowPath(
        path_type="internet-re-internet-app",
        path_label="Internet → RE → App",
        nodes=nodes, segments=segments,
        request_count=n_entries,
    )
