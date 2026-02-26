"""
Report section generation — format research results for Markdown reports.
"""

from __future__ import annotations

__all__ = ["generate_research_report_section"]


def generate_research_report_section(results: list[dict], queries: list[str]) -> list[str]:
    """Generate the Public Research section for the Markdown report (collapsed)."""
    lines = [
        "<details>",
        f"<summary><strong>Public Research — F5 Documentation & Community ({len(results)} results)</strong></summary>",
        "",
    ]

    if not results:
        lines += [
            "No relevant public articles found.",
            "",
            f"Search queries used: {', '.join(f'`{q}`' for q in queries)}",
            "", "</details>", "",
        ]
        return lines

    lines += [f"Found **{len(results)} article(s)** from F5 public sources that may be relevant.", ""]

    by_query: dict[str, list[dict]] = {}
    for r in results:
        by_query.setdefault(r.get("query", "General"), []).append(r)

    for query, qresults in by_query.items():
        lines += [f"**Search: `{query}`**", ""]
        for r in qresults:
            title, url, snippet = r.get("title", "Untitled"), r.get("url", ""), r.get("snippet", "")
            lines.append(f"- [{title}]({url})" if url else f"- {title}")
            if snippet:
                lines.append(f"  > {snippet[:200]}{'...' if len(snippet) > 200 else ''}")
            lines.append("")

    lines += ["</details>", ""]
    return lines
