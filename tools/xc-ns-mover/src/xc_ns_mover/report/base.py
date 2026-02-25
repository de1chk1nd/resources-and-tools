"""
Shared HTML report helpers — CSS, JS, escaping, and page scaffold.

Both the scanner and mover reports use these building blocks so that
styles, scripts, and the overall page structure stay consistent.
"""

from __future__ import annotations

import html as _html_mod


def esc(s: str) -> str:
    """HTML-escape a string (convenience wrapper)."""
    return _html_mod.escape(s)


# ------------------------------------------------------------------
# JavaScript helpers
# ------------------------------------------------------------------

def copy_to_clipboard_js() -> str:
    """Return a <script> block with clipboard-copy helpers.

    Provides:
      - copyJson(btn)  — copies the sibling <pre class="json-block">
      - copyCsv(btn)   — copies <pre id="csv-content">
    Both use navigator.clipboard with a textarea fallback.
    """
    return """\
<script>
function _doCopy(btn, text, labelOk, labelFail) {
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = labelOk;
      btn.classList.remove('copied');
    }, 2000);
  }, function() {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() {
        btn.textContent = labelOk;
        btn.classList.remove('copied');
      }, 2000);
    } catch(e) {
      btn.textContent = labelFail;
      setTimeout(function() { btn.textContent = labelOk; }, 2000);
    }
    document.body.removeChild(ta);
  });
}
function copyJson(btn) {
  var pre = btn.parentElement.querySelector('pre.json-block');
  if (!pre) return;
  _doCopy(btn, pre.textContent || pre.innerText, 'Copy JSON', 'Failed');
}
function copyCsv(btn) {
  var pre = document.getElementById('csv-content');
  if (!pre) return;
  _doCopy(btn, pre.textContent || pre.innerText, 'Copy CSV', 'Failed');
}
</script>"""


# ------------------------------------------------------------------
# Shared CSS
# ------------------------------------------------------------------

#: Base CSS used by both scanner and mover reports (body, h1, h2, meta,
#: tables, summary cards, copy-btn, json-block, footer).
BASE_CSS = """\
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 2rem; color: #1a1a1a; background: #f8f9fa; }
  h1 { color: #0d6efd; margin-bottom: 0.25rem; }
  h2 { color: #333; margin-top: 2rem; margin-bottom: 1rem; }
  .meta { color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; }

  /* --- Summary cards --- */
  .summary { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
  .summary .card { background: #fff; border: 1px solid #dee2e6; border-radius: 8px;
                    padding: 0.75rem 1.25rem; min-width: 110px; text-align: center;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
  .summary .card .num { font-size: 1.6rem; font-weight: 700; }
  .summary .card .label { font-size: 0.75rem; color: #666; text-transform: uppercase;
                           letter-spacing: 0.03em; margin-top: 0.15rem; }

  /* --- Table --- */
  table { border-collapse: collapse; width: 100%; background: #fff;
           border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden;
           margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
  th { background: #0d6efd; color: #fff; padding: 0.6rem 0.75rem;
       text-align: left; font-size: 0.8rem; text-transform: uppercase;
       letter-spacing: 0.03em; }
  td { padding: 0.45rem 0.75rem; border-top: 1px solid #e9ecef; font-size: 0.85rem; }
  tr:hover td { background: #f0f4ff; }

  /* --- Copy button --- */
  .copy-btn { background: #495057; color: #fff; border: 1px solid #6c757d;
              border-radius: 4px; padding: 0.25rem 0.6rem; font-size: 0.75rem;
              cursor: pointer; font-family: inherit;
              transition: background 0.15s, border-color 0.15s; }
  .copy-btn:hover { background: #6c757d; border-color: #adb5bd; }
  .copy-btn.copied { background: #198754; border-color: #198754; }

  /* --- JSON / code block --- */
  .json-block { background: #1e1e1e; color: #d4d4d4; padding: 1rem;
                border-radius: 0 0 6px 6px; overflow-x: auto; font-size: 0.8rem;
                line-height: 1.4; margin-top: 0; border: 1px solid #dee2e6;
                border-top: none; white-space: pre; }
  .json-block-wrapper { position: relative; }
  .json-block-wrapper .copy-btn { position: absolute; top: 0.5rem; right: 0.5rem; z-index: 10; }

  footer { margin-top: 2rem; font-size: 0.8rem; color: #888; }
"""


def render_html_page(
    title: str,
    meta_line: str,
    body_html: str,
    extra_css: str = "",
    extra_js: str = "",
) -> str:
    """Wrap *body_html* in a full HTML page with shared styles and scripts.

    Parameters
    ----------
    title : str
        Page ``<title>`` (already escaped by the caller).
    meta_line : str
        HTML snippet shown below ``<h1>`` (tenant, timestamp, etc.).
    body_html : str
        The main page content (everything between the meta line and footer).
    extra_css : str
        Additional ``<style>`` content appended after *BASE_CSS*.
    extra_js : str
        Additional ``<script>`` blocks inserted before ``</body>``.
    """
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
{BASE_CSS}
{extra_css}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">
{meta_line}
</div>

{body_html}

<footer>Generated by xc-ns-mover</footer>
{copy_to_clipboard_js()}
{extra_js}
</body>
</html>
"""
