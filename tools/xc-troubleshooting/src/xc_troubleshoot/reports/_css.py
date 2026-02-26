"""Embedded CSS for the HTML report — aligned with xc-ns-mover design language."""

CSS = """
*, *::before, *::after { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0; color: #1a1a1a; background: #f4f6f9; line-height: 1.65; font-size: 15px; }

/* --- Header (local variant — gradient kept) --- */
header {
  background: linear-gradient(135deg, #1a1a2e, #0d6efd);
  color: #fff; padding: 32px 0; margin-bottom: 2.5rem;
}
header .container { display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.3px; margin: 0; }
header .meta { font-size: 0.82rem; opacity: 0.85; text-align: right; }
header .meta div { margin-bottom: 2px; }

.container { max-width: 1400px; margin: 0 auto; padding: 0 2.5rem; }
.body-container { max-width: 1400px; margin: 0 auto; padding: 0 2.5rem 2.5rem; }

/* --- Section headers --- */
h2 {
  color: #1a1a1a; margin-top: 2.5rem; margin-bottom: 1.25rem;
  font-size: 1.35rem; font-weight: 700; letter-spacing: -0.3px;
  padding-bottom: 0.6rem; border-bottom: 2px solid #0d6efd;
}
h3 { font-size: 1rem; font-weight: 600; margin: 16px 0 10px 0; color: #333; }

/* --- Section wrapper (visual separation between chapters) --- */
.section {
  background: #fff; border: 1px solid #dee2e6; border-radius: 10px;
  padding: 1.75rem 2rem; margin-bottom: 2rem;
  box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.section > h2:first-child { margin-top: 0; }

/* --- Info grid (search params) --- */
.info-grid {
  display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px 28px;
  margin-bottom: 2rem; background: #fff; border: 1px solid #dee2e6;
  border-radius: 10px; padding: 1.25rem 1.5rem;
  box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.info-grid .item { display: flex; gap: 8px; align-items: baseline; }
.info-grid .label {
  font-weight: 600; color: #888; min-width: 120px;
  font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em;
}
.info-grid .value { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                     font-size: 0.85rem; word-break: break-all; color: #1a1a1a; }

/* --- Health / verdict banner (traffic-light) --- */
.health-banner {
  display: flex; align-items: flex-start; gap: 1.5rem;
  padding: 1.5rem 1.75rem; border-radius: 12px;
  margin-bottom: 2rem; border: 1px solid;
  box-shadow: 0 2px 10px rgba(0,0,0,0.08);
}
.health-light {
  flex-shrink: 0; width: 60px; height: 60px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.7rem; color: #fff;
  box-shadow: 0 0 0 4px rgba(255,255,255,0.6), 0 0 14px rgba(0,0,0,0.12);
}
.health-body { flex: 1; min-width: 0; }
.health-headline { font-size: 1.2rem; font-weight: 700; margin: 0 0 0.35rem 0; }
.health-stats { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.6rem; }
.health-pill {
  display: inline-block; padding: 0.2rem 0.65rem; border-radius: 12px;
  font-size: 0.82rem; font-weight: 600; background: rgba(255,255,255,0.65);
  border: 1px solid rgba(0,0,0,0.1);
}
.health-red    { background: #f8d7da; color: #721c24; border-color: #f1aeb5; }
.health-red    .health-light { background: #dc3545; }
.health-red    .health-pill  { color: #721c24; }
.health-yellow { background: #fff3cd; color: #664d03; border-color: #ffe69c; }
.health-yellow .health-light { background: #ffc107; color: #664d03; }
.health-yellow .health-pill  { color: #664d03; }
.health-green  { background: #d4edda; color: #155724; border-color: #b7dfb9; }
.health-green  .health-light { background: #28a745; }
.health-green  .health-pill  { color: #155724; }
.health-grey   { background: #e9ecef; color: #495057; border-color: #ced4da; }
.health-grey   .health-light { background: #6c757d; }
.health-grey   .health-pill  { color: #495057; }
.health-blue   { background: #d1ecf1; color: #0c5460; border-color: #bee5eb; }
.health-blue   .health-light { background: #0d6efd; }
.health-blue   .health-pill  { color: #0c5460; }

/* --- Warning banner (API errors) --- */
.warning-banner { background: #fff3cd; border: 1px solid #ffc107; border-left: 5px solid #ffc107;
                   border-radius: 8px; padding: 1.1rem 1.5rem; margin-bottom: 2rem; font-size: 0.92rem; }
.warning-banner strong { color: #856404; }
.warning-banner ul { margin: 0.5rem 0 0 1.25rem; padding: 0; }
.warning-banner li { margin-bottom: 0.25rem; }

/* --- Summary cards --- */
.summary { display: flex; flex-wrap: wrap; gap: 1.25rem; margin-bottom: 2rem; }
.summary .card { background: #fff; border: 1px solid #dee2e6; border-radius: 10px;
                  padding: 1rem 1.5rem; min-width: 130px; text-align: center; flex: 1;
                  box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
.summary .card .num { font-size: 2rem; font-weight: 700; }
.summary .card .label { font-size: 0.78rem; color: #666; text-transform: uppercase;
                         letter-spacing: 0.03em; margin-top: 0.2rem; }
.card-primary .num { color: #0d6efd; }
.card-blocked .num { color: #dc3545; }
.card-reported .num { color: #e67e22; }
.card-access .num { color: #198754; }
.card-ips .num { color: #6f42c1; }
.card-reqs .num { color: #0dcaf0; }

/* --- Table --- */
table { border-collapse: collapse; width: 100%; background: #fff;
         border: 1px solid #dee2e6; border-radius: 10px; overflow: hidden;
         margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
th { background: #0d6efd; color: #fff; padding: 0.7rem 1rem;
     text-align: left; font-size: 0.82rem; text-transform: uppercase;
     letter-spacing: 0.03em; }
td { padding: 0.55rem 1rem; border-top: 1px solid #e9ecef; font-size: 0.88rem;
     vertical-align: top; }
tr:hover td { background: #f0f4ff; }
td.mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 0.82rem; }

/* --- Badges --- */
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 5px;
  font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
}
.badge.block { background: #f8d7da; color: #721c24; }
.badge.report { background: #fff3cd; color: #856404; }
.badge.allow { background: #d4edda; color: #155724; }
.badge.code-2xx { background: #d4edda; color: #155724; }
.badge.code-3xx { background: #d1ecf1; color: #0c5460; }
.badge.code-4xx { background: #fff3cd; color: #856404; }
.badge.code-5xx { background: #f8d7da; color: #721c24; }

/* --- Details / collapsibles --- */
details { margin-bottom: 0.85rem; }
details summary {
  cursor: pointer; padding: 0.65rem 1rem; background: #fff;
  border: 1px solid #dee2e6; border-radius: 8px; font-weight: 600;
  font-size: 0.92rem; transition: background 0.15s;
}
details summary:hover { background: #f0f4ff; }
details[open] summary { border-radius: 8px 8px 0 0; border-bottom: none; }
details .detail-content {
  padding: 1.25rem; border: 1px solid #dee2e6;
  border-top: none; border-radius: 0 0 8px 8px; background: #fff;
}

/* --- Sub-details (nested collapsibles, e.g. LB config under services) --- */
details.sub-section summary {
  background: #f8f9fa; font-size: 0.88rem; padding: 0.55rem 0.9rem;
  border-color: #e2e6ea;
}
details.sub-section summary:hover { background: #eef2f7; }
details.sub-section .detail-content { background: #fafbfc; padding: 1rem; }

/* --- Finding cards --- */
.hints { margin-bottom: 2rem; }
.hint {
  padding: 0.7rem 1rem; margin-bottom: 0; border-radius: 8px;
  font-size: 0.92rem; border-left: 4px solid #0d6efd; background: #f0f4ff;
}
.hint.warn { border-left-color: #e67e22; background: #fff8f0; }
.hint.error { border-left-color: #dc3545; background: #fff5f5; }
.hint strong { font-weight: 600; }
.hint .sub { margin-left: 16px; font-size: 0.82rem; color: #555; margin-top: 3px; }
.finding-card { margin-bottom: 0.6rem; }
.finding-card summary.hint { border-radius: 8px; cursor: pointer; }
.finding-card[open] summary.hint { border-radius: 8px 8px 0 0; border-bottom: none; }
.finding-card .detail-content ul { margin: 4px 0 8px 20px; font-size: 0.92rem; }
.finding-card .detail-content li { margin-bottom: 4px; }

/* --- Copy button --- */
.copy-btn { background: #495057; color: #fff; border: 1px solid #6c757d;
            border-radius: 5px; padding: 0.3rem 0.7rem; font-size: 0.78rem;
            cursor: pointer; font-family: inherit;
            transition: background 0.15s, border-color 0.15s; }
.copy-btn:hover { background: #6c757d; border-color: #adb5bd; }
.copy-btn.copied { background: #198754; border-color: #198754; }

/* --- JSON / code block --- */
pre.json-block { background: #1e1e1e; color: #d4d4d4; padding: 1.25rem;
                  border-radius: 0 0 8px 8px; overflow-x: auto; font-size: 0.82rem;
                  line-height: 1.45; margin-top: 0; border: 1px solid #dee2e6;
                  border-top: none; white-space: pre;
                  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
pre.legacy { background: #1e1e1e; color: #d4d4d4; padding: 1.25rem; border-radius: 8px;
             overflow-x: auto; font-size: 0.82rem; line-height: 1.45;
             font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
.json-block-wrapper { position: relative; }
.json-block-wrapper .copy-btn { position: absolute; top: 0.5rem; right: 0.5rem; z-index: 10; }

/* --- Research --- */
.research-item { padding: 10px 0; border-bottom: 1px solid #dee2e6; }
.research-item:last-child { border-bottom: none; }
.research-item a { color: #0d6efd; text-decoration: none; font-weight: 500; }
.research-item a:hover { text-decoration: underline; }
.research-item .snippet { font-size: 0.82rem; color: #666; margin-top: 3px; }

/* --- Footer --- */
footer { margin-top: 2.5rem; font-size: 0.82rem; color: #888; padding-bottom: 1.5rem;
         border-top: 1px solid #dee2e6; padding-top: 1rem; }

/* --- Two-column grid for breakdowns --- */
.breakdown-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 28px; margin-bottom: 2rem;
}
@media (max-width: 800px) {
  .breakdown-grid { grid-template-columns: 1fr; }
  .info-grid { grid-template-columns: 1fr 1fr; }
}

@media print {
  header { background: #333 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .body-container { max-width: 100%; padding: 12px; }
  details[open] summary ~ .detail-content { display: block; }
  body { font-size: 12px; }
  .section { box-shadow: none; border: 1px solid #ccc; }
}
"""
