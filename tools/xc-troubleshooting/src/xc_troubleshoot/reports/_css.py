"""Embedded CSS for the HTML report. Separated to reduce noise in the generator."""

CSS = """
:root {
  --f5-blue: #0072c6; --f5-dark: #1a1a2e; --f5-light: #f4f6f9;
  --green: #28a745; --red: #dc3545; --orange: #fd7e14;
  --yellow: #ffc107; --gray: #6c757d; --border: #dee2e6;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  color: #333; background: #fff; line-height: 1.6; font-size: 14px;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
header {
  background: linear-gradient(135deg, var(--f5-dark), var(--f5-blue));
  color: #fff; padding: 32px 0; margin-bottom: 32px;
}
header .container { display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 22px; font-weight: 600; letter-spacing: -0.3px; }
header .meta { font-size: 12px; opacity: 0.85; text-align: right; }
header .meta div { margin-bottom: 2px; }
.verdict {
  padding: 16px 24px; border-radius: 8px; margin-bottom: 24px;
  font-size: 15px; font-weight: 600;
}
.verdict.blocked { background: #f8d7da; color: #721c24; border-left: 5px solid var(--red); }
.verdict.monitored { background: #fff3cd; color: #856404; border-left: 5px solid var(--yellow); }
.verdict.allowed { background: #d4edda; color: #155724; border-left: 5px solid var(--green); }
.verdict.nodata { background: var(--f5-light); color: var(--gray); border-left: 5px solid var(--gray); }
.verdict.info { background: #d1ecf1; color: #0c5460; border-left: 5px solid var(--f5-blue); }
h2 {
  font-size: 16px; font-weight: 600; color: var(--f5-dark);
  border-bottom: 2px solid var(--f5-blue); padding-bottom: 6px;
  margin: 28px 0 16px 0;
}
h3 { font-size: 14px; font-weight: 600; margin: 12px 0 8px 0; }
.info-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px 24px;
  margin-bottom: 20px;
}
.info-grid .item { display: flex; gap: 8px; }
.info-grid .label {
  font-weight: 600; color: var(--gray); min-width: 120px;
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px;
}
.info-grid .value { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; word-break: break-all; }
.metrics {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin-bottom: 20px;
}
.metric-card { background: var(--f5-light); border-radius: 8px; padding: 16px; text-align: center; }
.metric-card .number { font-size: 28px; font-weight: 700; color: var(--f5-blue); }
.metric-card .label {
  font-size: 11px; color: var(--gray); text-transform: uppercase;
  letter-spacing: 0.5px; margin-top: 4px;
}
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px; }
th {
  background: var(--f5-light); text-align: left; padding: 8px 12px;
  font-weight: 600; font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.3px; color: var(--gray); border-bottom: 2px solid var(--border);
}
td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: #f8f9fa; }
td.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 600; text-transform: uppercase;
}
.badge.block { background: #f8d7da; color: #721c24; }
.badge.report { background: #fff3cd; color: #856404; }
.badge.allow { background: #d4edda; color: #155724; }
.badge.code-4xx { background: #fff3cd; color: #856404; }
.badge.code-5xx { background: #f8d7da; color: #721c24; }
.badge.code-2xx { background: #d4edda; color: #155724; }
.badge.code-3xx { background: #d1ecf1; color: #0c5460; }
details { margin-bottom: 8px; }
details summary {
  cursor: pointer; padding: 10px 16px; background: var(--f5-light);
  border-radius: 6px; font-size: 13px; font-weight: 500;
  border: 1px solid var(--border); user-select: none;
}
details summary:hover { background: #e9ecef; }
details[open] summary { border-radius: 6px 6px 0 0; border-bottom: none; }
details .detail-content {
  padding: 16px; border: 1px solid var(--border);
  border-top: none; border-radius: 0 0 6px 6px;
}
.hints { margin-bottom: 20px; }
.hint {
  padding: 10px 14px; margin-bottom: 6px; border-radius: 6px;
  font-size: 13px; border-left: 4px solid var(--f5-blue); background: #f0f7ff;
}
.hint.warn { border-left-color: var(--orange); background: #fff8f0; }
.hint.error { border-left-color: var(--red); background: #fff5f5; }
.hint strong { font-weight: 600; }
.hint .sub { margin-left: 16px; font-size: 12px; color: #555; margin-top: 3px; }
.finding-card { margin-bottom: 6px; }
.finding-card summary.hint { border-radius: 6px; cursor: pointer; }
.finding-card[open] summary.hint { border-radius: 6px 6px 0 0; border-bottom: none; }
.finding-card .detail-content ul { margin: 4px 0 8px 20px; font-size: 13px; }
.finding-card .detail-content li { margin-bottom: 3px; }
pre {
  background: #1e1e2e; color: #cdd6f4; padding: 16px; border-radius: 6px;
  overflow-x: auto; font-size: 12px; font-family: 'SF Mono', 'Fira Code', monospace;
  line-height: 1.5;
}
.research-item { padding: 8px 0; border-bottom: 1px solid var(--border); }
.research-item:last-child { border-bottom: none; }
.research-item a { color: var(--f5-blue); text-decoration: none; font-weight: 500; }
.research-item a:hover { text-decoration: underline; }
.research-item .snippet { font-size: 12px; color: #666; margin-top: 2px; }
footer {
  margin-top: 40px; padding: 16px 0; border-top: 1px solid var(--border);
  font-size: 11px; color: var(--gray); text-align: center;
}
@media print {
  header { background: #333 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .container { max-width: 100%; padding: 12px; }
  details[open] summary ~ .detail-content { display: block; }
  body { font-size: 11px; }
}
"""
