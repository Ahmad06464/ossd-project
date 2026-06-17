import html
import json
from pathlib import Path

from scan_import_export import format_scan_time


def export_html(path, results, target="", meta=None, import_payload=None):
    meta = meta or {}
    hosts = [r for r in results if r.get("type") == "host"]
    urls = [r for r in results if r.get("type") == "url"]
    ips = [r for r in results if r.get("type") == "ip"]
    buckets = [r for r in results if r.get("type") == "bucket"]
    scan_time = format_scan_time(meta.get("scan_completed_at", ""))
    exported = meta.get("generated", meta.get("exported_at", ""))

    def rows(items, columns):
        body = []
        for row in items:
            cells = []
            for col in columns:
                val = html.escape(str(row.get(col, "") or ""))
                if col == "screenshot" and val:
                    uri = Path(row.get("screenshot", "")).as_uri()
                    cells.append(f'<td><a href="{uri}"><img src="{uri}" width="120"></a></td>')
                elif col == "value" and val.startswith("http"):
                    cells.append(f'<td><a href="{val}">{val}</a></td>')
                else:
                    cells.append(f"<td>{val}</td>")
            body.append("<tr>" + "".join(cells) + "</tr>")
        return "\n".join(body)

    json_block = json.dumps(import_payload) if import_payload else "{}"
    doc = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Recon Report — {html.escape(target)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #1a1a2e; color: #eee; }}
h1,h2 {{ color: #7ec8e3; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 28px; }}
th, td {{ border: 1px solid #444; padding: 8px; text-align: left; font-size: 13px; }}
th {{ background: #16213e; }}
tr:nth-child(even) {{ background: #0f3460; }}
.meta {{ color: #aaa; margin-bottom: 20px; }}
</style></head><body>
<h1>Recon Report: {html.escape(target)}</h1>
<div class="meta">Scan completed: {html.escape(scan_time)} | Exported: {html.escape(str(exported))} | Profile: {html.escape(meta.get("profile", ""))} | Hosts: {len(hosts)} | URLs: {len(urls)} | IPs: {len(ips)} | Buckets: {len(buckets)}</div>

<h2>Subdomains ({len(hosts)})</h2>
<table><tr><th>Host</th><th>Found By</th><th>Status</th><th>IP</th><th>Screenshot</th><th>Note</th></tr>
{rows(hosts, ["value", "tools", "status", "ip", "screenshot", "note"])}</table>

<h2>URLs ({len(urls)})</h2>
<table><tr><th>URL</th><th>Tool</th><th>Status</th><th>Note</th></tr>
{rows(urls, ["value", "tools", "status", "note"])}</table>

<h2>IPs ({len(ips)})</h2>
<table><tr><th>IP</th><th>Tool</th><th>Related</th><th>Note</th></tr>
{rows(ips, ["value", "tools", "related", "note"])}</table>

<h2>Cloud Buckets ({len(buckets)})</h2>
<table><tr><th>Bucket</th><th>Status</th><th>Tool</th><th>Note</th></tr>
{rows(buckets, ["value", "status", "tools", "note"])}</table>
<script type="application/json" id="recon-scan-export">
{json_block}
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(doc)
