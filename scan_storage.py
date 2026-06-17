import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from recon_patterns import is_js_url

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOST_IN_LINE_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
    re.IGNORECASE,
)

FINDINGS_FILENAME = "findings.json"

CATEGORY_DIRS = {
    "subdomains": "subdomains",
    "urls": "urls",
    "ips": "ips",
    "buckets": "buckets",
    "sensitive": "sensitive",
    "js": "js",
}

TOOL_CATEGORY = {
    "Subfinder": "subdomains",
    "Assetfinder": "subdomains",
    "Findomain": "subdomains",
    "Amass Passive": "subdomains",
    "Amass Active": "subdomains",
    "crt.sh": "subdomains",
    "Wayback CDX": "subdomains",
    "SecurityTrails": "subdomains",
    "VirusTotal Subs": "subdomains",
    "GitHub Subs": "subdomains",
    "FFUF DNS": "subdomains",
    "GAU": "urls",
    "Katana": "urls",
    "URLFinder": "urls",
    "Hakrawler": "urls",
    "FFUF Path": "urls",
    "URL Param Filter": "urls",
    "VT IP Harvest": "ips",
    "OTX IP Harvest": "ips",
    "URLScan IP": "ips",
    "Shodan": "ips",
    "Cloud Buckets": "buckets",
    "Sensitive Files": "sensitive",
    "Arjun Params": "sensitive",
    "JS Recon": "js",
}

ROOT_FILENAMES = {
    "HTTP Probe": "http_probe.txt",
    "Takeover Check": "takeover_check.txt",
    "GitHub Secrets": "github_secrets.txt",
    "Aquatone": "aquatone.log",
}

ALL_TOOLS = sorted(set(TOOL_CATEGORY) | set(ROOT_FILENAMES))


def tool_slug(tool_name):
    return re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")


def sanitize_target(target):
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", target.strip().lower())


def default_workspace():
    return Path(__file__).parent / "scan_output"


def is_workspace_writable(workspace):
    try:
        root = Path(workspace).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".recon_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def resolve_workspace(workspace):
    candidate = Path(workspace).expanduser() if workspace else default_workspace()
    if is_workspace_writable(candidate):
        return str(candidate.resolve())
    fallback = default_workspace()
    fallback.mkdir(parents=True, exist_ok=True)
    return str(fallback.resolve())


def ensure_workspace(workspace):
    path = Path(workspace).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_scan_session(workspace, target):
    root = ensure_workspace(workspace)
    target_dir = root / sanitize_target(target)
    session_dir = target_dir / datetime.now().strftime("%Y-%m-%d_%H%M%S")
    session_dir.mkdir(parents=True, exist_ok=True)
    for folder in CATEGORY_DIRS.values():
        (session_dir / folder).mkdir(exist_ok=True)
    return session_dir


def save_session_meta(session_dir, meta):
    path = Path(session_dir) / "meta.json"
    payload = {
        "version": 1,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        **meta,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def read_session_meta(session_dir):
    path = Path(session_dir) / "meta.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def tool_output_path(session_dir, tool):
    session_dir = Path(session_dir)
    category = TOOL_CATEGORY.get(tool)
    filename = f"{tool_slug(tool)}.txt"
    if category:
        return session_dir / CATEGORY_DIRS[category] / filename
    root_name = ROOT_FILENAMES.get(tool, filename)
    return session_dir / root_name


def save_tool_output(session_dir, tool, content):
    if not session_dir or content is None:
        return None
    path = tool_output_path(session_dir, tool)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(content), encoding="utf-8")
    return path


def copy_aquatone_output(session_dir, aquatone_out_dir, log_text=""):
    session_dir = Path(session_dir)
    dest = session_dir / "aquatone"
    src = Path(aquatone_out_dir)
    if dest.exists():
        shutil.rmtree(dest)
    if src.is_dir():
        shutil.copytree(src, dest)
    log_path = session_dir / ROOT_FILENAMES["Aquatone"]
    log_path.write_text(log_text or "", encoding="utf-8")
    return dest


def list_sessions(workspace, target=None):
    root = Path(workspace)
    if not root.is_dir():
        return []
    sessions = []
    target_dirs = [root / sanitize_target(target)] if target else sorted(root.iterdir())
    for target_dir in target_dirs:
        if not target_dir.is_dir():
            continue
        for session_dir in target_dir.iterdir():
            if session_dir.is_dir() and (session_dir / "meta.json").is_file():
                sessions.append(session_dir)
    sessions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return sessions


def latest_session(workspace, target=None):
    sessions = list_sessions(workspace, target=target)
    return sessions[0] if sessions else None


def save_session_findings(session_dir, payload):
    if not session_dir:
        return None
    path = Path(session_dir) / FINDINGS_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def load_session_findings(session_dir):
    path = Path(session_dir) / FINDINGS_FILENAME
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_host_line(line, domain):
    line = ANSI_RE.sub("", line).strip()
    if not line or line.startswith("#"):
        return None
    lower = line.lower()
    if any(
        token in lower
        for token in (
            "searching in", "error", "target ==>", "no subdomains", "stderr",
            "failed to", "api...", "🔍", "❌",
        )
    ):
        return None
    if line.startswith("[") and "]" in line:
        line = line.split("]", 1)[1].strip()
    if " " in line and not line.startswith("http"):
        line = line.split()[0]
    line = line.strip().lower()
    if line.startswith("http://") or line.startswith("https://"):
        line = line.split("://", 1)[1].split("/")[0]
    line = line.lstrip("*.").rstrip(".")
    if domain and not (line == domain or line.endswith(f".{domain}")):
        return None
    return line if line.count(".") >= 1 else None


def _hosts_from_line(line, domain):
    hosts = []
    direct = _parse_host_line(line, domain)
    if direct:
        hosts.append(direct)
        return hosts
    for match in HOST_IN_LINE_RE.findall(line):
        host = match.lower().lstrip("*.").rstrip(".")
        if domain and (host == domain or host.endswith(f".{domain}")):
            if host.count(".") >= 1 and host not in hosts:
                hosts.append(host)
    return hosts


def _tool_name_from_file(path):
    slug = path.stem
    for tool in ALL_TOOLS:
        if tool_slug(tool) == slug:
            return tool
    return slug.replace("_", " ").title()


def parse_httpx_probe_line(line):
    line = ANSI_RE.sub("", line).strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        host = str(data.get("host") or data.get("input") or "").split(":")[0].lower()
        if not host:
            return None
        tech_list = data.get("tech") or []
        tech = ", ".join(tech_list) if isinstance(tech_list, list) else str(tech_list or "")
        status = data.get("status_code")
        return {
            "host": host,
            "status": str(status) if status is not None else "",
            "ip": str(data.get("host_ip") or "-"),
            "content_length": str(data.get("content_length", "")),
            "title": str(data.get("title") or ""),
            "tech": tech,
            "content_type": str(data.get("content_type") or ""),
            "is_ip": bool(IPV4_RE.match(host)),
        }

    url_match = re.match(r"^(https?://\S+)", line)
    if not url_match:
        return None
    from urllib.parse import urlparse
    host = urlparse(url_match.group(1)).netloc.split(":")[0].lower()
    fields = re.findall(r"\[([^\]]*)\]", line)
    if not fields:
        return None
    status = fields[0]
    content_length = fields[1] if len(fields) > 1 else ""
    content_type = fields[2] if len(fields) > 2 else ""
    title = ""
    ip = "-"
    tech = ""
    rest = [x for x in fields[3:] if x]
    if len(rest) == 1:
        if IPV4_RE.match(rest[0]):
            ip = rest[0]
        else:
            title = rest[0]
    elif len(rest) == 2:
        if IPV4_RE.match(rest[0]):
            ip, tech = rest[0], rest[1]
        elif IPV4_RE.match(rest[1]):
            title, ip = rest[0], rest[1]
        else:
            title, tech = rest[0], rest[1]
    elif len(rest) >= 3:
        title = rest[0]
        ip = rest[1] if IPV4_RE.match(rest[1]) else "-"
        tech = ", ".join(rest[2:])
    return {
        "host": host,
        "status": status,
        "ip": ip,
        "content_length": content_length,
        "title": title,
        "tech": tech,
        "content_type": content_type,
        "is_ip": bool(IPV4_RE.match(host)),
    }


def _parse_httpx_line(line):
    parsed = parse_httpx_probe_line(line)
    if not parsed:
        return None
    status = parsed["status"]
    try:
        status = int(status) if status else None
    except ValueError:
        status = None
    return parsed["host"], status, parsed["ip"]


def _ingest_subdomain_file(path, domain, ingest):
    tool = _tool_name_from_file(path)
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("# CMD:") or line.startswith("# STDERR"):
            continue
        for host in _hosts_from_line(line, domain):
            if host not in seen:
                seen.add(host)
                ingest("host", host, tool, "-", "-")


def _ingest_url_file(path, ingest):
    tool = _tool_name_from_file(path)
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind = "js" if is_js_url(line) else "url"
        ingest(kind, line, tool, "-")


def _ingest_ip_file(path, domain, ingest):
    tool = _tool_name_from_file(path)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        for ip in ip_re.findall(line):
            ingest("ip", ip, tool, domain)


def _ingest_bucket_file(path, ingest):
    tool = _tool_name_from_file(path)
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(https?://\S+)(?:\s+\[(\d+)\])?", line)
        if match:
            ingest("bucket", match.group(1), tool, match.group(2) or "-")
        elif line.startswith("http"):
            ingest("bucket", line.split()[0], tool, "-")


def _ingest_http_probe(path, ingest):
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_httpx_probe_line(line)
        if not parsed or not parsed.get("status"):
            continue
        if parsed.get("is_ip"):
            ingest("ip_probe", parsed["host"], "HTTP Probe", parsed["status"], parsed)
        else:
            ingest("host_probe", parsed["host"], "HTTP Probe", parsed["status"], parsed)


def _ingest_takeover(path, ingest):
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "->" in line:
            host, cname = [p.strip() for p in line.split("->", 1)]
            ingest("takeover", host, cname, f"Possible takeover — CNAME: {cname}")
        elif " " in line:
            parts = line.split()
            ingest("takeover", parts[0], parts[-1], f"Possible takeover — CNAME: {parts[-1]}")


def _ingest_sensitive_file(path, ingest):
    tool = _tool_name_from_file(path)
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            url, note = line.split("\t", 1)
            ingest("sensitive", url.strip(), tool, "-", note.strip())
        elif line.startswith("http"):
            ingest("sensitive", line.split()[0], tool, "-", "")


def _parse_js_file_entries(path):
    tool = _tool_name_from_file(path)
    entries = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            url, note = line.split("\t", 1)
            status = "secret" if note.strip() else "js"
            entries.append((url.strip(), status, note.strip()))
        elif line.startswith("http"):
            entries.append((line.split()[0], "js", ""))
    return tool, entries


def _ingest_js_file(path, ingest):
    tool, entries = _parse_js_file_entries(path)
    for url, status, note in entries:
        ingest("js", url, tool, status, note)


def _supplement_js_from_disk(session_dir, ingest):
    js_dir = session_dir / "js"
    if not js_dir.is_dir():
        return
    jsfiles = js_dir / "jsfiles.txt"
    paths = [jsfiles] if jsfiles.is_file() else sorted(js_dir.glob("*.txt"))
    entries = []
    tool = "JS Recon"
    for path in paths:
        if not path.is_file():
            continue
        file_tool, file_entries = _parse_js_file_entries(path)
        if file_entries:
            tool = file_tool
            entries.extend(file_entries)
    if entries:
        ingest("js_batch", entries, tool)


def load_session_from_disk(session_dir, ingest):
    session_dir = Path(session_dir)
    meta = read_session_meta(session_dir)
    domain = meta.get("target", "")

    findings = load_session_findings(session_dir)
    if findings and findings.get("results"):
        for row in findings["results"]:
            kind = row.get("type")
            value = row.get("value", "")
            tool = row.get("tools", "")
            status = row.get("status", "-")
            if kind == "host":
                ingest("host", value, tool, status, row.get("ip", "-"))
            elif kind == "url":
                ingest("url", value, tool, status)
            elif kind == "ip":
                ingest("ip", value, tool, row.get("related", domain))
            elif kind == "bucket":
                ingest("bucket", value, tool, status)
            elif kind == "sensitive":
                ingest("sensitive", value, tool, status, row.get("note", ""))
            elif kind == "js":
                ingest("js", value, tool, status, row.get("note", ""))
        _supplement_js_from_disk(session_dir, ingest)
        return {**meta, **findings}

    sub_dir = session_dir / "subdomains"
    if sub_dir.is_dir():
        for path in sorted(sub_dir.glob("*.txt")):
            _ingest_subdomain_file(path, domain, ingest)

    for folder, handler in (
        ("urls", lambda p: _ingest_url_file(p, ingest)),
        ("ips", lambda p: _ingest_ip_file(p, domain, ingest)),
        ("buckets", lambda p: _ingest_bucket_file(p, ingest)),
        ("sensitive", lambda p: _ingest_sensitive_file(p, ingest)),
        ("js", lambda p: _ingest_js_file(p, ingest)),
    ):
        dir_path = session_dir / folder
        if dir_path.is_dir():
            for path in sorted(dir_path.glob("*.txt")):
                handler(path)

    probe = session_dir / ROOT_FILENAMES["HTTP Probe"]
    if probe.is_file():
        _ingest_http_probe(probe, ingest)

    takeover = session_dir / ROOT_FILENAMES["Takeover Check"]
    if takeover.is_file():
        _ingest_takeover(takeover, ingest)

    aquatone_dir = session_dir / "aquatone" / "screenshots"
    if aquatone_dir.is_dir():
        for png in aquatone_dir.glob("*.png"):
            stem = png.stem.lower()
            host = stem.replace("__", ".").replace("_", ".")
            host = re.sub(r"\.(\d+)$", "", host)
            if host.count(".") >= 1:
                ingest("screenshot", host, str(png.resolve()))

    return meta
