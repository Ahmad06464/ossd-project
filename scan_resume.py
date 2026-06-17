"""Scan resume — save/import partial progress and continue from the next tool."""

from scan_runner import SCAN_PROFILES, TOOL_NAMES

FINISHED_STATUSES = frozenset({"Done", "Skipped", "Error"})


def pipeline_for_profile(profile, selected_tools=None):
    selected = set(selected_tools or SCAN_PROFILES.get(profile, TOOL_NAMES))
    ordered = []
    seen = set()
    for tool in TOOL_NAMES:
        if tool in selected and tool not in seen:
            ordered.append(tool)
            seen.add(tool)
    return ordered


def infer_completed_tools(data, selected_tools=None):
    explicit = data.get("completed_tools") or []
    if explicit:
        return [t for t in explicit if t in TOOL_NAMES]

    tool_statuses = data.get("tool_statuses") or {}
    from_statuses = [
        tool for tool, status in tool_statuses.items()
        if tool in TOOL_NAMES and status in FINISHED_STATUSES
    ]
    if from_statuses:
        pipeline = pipeline_for_profile(data.get("profile", "Full"), selected_tools)
        return [t for t in pipeline if t in from_statuses]

    tools_with_findings = set()
    for row in data.get("results") or []:
        tool = row.get("tools") or ""
        if isinstance(tool, list):
            tool = tool[0] if tool else ""
        tool = str(tool).split(",")[0].strip()
        if tool:
            tools_with_findings.add(tool)

    if not tools_with_findings:
        return []

    pipeline = pipeline_for_profile(data.get("profile", "Full"), selected_tools)
    completed = []
    for tool in pipeline:
        if tool in tools_with_findings:
            completed.append(tool)
        else:
            break
    return completed


def next_resume_tool(completed_tools, profile, selected_tools=None):
    completed = set(completed_tools or [])
    for tool in pipeline_for_profile(profile, selected_tools):
        if tool not in completed:
            return tool
    return ""


def build_runner_state_from_ui(hosts, urls, sensitive=None, js_files=None, domain=""):
    sensitive = sensitive or {}
    js_files = js_files or {}
    domain = (domain or "").strip().lower()

    subdomains = {}
    live_hosts = []
    host_ips = {}
    host_probe_status = {}
    screenshots = {}

    for host, data in hosts.items():
        if domain and not (host == domain or host.endswith(f".{domain}")):
            continue
        sources = data.get("sources") or []
        subdomains[host] = list(sources) if isinstance(sources, list) else [str(sources)]
        status = str(data.get("status", "")).strip()
        if status and status != "-":
            live_hosts.append(host)
            host_probe_status[host] = status
        ip = data.get("ip", "-")
        if ip and ip != "-":
            host_ips[host] = ip
        shot = data.get("screenshot", "")
        if shot:
            screenshots[host] = shot

    collected_urls = set(urls.keys())
    collected_urls.update(sensitive.keys())
    collected_urls.update(js_files.keys())

    return {
        "subdomains": subdomains,
        "live_hosts": sorted(set(live_hosts)),
        "host_ips": host_ips,
        "host_probe_status": host_probe_status,
        "collected_urls": sorted(collected_urls),
        "screenshots": screenshots,
    }


def extract_resume_fields(data, selected_tools=None):
    profile = data.get("profile", "Full")
    scan_status = data.get("scan_status", "")
    explicit_resume = data.get("resume_from_tool", "")

    if scan_status == "complete":
        return {
            "scan_status": "complete",
            "completed_tools": infer_completed_tools(data, selected_tools),
            "resume_from_tool": "",
            "tool_statuses": data.get("tool_statuses") or {},
            "runner_state": data.get("runner_state") or {},
            "session_dir": data.get("session_dir") or "",
            "target": (data.get("target") or "").strip().lower(),
            "tool_counts": dict(data.get("tool_counts") or {}),
        }

    if data.get("scan_completed_at") and scan_status != "partial" and not explicit_resume:
        return {
            "scan_status": "complete",
            "completed_tools": infer_completed_tools(data, selected_tools),
            "resume_from_tool": "",
            "tool_statuses": data.get("tool_statuses") or {},
            "runner_state": data.get("runner_state") or {},
            "session_dir": data.get("session_dir") or "",
            "target": (data.get("target") or "").strip().lower(),
            "tool_counts": dict(data.get("tool_counts") or {}),
        }

    completed_tools = infer_completed_tools(data, selected_tools)
    resume_from = explicit_resume or next_resume_tool(completed_tools, profile, selected_tools)

    if not resume_from:
        return {
            "scan_status": "complete",
            "completed_tools": completed_tools,
            "resume_from_tool": "",
            "tool_statuses": data.get("tool_statuses") or {},
            "runner_state": data.get("runner_state") or {},
            "session_dir": data.get("session_dir") or "",
            "target": (data.get("target") or "").strip().lower(),
            "tool_counts": dict(data.get("tool_counts") or {}),
        }

    return {
        "scan_status": "partial",
        "completed_tools": completed_tools,
        "resume_from_tool": resume_from,
        "tool_statuses": data.get("tool_statuses") or {},
        "runner_state": data.get("runner_state") or {},
        "session_dir": data.get("session_dir") or "",
        "target": (data.get("target") or "").strip().lower(),
        "tool_counts": dict(data.get("tool_counts") or {}),
    }


def capture_resume_state(
    *,
    profile,
    selected_tools,
    tool_statuses,
    completed_tools,
    hosts,
    urls,
    sensitive=None,
    js_files=None,
    domain="",
    runner_state=None,
    session_dir="",
    scan_completed_at="",
    tool_counts=None,
):
    completed = list(completed_tools or [])
    resume_from = next_resume_tool(completed, profile, selected_tools)

    statuses = dict(tool_statuses or {})
    for tool, status in list(statuses.items()):
        if status == "Running":
            statuses[tool] = "Pending"
            if tool in completed:
                completed = [t for t in completed if t != tool]

    if not runner_state:
        runner_state = build_runner_state_from_ui(
            hosts, urls, sensitive=sensitive, js_files=js_files, domain=domain,
        )

    scan_status = "complete"
    if resume_from:
        scan_status = "partial"
    elif not scan_completed_at:
        scan_status = "partial" if completed else "complete"

    return {
        "scan_status": scan_status,
        "completed_tools": completed,
        "resume_from_tool": resume_from,
        "tool_statuses": statuses,
        "runner_state": runner_state,
        "session_dir": str(session_dir) if session_dir else "",
        "target": (domain or "").strip().lower(),
        "tool_counts": dict(tool_counts or {}),
    }


def can_resume(resume_state):
    if not resume_state:
        return False
    if resume_state.get("scan_status") == "complete":
        return False
    return bool(resume_state.get("resume_from_tool"))
