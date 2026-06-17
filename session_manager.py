import json
from datetime import datetime, timezone
from pathlib import Path

SESSION_VERSION = 1


def save_session(path, payload):
    data = {
        "version": SESSION_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def load_session(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _host_values(session):
    return {
        row["value"]
        for row in session.get("results", [])
        if row.get("type") == "host"
    }


def _url_values(session):
    return {
        row["value"]
        for row in session.get("results", [])
        if row.get("type") == "url"
    }


def _ip_values(session):
    return {
        (row.get("value"), row.get("related", ""))
        for row in session.get("results", [])
        if row.get("type") == "ip"
    }


def _bucket_values(session):
    return {
        row["value"]
        for row in session.get("results", [])
        if row.get("type") == "bucket"
    }


def diff_sessions(old_session, new_session):
    old_hosts = _host_values(old_session)
    new_hosts = _host_values(new_session)
    old_urls = _url_values(old_session)
    new_urls = _url_values(new_session)
    old_ips = _ip_values(old_session)
    new_ips = _ip_values(new_session)
    old_buckets = _bucket_values(old_session)
    new_buckets = _bucket_values(new_session)

    return {
        "new_hosts": sorted(new_hosts - old_hosts),
        "removed_hosts": sorted(old_hosts - new_hosts),
        "new_urls": sorted(new_urls - old_urls),
        "removed_urls": sorted(old_urls - new_urls),
        "new_ips": sorted(new_ips - old_ips),
        "removed_ips": sorted(old_ips - new_ips),
        "new_buckets": sorted(new_buckets - old_buckets),
        "removed_buckets": sorted(old_buckets - new_buckets),
    }
