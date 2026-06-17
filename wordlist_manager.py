import base64
import json
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

WORDLIST_DIR = Path(__file__).parent / "wordlists"
MY_WORDLIST = WORDLIST_DIR / "my-own-wordlist.txt"
COMMON_WORDLIST = WORDLIST_DIR / "common.txt"

DEFAULT_GITHUB_WORDLIST_PATH = "wordlists/my-own-wordlist.txt"


def ensure_wordlist_files():
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    if not MY_WORDLIST.is_file():
        MY_WORDLIST.write_text(
            "# My own wordlist — saved endpoints from Recon Dashboard\n",
            encoding="utf-8",
        )
    if not COMMON_WORDLIST.is_file():
        COMMON_WORDLIST.write_text(
            "# Common paths / labels — merged from scans\n",
            encoding="utf-8",
        )


def _existing_normalized(path):
    if not path.is_file():
        return set()
    items = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            norm = normalize_endpoint(line)
            if norm:
                items.add(norm)
    return items


def partition_endpoints(entries):
    """Split entries into new vs already present in my-own-wordlist (normalized)."""
    ensure_wordlist_files()
    existing = _existing_normalized(MY_WORDLIST)
    new_items = []
    duplicates = []
    batch_seen = set()
    for raw in entries:
        norm = normalize_endpoint(raw)
        if not norm or norm in batch_seen:
            continue
        batch_seen.add(norm)
        if norm in existing:
            duplicates.append(norm)
        else:
            new_items.append(norm)
    return new_items, duplicates


def endpoint_in_wordlist(value):
    norm = normalize_endpoint(value)
    if not norm:
        return False
    return norm in _existing_normalized(MY_WORDLIST)


def _append_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _existing_normalized(path)
    new_lines = []
    for line in lines:
        norm = normalize_endpoint(line) if line else ""
        if norm and norm not in existing:
            new_lines.append(norm)
            existing.add(norm)
    if not new_lines:
        return 0
    with open(path, "a", encoding="utf-8") as handle:
        for line in sorted(new_lines, key=str.lower):
            handle.write(line + "\n")
    return len(new_lines)


def normalize_endpoint(value):
    value = str(value or "").strip()
    if not value or " " in value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        normalized = value.split("#")[0].strip()
        return normalized.rstrip("/") or normalized
    return value.lower().rstrip(".")


def to_common_entry(value):
    value = normalize_endpoint(value)
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        path = parsed.path.strip("/")
        if path:
            segment = path.split("/")[0]
            return segment.lower()
        host = parsed.netloc.split(":")[0].lower()
        parts = host.split(".")
        return parts[0] if parts else host
    host = value.split("/")[0].split(":")[0].lower()
    parts = host.split(".")
    if len(parts) >= 3:
        return parts[0]
    if len(parts) == 2:
        return parts[0]
    return host


def append_endpoints(entries, config=None):
    ensure_wordlist_files()
    config = config or {}
    new_endpoints, duplicates = partition_endpoints(entries)
    common_items = []
    for endpoint in new_endpoints:
        common = to_common_entry(endpoint)
        if common and re.match(r"^[a-z0-9._-]+$", common, re.I):
            common_items.append(common.lower())

    added_my = _append_lines(MY_WORDLIST, new_endpoints)
    added_common = _append_lines(COMMON_WORDLIST, common_items)
    result = {
        "added_my": added_my,
        "added_common": added_common,
        "duplicates": duplicates,
        "new_endpoints": new_endpoints,
        "my_wordlist": str(MY_WORDLIST),
        "common_wordlist": str(COMMON_WORDLIST),
    }

    if added_my and config.get("auto_push_wordlist", True):
        repo = (config.get("github_wordlist_repo") or "").strip()
        if repo and config.get("github_token"):
            push_my_wordlist_to_github(config, async_push=True)

    return result


def push_my_wordlist_to_github(config=None, async_push=False):
    config = config or {}
    token = (config.get("github_token") or "").strip()
    repo = (config.get("github_wordlist_repo") or "").strip()
    if not token or not repo:
        return False, "GitHub token or github_wordlist_repo not configured in Settings"

    ensure_wordlist_files()

    def _push():
        return _push_file_github(
            token=token,
            repo=repo,
            branch=(config.get("github_wordlist_branch") or "main").strip() or "main",
            path_in_repo=(config.get("github_wordlist_path") or DEFAULT_GITHUB_WORDLIST_PATH).strip(),
            local_path=MY_WORDLIST,
            message=config.get("github_wordlist_commit_message") or "Update my-own-wordlist from Recon Dashboard",
        )

    if async_push:
        threading.Thread(target=_push, daemon=True).start()
        return True, "GitHub push started in background"

    return _push()


def _push_file_github(token, repo, branch, path_in_repo, local_path, message):
    if "/" not in repo:
        return False, "github_wordlist_repo must be owner/repo"
    owner, repo_name = repo.split("/", 1)
    path_in_repo = path_in_repo.lstrip("/")
    api_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{quote(path_in_repo)}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "ReconDashboard",
        "Content-Type": "application/json",
    }

    sha = None
    get_req = urllib.request.Request(api_url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(get_req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            sha = data.get("sha")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            body = exc.read().decode(errors="ignore")
            return False, f"GitHub read failed ({exc.code}): {body[:200]}"

    content_b64 = base64.b64encode(local_path.read_bytes()).decode("ascii")
    payload = {
        "message": message,
        "content": content_b64,
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha

    put_req = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="PUT",
    )
    try:
        with urllib.request.urlopen(put_req, timeout=45) as resp:
            json.loads(resp.read().decode())
        return True, f"Pushed {local_path.name} -> {repo}/{path_in_repo} ({branch})"
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="ignore")
        return False, f"GitHub push failed ({exc.code}): {body[:240]}"
