import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"
EXAMPLE_PATH = Path(__file__).parent / "config.example.json"
SCOPE_PATH = Path(__file__).parent / "scope.txt"

DEFAULT_CONFIG = {
    "amass_config": "~/.config/amass/config.ini",
    "securitytrails_api_key": "",
    "virustotal_api_key": "",
    "github_token": "",
    "shodan_api_key": "",
    "scope_domains": [],
    "scope_file": "scope.txt",
    "notify_on_complete": True,
    "default_timeout": 300,
    "httpx_threads": 50,
    "dns_wordlist": "",
    "path_wordlist": "",
    "appearance_mode": "dark",
    "url_dedupe": True,
    "url_param_filter": True,
    "default_scan_profile": "Full",
    "scan_workspace": "",
    "nuclei_templates": "",
    "github_wordlist_repo": "",
    "github_wordlist_path": "wordlists/my-own-wordlist.txt",
    "github_wordlist_branch": "main",
    "github_wordlist_commit_message": "Update my-own-wordlist from Recon Dashboard",
    "auto_push_wordlist": True,
}


def load_config():
    path = CONFIG_PATH if CONFIG_PATH.is_file() else EXAMPLE_PATH
    if not path.is_file():
        return dict(DEFAULT_CONFIG)

    with open(path, encoding="utf-8") as handle:
        data = {**DEFAULT_CONFIG, **json.load(handle)}

    if data.get("amass_config"):
        data["amass_config"] = str(Path(data["amass_config"]).expanduser())
    for key in ("dns_wordlist", "path_wordlist", "nuclei_templates"):
        if data.get(key):
            data[key] = str(Path(data[key]).expanduser())

    return data


def save_config(data):
    merged = {**DEFAULT_CONFIG, **data}
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, indent=2)


def load_scope_domains(config=None):
    config = config or load_config()
    domains = set(d.strip().lower() for d in config.get("scope_domains", []) if d.strip())

    scope_file = config.get("scope_file", "scope.txt")
    path = Path(scope_file)
    if not path.is_absolute():
        path = Path(__file__).parent / scope_file

    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                domains.add(line)

    return domains


def is_in_scope(domain, config=None):
    scope = load_scope_domains(config)
    if not scope:
        return True, ""

    domain = domain.strip().lower()
    for allowed in scope:
        if domain == allowed or domain.endswith(f".{allowed}"):
            return True, allowed
    return False, ", ".join(sorted(scope))
