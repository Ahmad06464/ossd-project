import json
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from config_loader import is_in_scope, load_config
from recon_patterns import (
    build_sensitive_dork,
    is_js_url,
    match_sensitive_url,
    scan_text_for_secrets,
)
from scan_storage import copy_aquatone_output, parse_httpx_probe_line, save_session_meta, save_tool_output
from url_utils import dedupe_key, filter_param_urls, normalize_url

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

TAKEOVER_CNAME_SIGS = [
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "amazonaws.com", "shopify.com", "fastly.net",
    "pantheonsite.io", "zendesk.com", "ghost.io", "surge.sh", "bitbucket.io",
    "azure-api.net", "cloudapp.net", "trafficmanager.net", "wordpress.com",
    "myshopify.com", "unbounce.com", "tumblr.com", "readme.io",
]

TOOL_NAMES = [
    "Subfinder",
    "Assetfinder",
    "Findomain",
    "Amass Passive",
    "Amass Active",
    "crt.sh",
    "Wayback CDX",
    "SecurityTrails",
    "VirusTotal Subs",
    "GitHub Subs",
    "GitHub Secrets",
    "FFUF DNS",
    "HTTP Probe",
    "Takeover Check",
    "FFUF Path",
    "VT IP Harvest",
    "OTX IP Harvest",
    "URLScan IP",
    "Shodan",
    "Cloud Buckets",
    "Aquatone",
    "GAU",
    "Katana",
    "URLFinder",
    "Hakrawler",
    "URL Param Filter",
    "Sensitive Files",
    "Arjun Params",
    "JS Recon",
]

SCAN_PROFILES = {
    "Full": TOOL_NAMES,
    "Quick": ["Subfinder", "HTTP Probe", "Aquatone"],
    "Passive": [
        "Subfinder", "Assetfinder", "Findomain", "Amass Passive",
        "crt.sh", "Wayback CDX", "HTTP Probe",
    ],
    "Probe Only": ["HTTP Probe", "Aquatone", "FFUF Path"],
}

DNS_WORDLIST_CANDIDATES = [
    Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path(__file__).parent / "wordlists" / "dns-subdomains.txt",
]

CONTENT_WORDLIST_CANDIDATES = [
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/wordlists/dirb/common.txt"),
    Path(__file__).parent / "wordlists" / "common.txt",
]

ARJUN_WORDLIST_CANDIDATES = [
    Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
    Path("/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
]

NUCLEI_EXPOSURE_CANDIDATES = [
    Path.home() / "nuclei-templates" / "http" / "exposures",
    Path("/root/nuclei-templates/http/exposures"),
    Path(__file__).parent / "nuclei-templates" / "http" / "exposures",
]


class ToolSkipped(Exception):
    pass


class ScanStopped(Exception):
    pass


FINISHED_STATUSES = frozenset({"Done", "Skipped", "Error"})
GAU_PROBE_STATUSES = frozenset({200, 302, 401, 403})


class ScanRunner:
    def __init__(self, selected_tools=None, import_hosts=None, session_dir=None, scan_profile=""):
        self.config = load_config()
        self.selected_tools = set(selected_tools or TOOL_NAMES)
        self.import_hosts = import_hosts or []
        self.session_dir = Path(session_dir) if session_dir else None
        self.scan_profile = scan_profile or ""
        self.subdomains = {}
        self.live_hosts = set()
        self.host_ips = {}
        self.host_probe_status = {}
        self.collected_ips = set()
        self.screenshots = {}
        self.collected_urls = set()
        self._url_dedupe_keys = set()
        self._skip_requested = False
        self._stop_requested = False
        self._current_process = None
        self._process_lock = threading.Lock()
        self._output_dir = Path(__file__).parent / "output"
        self._output_dir.mkdir(exist_ok=True)
        self._tool_output_chunks = []
        self._current_tool = ""
        self._aquatone_out_dir = None
        self._resume_tool_statuses = {}

    def export_state(self):
        return {
            "subdomains": {host: sorted(sources) for host, sources in self.subdomains.items()},
            "live_hosts": sorted(self.live_hosts),
            "host_ips": dict(self.host_ips),
            "host_probe_status": dict(self.host_probe_status),
            "collected_ips": sorted(self.collected_ips),
            "collected_urls": sorted(self.collected_urls),
            "screenshots": dict(self.screenshots),
        }

    def load_runner_state(self, state):
        if not state:
            return
        self.subdomains = {
            host: set(sources if isinstance(sources, list) else [sources])
            for host, sources in (state.get("subdomains") or {}).items()
        }
        self.live_hosts = set(state.get("live_hosts") or [])
        self.host_ips = dict(state.get("host_ips") or {})
        self.host_probe_status = dict(state.get("host_probe_status") or {})
        self.collected_ips = set(state.get("collected_ips") or [])
        for ip in self.host_ips.values():
            if ip and ip != "-":
                self.collected_ips.add(ip)
        self.collected_urls = set(state.get("collected_urls") or [])
        self.screenshots = dict(state.get("screenshots") or {})
        self._url_dedupe_keys = set()
        for url in self.collected_urls:
            key = dedupe_key(url)
            if key:
                self._url_dedupe_keys.add(key)

    def request_skip(self):
        self._skip_requested = True
        self._kill_current_process()

    def request_stop(self):
        self._stop_requested = True
        self._skip_requested = True
        self._kill_current_process()

    def _kill_current_process(self):
        with self._process_lock:
            proc = self._current_process
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _clear_skip(self):
        self._skip_requested = False

    def _tool_selected(self, tool):
        return tool in self.selected_tools

    def _check_abort(self):
        if self._stop_requested:
            raise ScanStopped()
        if self._skip_requested:
            raise ToolSkipped()

    def run_full_scan(self, domain, callbacks, completed_tools=None, runner_state=None, tool_statuses=None):
        domain = self._normalize_domain(domain)
        if not domain:
            callbacks["log"]("[ERROR] Invalid domain")
            return

        in_scope, scope_info = is_in_scope(domain, self.config)
        if not in_scope:
            callbacks["log"](f"[ERROR] {domain} not in scope. Allowed: {scope_info}")
            callbacks.get("scan_blocked", lambda _d: None)(domain)
            return

        completed = set(completed_tools or [])
        self._resume_tool_statuses = dict(tool_statuses or {})

        if runner_state:
            self.load_runner_state(runner_state)
            callbacks["log"](
                f"[RESUME] Restored state — {len(self.subdomains)} hosts, "
                f"{len(self.collected_urls)} URLs, {len(self.live_hosts)} live"
            )
        else:
            self.subdomains = {}
            self.live_hosts = set()
            self.host_ips = {}
            self.host_probe_status = {}
            self.collected_ips = set()
            self.screenshots = {}
            self.collected_urls = set()
            self._url_dedupe_keys = set()

            for host in self.import_hosts:
                h = self._normalize_domain(host)
                if h and (h == domain or h.endswith(f".{domain}")):
                    self.subdomains[h] = {"Import"}

            if not completed:
                for host in list(self.subdomains):
                    callbacks["host_found"](host, "Import", "-", "-")

        enum_tools = [
            ("Subfinder", self._run_subfinder),
            ("Assetfinder", self._run_assetfinder),
            ("Findomain", self._run_findomain),
            ("Amass Passive", self._run_amass_passive),
            ("Amass Active", self._run_amass_active),
            ("crt.sh", self._run_crtsh),
            ("Wayback CDX", self._run_wayback_cdx),
            ("SecurityTrails", self._run_securitytrails),
            ("VirusTotal Subs", self._run_virustotal_subs),
            ("GitHub Subs", self._run_github_subs),
            ("GitHub Secrets", self._run_github_secrets),
            ("FFUF DNS", self._run_ffuf_dns),
        ]

        post_enum_tools = [
            ("HTTP Probe", self._run_httpx),
            ("Takeover Check", self._run_takeover_check),
            ("FFUF Path", self._run_ffuf_path),
            ("VT IP Harvest", self._run_vt_ips),
            ("OTX IP Harvest", self._run_otx_ips),
            ("URLScan IP", self._run_urlscan_ips),
            ("Shodan", self._run_shodan),
            ("Cloud Buckets", self._run_cloud_buckets),
            ("Aquatone", self._run_aquatone),
            ("GAU", self._run_gau),
            ("Katana", self._run_katana),
            ("URLFinder", self._run_urlfinder),
            ("Hakrawler", self._run_hakrawler),
            ("URL Param Filter", self._run_url_param_filter),
            ("Sensitive Files", self._run_sensitive_files),
            ("Arjun Params", self._run_arjun_params),
            ("JS Recon", self._run_js_recon),
        ]

        pipeline = enum_tools + post_enum_tools
        selected_pipeline = [(t, r) for t, r in pipeline if self._tool_selected(t)]
        post_enum_names = {name for name, _ in post_enum_tools}
        total = len(selected_pipeline)

        if total == 0:
            callbacks["log"]("[ERROR] No tools selected for this scan profile")
            return

        callbacks["log"](f"[+] Pipeline: {total} tools queued for {domain}")
        if completed:
            callbacks["log"](f"[RESUME] Skipping {len(completed)} completed tool(s), continuing from next")

        if self.session_dir:
            save_session_meta(self.session_dir, {
                "target": domain,
                "tools": [t for t, _ in selected_pipeline],
                "profile": self.scan_profile,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "resumed": bool(completed),
                "completed_tools": sorted(completed),
            })

        try:
            for index, (tool, runner) in enumerate(selected_pipeline, start=1):
                self._check_abort()
                callbacks.get("scan_progress", lambda *_: None)(index, total, tool)

                if tool in completed:
                    saved = self._resume_tool_statuses.get(tool, "Done")
                    callbacks["tool_done"](tool, saved if saved in FINISHED_STATUSES else "Done")
                    callbacks["log"](f"[RESUME] Skip {tool} (already completed)")
                    continue

                if tool in post_enum_names and tool not in (
                    "Cloud Buckets", "URL Param Filter", "Sensitive Files", "Arjun Params", "JS Recon",
                ) and not self.subdomains:
                    callbacks["log"](f"[!] Skipping {tool}: no subdomains found")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                if tool == "URL Param Filter" and not self.collected_urls:
                    callbacks["log"](f"[!] Skipping {tool}: no URLs collected")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                if tool == "Sensitive Files" and not self.collected_urls:
                    callbacks["log"](f"[!] Skipping {tool}: no URLs collected")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                if tool == "JS Recon" and not self.collected_urls and not self.live_hosts:
                    callbacks["log"](f"[!] Skipping {tool}: no URLs or live hosts")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                if tool == "Arjun Params" and not self.live_hosts:
                    callbacks["log"](f"[!] Skipping {tool}: no live hosts")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                if tool == "GAU" and not self._gau_eligible_hosts():
                    callbacks["log"](f"[!] Skipping {tool}: no live hosts with 200/302/401/403")
                    callbacks["tool_done"](tool, "Skipped")
                    continue

                self._run_tool_stage(tool, domain, runner, callbacks)

        except ScanStopped:
            callbacks["log"]("[!] Scan stopped by user")
            callbacks.get("scan_stopped", lambda: None)()

        ips = self._collect_ips_for_probe()
        if ips and self._tool_selected("HTTP Probe"):
            callbacks["log"](f"[HTTP Probe] Probing {len(ips)} collected IP(s)...")
            self._httpx_probe_batch(ips, domain, callbacks, label="ips")

        callbacks["log"](
            f"[+] Scan finished — {len(self.subdomains)} unique subdomains, "
            f"{len(self.live_hosts)} live hosts"
        )
        if self.session_dir:
            save_session_meta(self.session_dir, {
                "target": domain,
                "tools": [t for t, _ in selected_pipeline],
                "profile": self.scan_profile,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "subdomains": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "urls": len(self.collected_urls),
            })

    def run_tool_once(self, domain, tool, callbacks):
        """
        Run a single pipeline tool again (without resetting UI data).
        Intended for "re-run tool" actions from the UI.
        """
        domain = self._normalize_domain(domain)
        if not domain:
            callbacks["log"]("[ERROR] Invalid domain")
            return

        in_scope, scope_info = is_in_scope(domain, self.config)
        if not in_scope:
            callbacks["log"](f"[ERROR] {domain} not in scope. Allowed: {scope_info}")
            callbacks.get("scan_blocked", lambda _d: None)(domain)
            return

        enum_tools = {
            "Subfinder": self._run_subfinder,
            "Assetfinder": self._run_assetfinder,
            "Findomain": self._run_findomain,
            "Amass Passive": self._run_amass_passive,
            "Amass Active": self._run_amass_active,
            "crt.sh": self._run_crtsh,
            "Wayback CDX": self._run_wayback_cdx,
            "SecurityTrails": self._run_securitytrails,
            "VirusTotal Subs": self._run_virustotal_subs,
            "GitHub Subs": self._run_github_subs,
            "GitHub Secrets": self._run_github_secrets,
            "FFUF DNS": self._run_ffuf_dns,
        }

        post_enum_tools = {
            "HTTP Probe": self._run_httpx,
            "Takeover Check": self._run_takeover_check,
            "FFUF Path": self._run_ffuf_path,
            "VT IP Harvest": self._run_vt_ips,
            "OTX IP Harvest": self._run_otx_ips,
            "URLScan IP": self._run_urlscan_ips,
            "Shodan": self._run_shodan,
            "Cloud Buckets": self._run_cloud_buckets,
            "Aquatone": self._run_aquatone,
            "GAU": self._run_gau,
            "Katana": self._run_katana,
            "URLFinder": self._run_urlfinder,
            "Hakrawler": self._run_hakrawler,
            "URL Param Filter": self._run_url_param_filter,
            "Sensitive Files": self._run_sensitive_files,
            "Arjun Params": self._run_arjun_params,
            "JS Recon": self._run_js_recon,
        }

        runner = enum_tools.get(tool) or post_enum_tools.get(tool)
        if not runner:
            callbacks["log"](f"[ERROR] Unknown tool: {tool}")
            return

        post_enum_names = set(post_enum_tools.keys())
        if tool in post_enum_names and tool not in (
            "Cloud Buckets", "URL Param Filter", "Sensitive Files", "Arjun Params", "JS Recon",
        ) and not self.subdomains:
            callbacks["log"](f"[!] Skipping {tool}: no subdomains found")
            callbacks["tool_done"](tool, "Skipped")
            return

        if tool == "URL Param Filter" and not self.collected_urls:
            callbacks["log"](f"[!] Skipping {tool}: no URLs collected")
            callbacks["tool_done"](tool, "Skipped")
            return

        if tool == "Sensitive Files" and not self.collected_urls:
            callbacks["log"](f"[!] Skipping {tool}: no URLs collected")
            callbacks["tool_done"](tool, "Skipped")
            return

        if tool == "JS Recon" and not self.collected_urls and not self.live_hosts:
            callbacks["log"](f"[!] Skipping {tool}: no URLs or live hosts")
            callbacks["tool_done"](tool, "Skipped")
            return

        if tool == "Arjun Params" and not self.live_hosts:
            callbacks["log"](f"[!] Skipping {tool}: no live hosts")
            callbacks["tool_done"](tool, "Skipped")
            return

        if tool == "GAU" and not self._gau_eligible_hosts():
            callbacks["log"](f"[!] Skipping {tool}: no live hosts with 200/302/401/403")
            callbacks["tool_done"](tool, "Skipped")
            return

        self._run_tool_stage(tool, domain, runner, callbacks)

    def _begin_tool(self, tool):
        self._current_tool = tool
        self._tool_output_chunks = []

    def _append_tool_text(self, text):
        if text and str(text).strip():
            self._tool_output_chunks.append(str(text))

    def _finish_tool(self, tool):
        if not self.session_dir:
            return
        if tool == "Aquatone" and self._aquatone_out_dir:
            log_text = "\n".join(self._tool_output_chunks)
            copy_aquatone_output(self.session_dir, self._aquatone_out_dir, log_text)
            self._aquatone_out_dir = None
            return
        parts = []
        for chunk in self._tool_output_chunks:
            parts.append(chunk)
        save_tool_output(self.session_dir, tool, "\n".join(parts).strip() + "\n")

    def _normalize_domain(self, domain):
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://")
        return domain.split("/")[0].strip()

    def _run_tool_stage(self, tool, domain, runner, callbacks):
        if not self._tool_available(tool):
            reason = self._skip_reason(tool)
            callbacks["log"](f"[!] Skipping {tool}: {reason}")
            callbacks["tool_done"](tool, "Skipped")
            return

        self._clear_skip()
        callbacks["tool_start"](tool)
        callbacks["log"](f"[+] Running {tool} on {domain}")
        self._begin_tool(tool)

        try:
            runner(domain, callbacks)
            if self._skip_requested:
                callbacks["tool_done"](tool, "Skipped")
                callbacks["log"](f"[!] Skipped {tool}")
                self._clear_skip()
            else:
                callbacks["tool_done"](tool, "Done")
                callbacks["log"](f"[-] Finished {tool}")
        except ToolSkipped:
            callbacks["tool_done"](tool, "Skipped")
            callbacks["log"](f"[!] Skipped {tool}")
            self._clear_skip()
        except ScanStopped:
            raise
        except subprocess.TimeoutExpired:
            callbacks["tool_done"](tool, "Error")
            callbacks["log"](f"[ERROR] {tool} timed out")
        except Exception as exc:
            callbacks["tool_done"](tool, "Error")
            callbacks["log"](f"[ERROR] {tool}: {exc}")
        finally:
            self._finish_tool(tool)

    def _tool_available(self, tool):
        binary = self._tool_binary(tool)
        if binary is None:
            return True
        if isinstance(binary, tuple):
            if tool in ("HTTP Probe", "Cloud Buckets", "Shodan", "Takeover Check", "JS Recon"):
                return any(shutil.which(b) for b in binary)
            return all(shutil.which(b) for b in binary)
        return bool(shutil.which(binary))

    def _skip_reason(self, tool):
        api_key_map = {
            "SecurityTrails": "securitytrails_api_key",
            "VirusTotal Subs": "virustotal_api_key",
            "VT IP Harvest": "virustotal_api_key",
            "GitHub Subs": "github_token",
            "GitHub Secrets": "github_token",
            "Shodan": "shodan_api_key",
        }
        if tool in api_key_map and not self.config.get(api_key_map[tool]):
            return "API key not set in config.json"
        binary = self._tool_binary(tool)
        if binary is None:
            return "not available"
        if isinstance(binary, tuple):
            missing = [b for b in binary if not shutil.which(b)]
            return f"{', '.join(missing)} not installed"
        return f"{binary} not installed"

    def _tool_binary(self, tool):
        mapping = {
            "Subfinder": "subfinder",
            "Assetfinder": "assetfinder",
            "Findomain": "findomain",
            "Amass Passive": "amass",
            "Amass Active": "amass",
            "crt.sh": ("curl", "jq", "grep"),
            "Wayback CDX": "curl",
            "SecurityTrails": "curl",
            "VirusTotal Subs": ("curl", "jq"),
            "GitHub Subs": "github-subdomains",
            "GitHub Secrets": "curl",
            "FFUF DNS": "ffuf",
            "FFUF Path": "ffuf",
            "HTTP Probe": ("httpx-toolkit", "httpx"),
            "Takeover Check": ("dig", "dnsx"),
            "VT IP Harvest": ("curl", "jq"),
            "OTX IP Harvest": ("curl", "jq"),
            "URLScan IP": ("curl", "jq"),
            "Shodan": ("shodan", "httpx-toolkit"),
            "Cloud Buckets": ("httpx-toolkit", "httpx"),
            "Aquatone": "aquatone",
            "GAU": "gau",
            "Katana": "katana",
            "URLFinder": "urlfinder",
            "Hakrawler": "hakrawler",
            "URL Param Filter": None,
            "Sensitive Files": None,
            "Arjun Params": "arjun",
            "JS Recon": ("katana", "curl", "nuclei"),
        }
        return mapping.get(tool)

    def _httpx_bin(self):
        return "httpx-toolkit" if shutil.which("httpx-toolkit") else "httpx"

    def _check_skip(self):
        self._check_abort()

    def _run_cmd(self, cmd, input_text=None, timeout=None):
        if timeout is None:
            timeout = int(self.config.get("default_timeout", 300))
        with self._process_lock:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if input_text is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._current_process = proc

        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
            if self._stop_requested:
                raise ScanStopped()
            if self._skip_requested:
                raise ToolSkipped()
            if self.session_dir and self._current_tool:
                block = f"# CMD: {' '.join(str(c) for c in cmd)}\n"
                if stdout:
                    block += stdout
                    if not stdout.endswith("\n"):
                        block += "\n"
                if stderr and stderr.strip():
                    block += f"# STDERR:\n{stderr}\n"
                self._tool_output_chunks.append(block)
            return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        finally:
            with self._process_lock:
                if self._current_process is proc:
                    self._current_process = None

    def _valid_host(self, host, domain):
        host = host.strip().lower().rstrip(".")
        if not host or "*" in host or " " in host:
            return None
        if host == domain or host.endswith(f".{domain}"):
            return host
        return None

    def _record_subdomain(self, subdomain, source, callbacks, domain):
        self._check_skip()
        host = self._valid_host(subdomain, domain)
        if not host:
            return False

        if host not in self.subdomains:
            self.subdomains[host] = set()
        self.subdomains[host].add(source)
        ip = self.host_ips.get(host, "-")
        callbacks["host_found"](host, source, "-", ip)
        if source != "Import":
            callbacks["log"](f"[{source}] Found: {host}")
        return True

    def _record_url(self, url, source, callbacks, status="-"):
        self._check_abort()
        url = normalize_url(url) or url.strip()
        if not url:
            return

        if self.config.get("url_dedupe", True):
            key = dedupe_key(url)
            if key not in self._url_dedupe_keys:
                self._url_dedupe_keys.add(key)
                self.collected_urls.add(url)
        else:
            self.collected_urls.add(url)

        if is_js_url(url):
            self._record_js(url, source, callbacks, status)
            return

        callbacks["url_found"](source, url, status)
        callbacks["log"](f"[{source}] URL: {url}")

    def _record_sensitive(self, url, source, callbacks, status="-", note=""):
        if note and self._current_tool:
            self._append_tool_text(f"{url}\t{note}\n")
        callbacks.get("sensitive_found", lambda *_: None)(source, url, status, note)
        callbacks["log"](f"[{source}] Sensitive: {url}" + (f" — {note}" if note else ""))

    def _record_js(self, url, source, callbacks, status="-", note=""):
        if note and self._current_tool:
            self._append_tool_text(f"{url}\t{note}\n")
        callbacks.get("js_found", lambda *_: None)(source, url, status, note)
        if note:
            callbacks["log"](f"[{source}] JS secret: {url} — {note[:80]}")
        else:
            callbacks["log"](f"[{source}] JS: {url}")

    def _save_allurls_snapshot(self, domain):
        if not self.session_dir or not self.collected_urls:
            return None
        path = Path(self.session_dir) / "urls" / "allurls.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = "\n".join(sorted(self.collected_urls)) + "\n"
        path.write_text(text, encoding="utf-8")
        return path

    def _update_host_probe(self, probe, callbacks, *, related=""):
        if not probe:
            return
        target = probe.get("host", "")
        status = str(probe.get("status", ""))
        ip = probe.get("ip", "-")
        if probe.get("is_ip"):
            cb = callbacks.get("ip_probe_update")
            if cb:
                cb(target, related, probe)
            return
        if status and status != "-":
            self.host_probe_status[target] = status
            if target in self.live_hosts or (status.isdigit() and int(status) < 500):
                self.live_hosts.add(target)
        if ip and ip != "-":
            self.host_ips[target] = ip
        callbacks["host_update"](target, probe)

    def _collect_ips_for_probe(self):
        ips = set(self.collected_ips)
        for ip in self.host_ips.values():
            if ip and ip != "-":
                ips.add(ip)
        return sorted(ips)

    def _note_ip(self, ip):
        if ip and ip != "-":
            self.collected_ips.add(ip)

    def _httpx_probe_batch(self, targets, domain, callbacks, label="hosts"):
        if not targets:
            return set()
        input_path = Path(tempfile.gettempdir()) / f"httpx_{label}_{domain.replace('.', '_')}.txt"
        output_path = Path(tempfile.gettempdir()) / f"httpx_out_{label}_{domain.replace('.', '_')}.txt"
        input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
        output_path.unlink(missing_ok=True)

        httpx = self._httpx_bin()
        cmd = [
            httpx,
            "-l", str(input_path),
            "-title",
            "-content-length",
            "-content-type",
            "-tech-detect",
            "-status-code",
            "-ip",
            "-silent",
            "-no-color",
            "-threads",
            str(self.config.get("httpx_threads", 50)),
            "-o", str(output_path),
        ]
        result = self._run_cmd(cmd, timeout=600)
        self._log_stderr("HTTP Probe", result, callbacks)
        input_path.unlink(missing_ok=True)

        responded = set()
        live_lines = []
        if output_path.is_file():
            for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                self._check_skip()
                parsed = parse_httpx_probe_line(line)
                if not parsed or not parsed.get("status"):
                    continue
                target = parsed["host"]
                responded.add(target)
                live_lines.append(line)
                self._update_host_probe(parsed, callbacks, related=domain)
                callbacks["log"](
                    f"[HTTP Probe] {target} [{parsed['status']}] "
                    f"len={parsed.get('content_length', '-')} "
                    f"tech={parsed.get('tech', '-') or '-'}"
                )
            output_path.unlink(missing_ok=True)

        section = f"# {label}\n# CMD: {' '.join(str(c) for c in cmd)}\n"
        body = "\n".join(live_lines)
        self._append_tool_text(section + (body + "\n" if body else ""))
        return responded

    def _hosts_from_urls(self, urls, domain):
        domain = domain.lower()
        hosts = set()
        for raw in urls:
            self._check_skip()
            raw = raw.strip()
            if not raw:
                continue
            parsed = urlparse(raw if "://" in raw else f"http://{raw}")
            host = parsed.netloc.split(":")[0].lower().rstrip(".")
            valid = self._valid_host(host, domain)
            if valid:
                hosts.add(valid)
        return hosts

    def _parse_amass_line(self, line):
        line = line.strip()
        if not line:
            return None
        if "]" in line:
            line = line.split("]", 1)[1].strip()
        token = line.split()[0].strip().lower().rstrip(".")
        return token if token else None

    def _find_wordlist(self, candidates, config_key=None):
        custom = self.config.get(config_key, "") if config_key else ""
        if custom and Path(custom).is_file():
            return Path(custom)
        for path in candidates:
            if path.is_file():
                return path
        return None

    def _amass_config_args(self):
        config = self.config.get("amass_config", "")
        if config and Path(config).is_file():
            return ["-config", config]
        return []

    def _host_urls(self, limit=50, prefer_live=True):
        if prefer_live and self.live_hosts:
            hosts = sorted(self.live_hosts)[:limit]
        elif self.subdomains:
            hosts = sorted(self.subdomains)[:limit]
        else:
            return []
        urls = []
        for host in hosts:
            host = str(host).strip()
            if not host:
                continue
            urls.append(host if host.startswith("http") else f"https://{host}")
        return urls

    def _domain_lines_input(self, domain, limit=100):
        if self.live_hosts:
            hosts = sorted(self.live_hosts)[:limit]
        elif self.subdomains:
            hosts = sorted(self.subdomains)[:limit]
        else:
            hosts = [domain]
        return "\n".join(hosts) + "\n"

    def _write_temp_lines(self, prefix, lines):
        path = Path(tempfile.gettempdir()) / prefix
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def _find_nuclei_exposures(self):
        configured = (self.config.get("nuclei_templates") or "").strip()
        if configured:
            path = Path(configured).expanduser()
            if path.is_dir():
                return path
        for path in NUCLEI_EXPOSURE_CANDIDATES:
            if path.is_dir():
                return path
        return None

    def _parse_wayback_line(self, raw, domain):
        raw = raw.strip()
        if not raw:
            return None, None
        if raw.startswith("http://") or raw.startswith("https://"):
            host = re.sub(r"^https?://", "", raw)
            host = host.split("/")[0].split(":")[0]
            url = raw
        else:
            host = raw.split("/")[0].split(":")[0]
            url = None
        host = host.removeprefix("www.").lower().rstrip(".")
        valid = self._valid_host(host, domain)
        return valid, url

    def _gau_eligible_hosts(self):
        hosts = []
        for host in sorted(self.subdomains):
            status = self.host_probe_status.get(host)
            if not status:
                continue
            try:
                code = int(str(status).strip())
            except (TypeError, ValueError):
                continue
            if code in GAU_PROBE_STATUSES:
                hosts.append(host)
        return hosts

    def _run_gau_on_hosts(self, hosts, callbacks, source="GAU", log_prefix="GAU"):
        if not hosts or not shutil.which("gau"):
            return 0
        list_file = self._write_temp_lines("livesubdomains.txt", hosts)
        cmd = f"cat {shlex.quote(str(list_file))} | gau | sort -u"
        try:
            result = self._run_cmd(["bash", "-c", cmd], timeout=600)
            self._log_stderr(log_prefix, result, callbacks)
            count = 0
            for line in result.stdout.splitlines():
                self._check_skip()
                url = line.strip()
                if url:
                    self._record_url(url, source, callbacks)
                    count += 1
            return count
        finally:
            list_file.unlink(missing_ok=True)

    def _bootstrap_urls_if_empty(self, domain, callbacks):
        if self.collected_urls or not shutil.which("gau"):
            return
        hosts = self._gau_eligible_hosts()
        if not hosts:
            callbacks["log"]("[Sensitive Files] No live hosts (200/302/401/403) for gau bootstrap")
            return
        callbacks["log"](f"[Sensitive Files] Fetching passive URLs with gau on {len(hosts)} live host(s)")
        self._run_gau_on_hosts(hosts, callbacks)

    # ---------------- SUBDOMAIN ENUM ----------------

    def _run_subfinder(self, domain, callbacks):
        result = self._run_cmd(
            ["subfinder", "-d", domain, "-all", "-recursive", "-silent"],
            timeout=300,
        )
        self._log_stderr("Subfinder", result, callbacks)
        for line in result.stdout.splitlines():
            self._record_subdomain(line, "Subfinder", callbacks, domain)

    def _run_assetfinder(self, domain, callbacks):
        result = self._run_cmd(
            ["assetfinder", "--subs-only", domain],
            timeout=120,
        )
        self._log_stderr("Assetfinder", result, callbacks)
        for line in result.stdout.splitlines():
            self._record_subdomain(line, "Assetfinder", callbacks, domain)

    def _run_findomain(self, domain, callbacks):
        result = self._run_cmd(
            ["findomain", "-t", domain, "-q"],
            timeout=300,
        )
        self._log_stderr("Findomain", result, callbacks)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            callbacks["log"](f"[Findomain] No subdomains returned (exit code {result.returncode})")
        else:
            self._append_tool_text("\n".join(lines) + "\n")

        for line in lines:
            self._record_subdomain(line, "Findomain", callbacks, domain)

    def _run_amass_passive(self, domain, callbacks):
        cmd = ["amass", "enum", "-passive", "-d", domain, "-silent", *self._amass_config_args()]
        result = self._run_cmd(cmd, timeout=600)
        self._log_stderr("Amass Passive", result, callbacks)
        for line in result.stdout.splitlines():
            host = self._parse_amass_line(line)
            if host:
                self._record_subdomain(host, "Amass Passive", callbacks, domain)

    def _run_amass_active(self, domain, callbacks):
        cmd = ["amass", "enum", "-active", "-d", domain, *self._amass_config_args()]
        result = self._run_cmd(cmd, timeout=900)
        self._log_stderr("Amass Active", result, callbacks)
        seen = set()
        for line in result.stdout.splitlines():
            host = self._parse_amass_line(line)
            if host and host not in seen:
                seen.add(host)
                self._record_subdomain(host, "Amass Active", callbacks, domain)

    def _run_crtsh(self, domain, callbacks):
        url = f"https://crt.sh/?q={quote(domain)}&output=json"
        cmd = (
            f"curl -s {shlex.quote(url)} "
            f"| jq -r '.[].name_value' "
            f"| grep -Po '(\\w+\\.\\w+\\.\\w+)$'"
        )
        result = self._run_cmd(["bash", "-c", cmd], timeout=180)
        if result.returncode not in (0, 1):
            err = (result.stderr or "").strip()
            if err:
                callbacks["log"](f"[crt.sh] {err}")
            return
        if not result.stdout.strip():
            callbacks["log"]("[crt.sh] No subdomains matched")
            return

        seen = set()
        for line in result.stdout.splitlines():
            self._check_skip()
            host = line.strip().lower().lstrip("*.")
            valid = self._valid_host(host, domain)
            if valid and valid not in seen:
                seen.add(valid)
                self._record_subdomain(valid, "crt.sh", callbacks, domain)

    def _run_wayback_cdx(self, domain, callbacks):
        url = (
            "http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        )
        result = self._run_cmd(
            ["curl", "-s", "-A", "Mozilla/5.0", url],
            timeout=300,
        )
        seen_hosts = set()
        for raw in result.stdout.splitlines():
            self._check_skip()
            valid, full_url = self._parse_wayback_line(raw, domain)
            if full_url:
                self._record_url(full_url, "Wayback CDX", callbacks)
            if valid and valid not in seen_hosts:
                seen_hosts.add(valid)
                self._record_subdomain(valid, "Wayback CDX", callbacks, domain)

    def _run_securitytrails(self, domain, callbacks):
        api_key = self.config.get("securitytrails_api_key", "")
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        result = self._run_cmd(
            ["curl", "-s", "-H", f"APIKEY: {api_key}", url],
            timeout=60,
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            callbacks["log"]("[SecurityTrails] Invalid API response")
            return

        for sub in data.get("subdomains", []):
            self._record_subdomain(f"{sub}.{domain}", "SecurityTrails", callbacks, domain)

    def _run_virustotal_subs(self, domain, callbacks):
        api_key = self.config.get("virustotal_api_key", "")
        url = (
            "https://www.virustotal.com/vtapi/v2/domain/report"
            f"?apikey={api_key}&domain={domain}"
        )
        result = self._run_cmd(["curl", "-s", url], timeout=60)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            callbacks["log"]("[VirusTotal Subs] Invalid API response")
            return

        for sub in data.get("subdomains", []):
            self._record_subdomain(sub, "VirusTotal Subs", callbacks, domain)

        for sibling in data.get("domain_siblings", []):
            self._record_subdomain(sibling, "VirusTotal Subs", callbacks, domain)

    def _run_github_subs(self, domain, callbacks):
        token = self.config.get("github_token", "")
        if not token:
            callbacks["log"]("[GitHub Subs] github_token not set — add it in Settings")
            return
        result = self._run_cmd(
            ["github-subdomains", "-d", domain, "-t", token],
            timeout=180,
        )
        self._log_stderr("GitHub Subs", result, callbacks)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                self._record_subdomain(line, "GitHub Subs", callbacks, domain)

    def _run_ffuf_dns(self, domain, callbacks):
        wordlist = self._find_wordlist(DNS_WORDLIST_CANDIDATES, "dns_wordlist")
        if not wordlist:
            callbacks["log"]("[!] No DNS wordlist found for FFUF DNS")
            return

        out_file = Path(tempfile.gettempdir()) / f"ffuf_dns_{domain.replace('.', '_')}.json"
        try:
            result = self._run_cmd(
                [
                    "ffuf",
                    "-u",
                    f"https://FUZZ.{domain}",
                    "-w",
                    str(wordlist),
                    "-mc",
                    "200,301,302",
                    "-t",
                    "40",
                    "-timeout",
                    "10",
                    "-of",
                    "json",
                    "-o",
                    str(out_file),
                    "-s",
                ],
                timeout=300,
            )
            self._log_stderr("FFUF DNS", result, callbacks)
            if not out_file.is_file():
                return
            with open(out_file, encoding="utf-8") as handle:
                data = json.load(handle)
            if out_file.is_file():
                self._append_tool_text(out_file.read_text(encoding="utf-8"))
        finally:
            out_file.unlink(missing_ok=True)

        for item in data.get("results", []):
            self._check_skip()
            fuzz = item.get("input", {}).get("FUZZ", "")
            status = str(item.get("status", "-"))
            host = f"{fuzz}.{domain}".lower()
            if self._record_subdomain(host, "FFUF DNS", callbacks, domain):
                pass
            else:
                self._update_host_probe(
                    {"host": host, "status": status, "ip": "-", "is_ip": False},
                    callbacks,
                    related=domain,
                )

    def _run_ffuf_path(self, domain, callbacks):
        wordlist = self._find_wordlist(CONTENT_WORDLIST_CANDIDATES, "path_wordlist")
        if not wordlist:
            callbacks["log"]("[!] No path wordlist found for FFUF Path")
            return

        targets = sorted(self.live_hosts)[:10] or sorted(self.subdomains)[:5]
        for host in targets:
            self._check_abort()
            target_url = f"https://{host}/FUZZ"
            out_file = Path(tempfile.gettempdir()) / f"ffuf_path_{host.replace('.', '_')}.json"
            try:
                result = self._run_cmd(
                    [
                        "ffuf",
                        "-u",
                        target_url,
                        "-w",
                        str(wordlist),
                        "-mc",
                        "200,301,302,403",
                        "-t",
                        "30",
                        "-timeout",
                        "10",
                        "-of",
                        "json",
                        "-o",
                        str(out_file),
                        "-s",
                    ],
                    timeout=240,
                )
                self._log_stderr("FFUF Path", result, callbacks)
                if not out_file.is_file():
                    continue
                with open(out_file, encoding="utf-8") as handle:
                    data = json.load(handle)
                self._append_tool_text(out_file.read_text(encoding="utf-8"))
            finally:
                out_file.unlink(missing_ok=True)

            for item in data.get("results", []):
                self._check_abort()
                path = item.get("input", {}).get("FUZZ", "")
                status = str(item.get("status", "-"))
                url = item.get("url") or f"https://{host}/{path.lstrip('/')}"
                self._record_url(url, "FFUF Path", callbacks, status)

    # ---------------- PROBING ----------------

    def _prune_non_responding_hosts(self, responded_hosts, callbacks):
        dead = [host for host in list(self.subdomains) if host not in responded_hosts]
        if not dead:
            return
        for host in dead:
            self.subdomains.pop(host, None)
            self.live_hosts.discard(host)
            self.host_probe_status.pop(host, None)
            self.host_ips.pop(host, None)
            self.screenshots.pop(host, None)
        callbacks["log"](f"[HTTP Probe] Removed {len(dead)} host(s) with no response")
        prune_cb = callbacks.get("hosts_prune")
        if prune_cb:
            prune_cb(dead)

    def _rewrite_httpx_tool_output(self, cmd, live_lines):
        cmd_line = f"# CMD: {' '.join(str(c) for c in cmd)}"
        body = "\n".join(live_lines)
        block = cmd_line + ("\n" + body if body else "") + "\n"
        if self._tool_output_chunks:
            self._tool_output_chunks[-1] = block
        else:
            self._tool_output_chunks.append(block)

    def _run_httpx(self, domain, callbacks):
        hosts = sorted(self.subdomains)
        responded_hosts = self._httpx_probe_batch(hosts, domain, callbacks, label="subdomains")
        ips = self._collect_ips_for_probe()
        if ips:
            self._httpx_probe_batch(ips, domain, callbacks, label="ips_early")

        if hosts and not responded_hosts:
            callbacks["log"]("[HTTP Probe] Warning: no hosts responded to probe")
        self._prune_non_responding_hosts(responded_hosts, callbacks)

    def _parse_httpx_line(self, line):
        parsed = parse_httpx_probe_line(line)
        if not parsed:
            return None
        try:
            status = int(parsed["status"]) if parsed.get("status") else None
        except ValueError:
            status = None
        return parsed["host"], status, parsed.get("ip"), parsed.get("title")

    def _extract_ips(self, text):
        return sorted(set(IP_RE.findall(text)))

    def _run_vt_ips(self, domain, callbacks):
        api_key = self.config.get("virustotal_api_key", "")
        url = (
            "https://www.virustotal.com/vtapi/v2/domain/report"
            f"?domain={domain}&apikey={api_key}"
        )
        result = self._run_cmd(["curl", "-s", url], timeout=60)
        for ip in self._extract_ips(result.stdout):
            self._check_skip()
            self._note_ip(ip)
            callbacks["ip_found"]("VT IP Harvest", domain, ip)
            callbacks["log"](f"[VT IP Harvest] {domain} -> {ip}")

    def _run_otx_ips(self, domain, callbacks):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1"
        result = self._run_cmd(["curl", "-s", url], timeout=60)
        for ip in self._extract_ips(result.stdout):
            self._check_skip()
            self._note_ip(ip)
            callbacks["ip_found"]("OTX IP Harvest", domain, ip)
            callbacks["log"](f"[OTX IP Harvest] {domain} -> {ip}")

    def _run_urlscan_ips(self, domain, callbacks):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        result = self._run_cmd(["curl", "-s", url], timeout=60)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        for item in data.get("results", []):
            self._check_skip()
            ip = item.get("page", {}).get("ip")
            if ip:
                self._note_ip(ip)
                callbacks["ip_found"]("URLScan IP", domain, ip)
                callbacks["log"](f"[URLScan IP] {domain} -> {ip}")

    def _run_shodan(self, domain, callbacks):
        api_key = self.config.get("shodan_api_key", "")
        if shutil.which("shodan"):
            init = self._run_cmd(["shodan", "init", api_key], timeout=30)
            self._log_stderr("Shodan", init, callbacks)
            result = self._run_cmd(
                ["shodan", "search", f'Ssl.cert.subject.CN:"{domain}"', "200", "--fields", "ip_str"],
                timeout=120,
            )
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for ip in ips:
                self._check_skip()
                self._note_ip(ip)
                callbacks["ip_found"]("Shodan", domain, ip)
                callbacks["log"](f"[Shodan] {domain} -> {ip}")

    # ---------------- CLOUD BUCKETS ----------------

    def _run_cloud_buckets(self, domain, callbacks):
        base = domain.split(".")[0]
        names = {
            domain.replace(".", "-"),
            base,
            f"{base}-backup",
            f"{base}-dev",
            f"{base}-prod",
            f"{base}-staging",
            f"{base}-assets",
            f"{base}-media",
            f"{base}-static",
            f"{base}-files",
            f"{base}-data",
            f"www-{base}",
        }

        urls = []
        for name in names:
            urls.extend([
                f"https://{name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{name}",
                f"https://{name}.blob.core.windows.net",
                f"https://storage.googleapis.com/{name}",
                f"https://{name}.digitaloceanspaces.com",
            ])

        httpx = self._httpx_bin()
        probe_input = "\n".join(urls) + "\n"
        result = self._run_cmd(
            [httpx, "-silent", "-status-code", "-no-color", "-mc", "200,204,301,302,403"],
            input_text=probe_input,
            timeout=180,
        )
        self._log_stderr("Cloud Buckets", result, callbacks)

        for line in result.stdout.splitlines():
            self._check_abort()
            line = ANSI_RE.sub("", line).strip()
            match = re.match(r"^(https?://\S+)(?:\s+\[(\d+)\])?", line)
            if not match:
                continue
            bucket_url = match.group(1)
            status = match.group(2) or "-"
            callbacks["bucket_found"]("Cloud Buckets", bucket_url, status)
            callbacks["log"](f"[Cloud Buckets] {status} {bucket_url}")

    # ---------------- AQUATONE ----------------

    def _run_aquatone(self, domain, callbacks):
        hosts = sorted(self.live_hosts) or sorted(self.subdomains)[:50]
        if not hosts:
            callbacks["log"]("[Aquatone] No hosts to screenshot")
            return

        out_dir = self._output_dir / f"aquatone_{domain.replace('.', '_')}"
        out_dir.mkdir(parents=True, exist_ok=True)
        host_input = "\n".join(hosts) + "\n"

        result = self._run_cmd(
            ["aquatone", "-out", str(out_dir), "-ports", "large"],
            input_text=host_input,
            timeout=900,
        )
        self._log_stderr("Aquatone", result, callbacks)
        self._map_aquatone_screenshots(out_dir, callbacks)
        self._aquatone_out_dir = out_dir

    def _map_aquatone_screenshots(self, out_dir, callbacks):
        screenshots_dir = out_dir / "screenshots"
        if not screenshots_dir.is_dir():
            return

        known_hosts = set(self.subdomains) | self.live_hosts

        for png in screenshots_dir.glob("*.png"):
            self._check_skip()
            host = self._match_screenshot_host(png.stem, known_hosts)
            if not host:
                continue
            self.screenshots[host] = str(png.resolve())
            callbacks["screenshot"](host, str(png.resolve()))
            callbacks["log"](f"[Aquatone] Screenshot: {host}")

    def _match_screenshot_host(self, stem, known_hosts):
        stem_lower = stem.lower()
        for host in sorted(known_hosts, key=len, reverse=True):
            if host.replace(".", "_") in stem_lower or host in stem_lower:
                return host
        return self._host_from_screenshot(stem)

    def _host_from_screenshot(self, stem):
        name = stem.replace("__", ".")
        for prefix in ("https_", "http_"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        name = name.replace("_", ".")
        name = re.sub(r"\.(\d+)$", "", name)
        if name.count(".") >= 1:
            return name.lower()
        return None

    # ---------------- URL CRAWL ----------------

    def _live_host_input(self):
        return "\n".join(sorted(self.live_hosts)) + "\n" if self.live_hosts else ""

    def _run_gau(self, domain, callbacks):
        hosts = self._gau_eligible_hosts()
        if not hosts:
            callbacks["log"]("[GAU] No live hosts with 200/302/401/403 — run HTTP Probe first")
            return
        callbacks["log"](f"[GAU] Running on {len(hosts)} live host(s): cat livesubdomains.txt | gau | sort -u")
        found = self._run_gau_on_hosts(hosts, callbacks)
        callbacks["log"](f"[GAU] Done — {found} URL(s)")

    def _run_katana(self, domain, callbacks):
        targets = self._host_urls(limit=30, prefer_live=True)
        if not targets:
            targets = self._host_urls(limit=30, prefer_live=False)
        if not targets:
            callbacks["log"]("[Katana] No hosts to crawl")
            return

        list_file = self._write_temp_lines(
            f"katana_{domain.replace('.', '_')}.txt",
            targets,
        )
        try:
            result = self._run_cmd(
                ["katana", "-list", str(list_file), "-d", "2", "-silent", "-jc"],
                timeout=600,
            )
            self._log_stderr("Katana", result, callbacks)
            for line in result.stdout.splitlines():
                url = line.strip()
                if url:
                    self._record_url(url, "Katana", callbacks)
        finally:
            list_file.unlink(missing_ok=True)

    def _run_urlfinder(self, domain, callbacks):
        result = self._run_cmd(
            ["urlfinder", "-d", domain],
            timeout=180,
        )
        self._log_stderr("URLFinder", result, callbacks)
        seen = set()
        for line in result.stdout.splitlines():
            self._check_skip()
            url = line.strip()
            if url and url not in seen:
                seen.add(url)
                self._record_url(url, "URLFinder", callbacks)

    def _run_hakrawler(self, domain, callbacks):
        url_input = "\n".join(self._host_urls(limit=40, prefer_live=True)) + "\n"
        if not url_input.strip():
            url_input = "\n".join(self._host_urls(limit=40, prefer_live=False)) + "\n"
        if not url_input.strip():
            callbacks["log"]("[Hakrawler] No hosts to crawl")
            return

        result = self._run_cmd(
            ["hakrawler", "-d", "2", "-subs", "-u", "-t", "8"],
            input_text=url_input,
            timeout=600,
        )
        self._log_stderr("Hakrawler", result, callbacks)
        for line in result.stdout.splitlines():
            self._check_skip()
            url = line.strip()
            if url.startswith("http"):
                self._record_url(url, "Hakrawler", callbacks)

    def _run_github_secrets(self, domain, callbacks):
        token = self.config.get("github_token", "")
        queries = [
            f'"{domain}" filename:.env',
            f'"{domain}" extension:json api',
            f'"{domain}" password',
            f'"{domain}" secret',
            f'"{domain}" apikey',
            f'"{domain}" token',
        ]
        seen = set()
        for query in queries:
            self._check_abort()
            url = f"https://api.github.com/search/code?q={quote(query)}&per_page=20"
            result = self._run_cmd(
                [
                    "curl", "-s",
                    "-H", f"Authorization: Bearer {token}",
                    "-H", "Accept: application/vnd.github+json",
                    url,
                ],
                timeout=60,
            )
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                continue
            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                if not html_url or html_url in seen:
                    continue
                seen.add(html_url)
                self._record_url(html_url, "GitHub Secrets", callbacks, "found")
                callbacks["log"](f"[GitHub Secrets] {repo}/{path}")

    def _run_takeover_check(self, domain, callbacks):
        hosts = sorted(self.subdomains)[:200]
        use_dnsx = shutil.which("dnsx")

        for host in hosts:
            self._check_abort()
            cname = ""
            if use_dnsx:
                result = self._run_cmd(
                    ["dnsx", "-silent", "-cname", "-d", host],
                    timeout=30,
                )
                cname = result.stdout.strip().lower().rstrip(".")
            elif shutil.which("dig"):
                result = self._run_cmd(["dig", "+short", "CNAME", host], timeout=20)
                cname = result.stdout.strip().lower().rstrip(".")

            if not cname:
                continue

            for sig in TAKEOVER_CNAME_SIGS:
                if cname == sig or cname.endswith(f".{sig}"):
                    note = f"Possible takeover — CNAME: {cname}"
                    callbacks["takeover_found"](host, cname, note)
                    callbacks["log"](f"[Takeover Check] {host} -> {cname}")
                    self._append_tool_text(f"{host} -> {cname}\n")
                    break

    def _run_url_param_filter(self, domain, callbacks):
        if not self.config.get("url_param_filter", True):
            callbacks["log"]("[URL Param Filter] Disabled in settings")
            return

        filtered = filter_param_urls(self.collected_urls)
        callbacks["log"](f"[URL Param Filter] {len(filtered)} parameterized endpoints")
        lines = []
        for url in filtered:
            self._check_abort()
            key = dedupe_key(url)
            if key in self._url_dedupe_keys:
                continue
            self._url_dedupe_keys.add(key)
            self.collected_urls.add(url)
            callbacks["url_found"]("URL Param Filter", url, "param")
            callbacks["log"](f"[URL Param Filter] {url}")
            lines.append(url)
        if lines:
            self._append_tool_text("\n".join(lines) + "\n")

    def _run_sensitive_files(self, domain, callbacks):
        self._bootstrap_urls_if_empty(domain, callbacks)
        urls = sorted(self.collected_urls)
        allurls_path = self._save_allurls_snapshot(domain)
        if allurls_path:
            callbacks["log"](f"[Sensitive Files] Saved {len(urls)} URLs -> {allurls_path}")

        dork = build_sensitive_dork(domain)
        self._append_tool_text(f"# Google dork reference\n{dork}\n\n# Regex matches\n")

        seen = set()
        matched_lines = []
        for url in urls:
            self._check_skip()
            ok, reason = match_sensitive_url(url)
            if ok and url not in seen:
                seen.add(url)
                matched_lines.append(f"{url}\t{reason}")
                self._record_sensitive(url, "Sensitive Files", callbacks, status="file", note=reason)

        if matched_lines:
            self._append_tool_text("\n".join(matched_lines) + "\n")
        callbacks["log"](f"[Sensitive Files] {len(seen)} sensitive file URLs from {len(urls)} total")

    def _run_arjun_params(self, domain, callbacks):
        targets = [f"https://{host}/" for host in sorted(self.live_hosts)[:10]]
        if not targets:
            targets = [f"https://{host}/" for host in sorted(self.subdomains)[:10]]
        for url in sorted(self.collected_urls):
            if len(targets) >= 15:
                break
            if url.startswith("http") and "?" not in url:
                targets.append(url if url.endswith("/") else f"{url}/")
        targets = list(dict.fromkeys(targets))[:8]
        if not targets:
            callbacks["log"]("[Arjun Params] No endpoints to probe")
            return

        wordlist = self._find_wordlist(ARJUN_WORDLIST_CANDIDATES)
        for target in targets:
            self._check_abort()
            out_file = Path(tempfile.gettempdir()) / f"arjun_{abs(hash(target))}.txt"
            try:
                cmd = [
                    "arjun", "-u", target,
                    "-oT", str(out_file),
                    "-t", "10", "--rate-limit", "10",
                    "--passive",
                    "-m", "GET,POST",
                    "-T", "15",
                    "--headers", "User-Agent: Mozilla/5.0",
                ]
                result = self._run_cmd(cmd, timeout=300)
                self._log_stderr("Arjun Params", result, callbacks)
                output = ""
                if out_file.is_file():
                    output = out_file.read_text(encoding="utf-8", errors="ignore")
                    self._append_tool_text(f"# {target}\n{output}\n")
                params = []
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("parameter") or ":" in line:
                        params.append(line)
                    elif re.match(r"^[a-zA-Z0-9_\-\[\]]+$", line):
                        params.append(line)
                if params:
                    note = ", ".join(params[:12])
                    if len(params) > 12:
                        note += f" (+{len(params) - 12} more)"
                    self._record_sensitive(target, "Arjun Params", callbacks, status="params", note=note)
                elif wordlist:
                    active_cmd = [
                        "arjun", "-u", target,
                        "-oT", str(out_file),
                        "-t", "10", "--rate-limit", "10",
                        "-m", "GET,POST",
                        "-w", str(wordlist),
                        "-T", "15",
                        "--headers", "User-Agent: Mozilla/5.0",
                    ]
                    active = self._run_cmd(active_cmd, timeout=300)
                    self._log_stderr("Arjun Params", active, callbacks)
                    if out_file.is_file():
                        output = out_file.read_text(encoding="utf-8", errors="ignore")
                        params = [
                            line.strip() for line in output.splitlines()
                            if line.strip() and not line.startswith("#")
                        ]
                        if params:
                            note = ", ".join(params[:12])
                            self._record_sensitive(target, "Arjun Params", callbacks, status="params", note=note)
            finally:
                out_file.unlink(missing_ok=True)

    def _run_js_recon(self, domain, callbacks):
        js_urls = {url for url in self.collected_urls if is_js_url(url)}

        if shutil.which("katana"):
            targets = self._host_urls(limit=10, prefer_live=True) or self._host_urls(limit=10, prefer_live=False)
            if targets:
                list_file = self._write_temp_lines(
                    f"js_katana_{domain.replace('.', '_')}.txt",
                    targets,
                )
                try:
                    result = self._run_cmd(
                        ["katana", "-list", str(list_file), "-d", "3", "-silent", "-jc"],
                        timeout=600,
                    )
                    self._log_stderr("JS Recon", result, callbacks)
                    for line in result.stdout.splitlines():
                        url = line.strip()
                        if url and is_js_url(url):
                            js_urls.add(url)
                            self._record_url(url, "JS Recon", callbacks, "-")
                finally:
                    list_file.unlink(missing_ok=True)

        js_list = sorted(js_urls)
        jsfiles_path = None
        if self.session_dir and js_list:
            jsfiles_path = Path(self.session_dir) / "js" / "jsfiles.txt"
            jsfiles_path.parent.mkdir(parents=True, exist_ok=True)
            jsfiles_path.write_text("\n".join(js_list) + "\n", encoding="utf-8")
            callbacks["log"](f"[JS Recon] Saved {len(js_list)} JS URLs -> {jsfiles_path}")

        self._append_tool_text(f"# JS files ({len(js_list)})\n" + "\n".join(js_list[:200]) + "\n")

        nuclei_templates = self._find_nuclei_exposures()
        if js_list and shutil.which("nuclei") and nuclei_templates:
            list_file = self._write_temp_lines(
                f"js_nuclei_{domain.replace('.', '_')}.txt",
                js_list[:50],
            )
            try:
                result = self._run_cmd(
                    [
                        "nuclei", "-l", str(list_file),
                        "-t", str(nuclei_templates),
                        "-c", "30", "-silent",
                    ],
                    timeout=600,
                )
                if result.stdout.strip():
                    self._append_tool_text(f"# nuclei exposures\n{result.stdout}\n")
            finally:
                list_file.unlink(missing_ok=True)
        elif js_list and not nuclei_templates:
            callbacks["log"]("[JS Recon] Set nuclei_templates in Settings for nuclei exposure scan")

        httpx = self._httpx_bin()
        live_js = []
        if js_list and shutil.which(httpx):
            probe_input = "\n".join(js_list[:50]) + "\n"
            result = self._run_cmd(
                [httpx, "-silent", "-status-code", "-content-type", "-mc", "200"],
                input_text=probe_input,
                timeout=300,
            )
            self._append_tool_text(f"# httpx JS probe\n{result.stdout}\n")
            for line in result.stdout.splitlines():
                lower = line.lower()
                if "javascript" in lower or ".js" in lower:
                    url = line.split()[0].strip()
                    if url:
                        live_js.append(url)

        fetch_targets = live_js[:40] if live_js else js_list[:40]
        secrets_by_url = {}
        secrets_found = 0
        for url in fetch_targets:
            self._check_abort()
            result = self._run_cmd(
                ["curl", "-sL", "--max-time", "20", "-A", "Mozilla/5.0", url],
                timeout=25,
            )
            body = result.stdout or ""
            secrets = scan_text_for_secrets(body)
            if secrets:
                secrets_found += 1
                notes = [f"[{label}] {snippet}" for label, snippet in secrets[:3]]
                note = " | ".join(notes)[:240]
                secrets_by_url[url] = note
                self._append_tool_text(f"# secrets in {url}\n{note}\n")

        self._emit_js_results(js_list, secrets_by_url, callbacks)
        callbacks["log"](f"[JS Recon] {len(js_list)} JS files, {secrets_found} with secrets")

    def _emit_js_results(self, js_list, secrets_by_url, callbacks):
        if not js_list:
            return
        entries = []
        for url in js_list:
            if url in secrets_by_url:
                entries.append((url, "secret", secrets_by_url[url]))
            else:
                entries.append((url, "js", ""))
        batch_cb = callbacks.get("js_batch_found")
        if batch_cb:
            batch_cb("JS Recon", entries)
        else:
            for url, status, note in entries:
                self._record_js(url, "JS Recon", callbacks, status=status, note=note)

    def _log_stderr(self, tool, result, callbacks):
        if result.stderr.strip():
            callbacks["log"](f"[{tool}] {result.stderr.strip()[:300]}")
