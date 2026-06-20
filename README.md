# Recon Intelligence Dashboard

A desktop reconnaissance orchestration tool for bug bounty hunters, penetration testers, and security researchers. It wraps dozens of popular CLI recon tools behind a modern **CustomTkinter** GUI, runs them in a structured pipeline, and presents live results across organized tabs — subdomains, URLs, IPs, buckets, sensitive files, and JavaScript assets.

Instead of juggling terminal windows and log files, you get one dashboard to start scans, monitor tool progress, filter findings, add notes, resume interrupted work, and export polished reports.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Scan Profiles](#scan-profiles)
- [Built-in Tools](#built-in-tools)
- [Dashboard Tabs](#dashboard-tabs)
- [Scan Workspace](#scan-workspace)
- [Resume & Session Management](#resume--session-management)
- [Export & Reporting](#export--reporting)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Wordlist Management](#wordlist-management)
- [Project Structure](#project-structure)
- [Legal & Responsible Use](#legal--responsible-use)

---

## Features

### Recon pipeline
- **29 integrated tools** across subdomain discovery, HTTP probing, URL harvesting, IP intelligence, cloud bucket checks, and deep recon.
- **Scan profiles** — Full, Quick, Passive, and Probe Only — or pick individual tools in Settings.
- **Multi-target queue** — scan one domain now, queue additional targets for later.
- **Scope filtering** — restrict results to in-scope domains via `scope.txt` or config.
- **Auto URL deduplication** and optional parameter-URL filtering.

### Live dashboard
- Real-time stats cards: subdomains, live hosts, URLs, IPs, buckets, sensitive files, JS files, takeovers.
- **Six result tabs**: Subdomains, URLs, IPs, Buckets, Sensitive, JS.
- Wrapping data tables — long URLs and hostnames display cleanly without truncation.
- HTTP probe details in a single aligned column: `Found by · Length · Title · Tech · Status`.
- Color-coded status rows (200 = green, 403 = amber, 5xx = red, takeover = highlighted).
- Screenshot thumbnails (via Aquatone) — click the 📷 column to open.
- Search, status filters, column sorting, right-click **Add note** / **Remove**.

### Workflow
- **Stop / Skip** individual tools mid-scan.
- **Resume** interrupted scans from the last completed tool.
- **New Scan** — archive current results and start fresh (`Ctrl+Shift+N`).
- **Re-run** any single tool on existing data.
- Drag-and-drop `.txt` target files into the window (requires `tkinterdnd2`).
- Dark / light theme toggle.

### Persistence & export
- Automatic workspace output per scan session on disk.
- `findings.json` auto-saved during scans.
- Export to **TXT**, **Excel**, **HTML report**, or portable **JSON session**.
- Import previous scans, diff two sessions, load latest from workspace folder.
- Optional desktop notification on scan completion (`notify-send`).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Recon Intelligence Dashboard               │
│                         (main.py / GUI)                     │
├──────────────┬──────────────────┬───────────────────────────┤
│ gui_helpers  │  scan_runner.py  │  scan_storage.py          │
│ (UI tables,  │  (tool pipeline, │  (workspace layout,       │
│  tool groups)│   subprocess)    │   findings persistence) │
├──────────────┴──────────────────┴───────────────────────────┤
│ recon_patterns.py │ url_utils.py │ config_loader.py        │
│ export_results.py │ html_report.py │ scan_resume.py        │
└─────────────────────────────────────────────────────────────┘
                              │
                    External CLI tools
              (subfinder, httpx, katana, ffuf, …)
```

**Scan flow:**
1. User selects target + profile → `ScanRunner` creates a timestamped session folder.
2. Tools run sequentially; each streams results back via callbacks to the GUI.
3. Subdomains are probed with **httpx** (title, content-length, tech, status, IP).
4. URL harvesters feed a shared URL pool; `.js` URLs route to the **JS** tab automatically.
5. Results persist to `findings.json` and per-tool output files under `scan_output/`.

---

## Requirements

### Python
- **Python 3.10+** (tested on Python 3.13)
- **customtkinter** — modern Tkinter UI
- **openpyxl** — Excel export
- **Pillow** — app icon (optional, auto-generated if missing)
- **tkinterdnd2** — drag-and-drop targets (optional)

```bash
pip install customtkinter openpyxl pillow tkinterdnd2
```

### External CLI tools
Tools are detected at runtime. Missing binaries are **skipped** with a status message — the scan continues with available tools.

| Category | Tools | CLI binaries |
|----------|-------|--------------|
| Discovery | Subfinder, Assetfinder, Findomain, Amass, crt.sh, Wayback CDX, SecurityTrails, VirusTotal Subs, GitHub Subs, GitHub Secrets, FFUF DNS | `subfinder`, `assetfinder`, `findomain`, `amass`, `ffuf`, `curl`, `jq`, `grep`, `github-subdomains` |
| Probe | HTTP Probe, Takeover Check, FFUF Path, Cloud Buckets, Aquatone | `httpx` or `httpx-toolkit`, `dig`/`dnsx`, `ffuf`, `aquatone` |
| Intel & URLs | VT/OTX/URLScan IP harvest, Shodan, GAU, Katana, URLFinder, Hakrawler, URL Param Filter | `curl`, `jq`, `shodan`, `gau`, `katana`, `urlfinder`, `hakrawler` |
| Deep Recon | Sensitive Files, Arjun Params, JS Recon | `arjun`, `katana`, `nuclei`, `curl` |

> **Kali Linux** ships with most of these tools. On other distros, install via Go (`go install …`), apt, or project-specific installers.

### API keys (optional)
Some tools need keys in `config.json`:

| Tool | Config key |
|------|------------|
| SecurityTrails | `securitytrails_api_key` |
| VirusTotal Subs / VT IP Harvest | `virustotal_api_key` |
| GitHub Subs / GitHub Secrets | `github_token` |
| Shodan | `shodan_api_key` |

Tools without keys are skipped automatically.

---

## Installation

```bash
git clone <repository-url>
cd ossd-project

# Install Python dependencies
pip install customtkinter openpyxl pillow

# Optional: drag-and-drop support
pip install tkinterdnd2

# Create config from example
cp config.example.json config.json

# Edit API keys, wordlists, workspace path
nano config.json

# Run
python3 main.py
```

---

## Quick Start

1. **Launch** the app: `python3 main.py`
2. Enter a target domain (e.g. `example.com`) in the top bar.
3. Choose a **scan profile** in Settings (default: **Full**).
4. Click **Start Scan**.
5. Watch results populate in the **Subdomains** tab in real time.
6. Switch tabs to browse URLs, IPs, buckets, sensitive files, and JS assets.
7. Use **Export HTML report** or **Save session** when done.

**Tip:** Set `scan_workspace` in config to control where scan output is saved. Default: `./scan_output/`.

---

## Configuration

Copy `config.example.json` to `config.json` and adjust:

```json
{
  "securitytrails_api_key": "",
  "virustotal_api_key": "",
  "github_token": "",
  "shodan_api_key": "",
  "scope_domains": [],
  "scope_file": "scope.txt",
  "notify_on_complete": true,
  "default_timeout": 300,
  "httpx_threads": 50,
  "dns_wordlist": "",
  "path_wordlist": "",
  "appearance_mode": "dark",
  "url_dedupe": true,
  "url_param_filter": true,
  "default_scan_profile": "Full",
  "scan_workspace": "",
  "nuclei_templates": "",
  "amass_config": "~/.config/amass/config.ini"
}
```

| Setting | Description |
|---------|-------------|
| `scope_file` / `scope_domains` | Only keep hosts/URLs matching in-scope domains |
| `httpx_threads` | Parallel threads for HTTP Probe |
| `default_timeout` | Per-tool subprocess timeout (seconds) |
| `url_dedupe` | Deduplicate collected URLs across tools |
| `url_param_filter` | Extract and tag URLs with query parameters |
| `dns_wordlist` | Custom wordlist for FFUF DNS brute-force |
| `path_wordlist` | Custom wordlist for FFUF path fuzzing |
| `nuclei_templates` | Nuclei templates path for JS Recon |
| `scan_workspace` | Root folder for all scan sessions |
| `notify_on_complete` | Show dialog + `notify-send` when scan finishes |

---

## Scan Profiles

| Profile | Tools included | Best for |
|---------|----------------|----------|
| **Full** | All 29 tools | Comprehensive recon |
| **Quick** | Subfinder, HTTP Probe, Aquatone | Fast initial look |
| **Passive** | Passive subdomain sources + HTTP Probe | Stealth / no active DNS brute |
| **Probe Only** | HTTP Probe, Aquatone, FFUF Path | Re-probe known hosts |

You can also toggle individual tools in **Settings → Tool selection**.

---

## Built-in Tools

### Discovery
| Tool | What it does |
|------|--------------|
| **Subfinder** | Passive subdomain enumeration |
| **Assetfinder** | Asset discovery via multiple sources |
| **Findomain** | Fast subdomain finder |
| **Amass Passive** | OWASP Amass passive mode |
| **Amass Active** | Amass with active DNS brute-force |
| **crt.sh** | Certificate transparency logs |
| **Wayback CDX** | Historical subdomains from Wayback Machine |
| **SecurityTrails** | Subdomains via SecurityTrails API |
| **VirusTotal Subs** | Subdomains from VirusTotal |
| **GitHub Subs** | Subdomains from GitHub code search |
| **GitHub Secrets** | Search GitHub for leaked secrets related to target |
| **FFUF DNS** | DNS subdomain brute-force with wordlist |

### Probe
| Tool | What it does |
|------|--------------|
| **HTTP Probe** | Live host detection via httpx (status, title, tech, IP, content-length) |
| **Takeover Check** | CNAME dangling / subdomain takeover signatures |
| **FFUF Path** | Path fuzzing on live hosts |
| **Cloud Buckets** | Probe common S3/Azure/GCP bucket naming patterns |
| **Aquatone** | Screenshot live web services |

### Intel & URLs
| Tool | What it does |
|------|--------------|
| **VT IP Harvest** | IPs from VirusTotal passive DNS |
| **OTX IP Harvest** | IPs from AlienVault OTX |
| **URLScan IP** | IPs from URLScan.io |
| **Shodan** | Host info from Shodan API |
| **GAU** | URLs from Wayback, Common Crawl, OTX, URLScan |
| **Katana** | Web crawler for URLs and JS files |
| **URLFinder** | Passive URL discovery |
| **Hakrawler** | Simple web crawler |
| **URL Param Filter** | Filter URLs containing query parameters |

### Deep Recon
| Tool | What it does |
|------|--------------|
| **Sensitive Files** | Regex scan of collected URLs for sensitive extensions (`.env`, `.sql`, `.bak`, etc.) |
| **Arjun Params** | Passive HTTP parameter discovery |
| **JS Recon** | Katana JS crawl → Nuclei exposure scan → httpx probe → curl + secret regex (AWS keys, API tokens, etc.) |

> **Note:** Any `.js` URL found by **any** tool is automatically routed to the **JS** tab, not the URLs tab.

---

## Dashboard Tabs

### Subdomains
- Columns: **Screenshot** · **Host** · **Probe details** · **Note**
- Probe column format: `Found by · Length · Title · Tech · Status` (wraps cleanly on long titles)
- Double-click a host to open it in the browser
- Click 📷 to open Aquatone screenshot

### URLs
- Discovered endpoints (non-JS)
- Shows source tool, status, and notes

### IPs
- Harvested IP addresses with HTTP probe details and related domain

### Buckets
- Cloud storage bucket candidates and probe status

### Sensitive
- URLs matching sensitive file patterns (configs, backups, credentials files, etc.)

### JS
- JavaScript file URLs from all tools
- JS Recon secret findings appear here with status and notes

---

## Scan Workspace

Each scan creates a timestamped folder:

```
scan_output/
└── example.com/
    └── 2026-06-17_091736/
        ├── meta.json              # target, profile, timestamps, resume state
        ├── findings.json          # all GUI findings (auto-saved)
        ├── http_probe.txt         # httpx output
        ├── takeover_check.txt
        ├── github_secrets.txt
        ├── aquatone.log
        ├── subdomains/
        │   ├── subfinder.txt
        │   ├── assetfinder.txt
        │   └── ...
        ├── urls/
        │   ├── allurls.txt        # merged URL snapshot
        │   ├── gau.txt
        │   ├── katana.txt
        │   └── ...
        ├── ips/
        ├── buckets/
        ├── sensitive/
        ├── js/
        └── aquatone/              # screenshots + HTML report
```

Tool output files include `# CMD:` headers showing the exact command that was run.

---

## Resume & Session Management

### Auto-resume
If you scan the **same target** again without clearing results, the app offers to resume from the last incomplete tool.

### Stop & resume
- **Stop** pauses the scan and saves progress in memory.
- **Resume** continues from the next pending tool.
- **Save session** exports full state to a portable JSON file.

### New Scan
**File → New Scan** (or `Ctrl+Shift+N`) archives the current scan to the workspace and starts a clean session for the same or new target.

### Session diff
**File → Diff sessions** compares two JSON session files and shows new/removed subdomains, URLs, IPs, and buckets.

---

## Export & Reporting

| Format | Menu item | Contents |
|--------|-----------|----------|
| **TXT** | File → Export TXT | Plain-text findings table |
| **Excel** | File → Export Excel | Spreadsheet with ScanMeta + Results sheets |
| **HTML** | File → Export HTML report | Styled web report with stats and tables |
| **JSON** | File → Save session | Full session including resume state |

Import via **File → Import scan export** (supports `.json`, `.txt`, `.xlsx`, `.html`).

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Start scan |
| `Ctrl+Shift+N` | New scan (archive current) |
| `Ctrl+S` | Save session |
| `Ctrl+F` | Focus search filter |
| `Ctrl+B` | Toggle sidebar |
| `Ctrl+D` | Toggle dark/light theme |
| `Ctrl+L` | Focus target entry |
| `Ctrl+1` – `Ctrl+6` | Switch tabs (Subdomains → JS) |
| `Ctrl+N` | Add finding manually |

---

## Wordlist Management

Built-in wordlists live in `wordlists/`:
- `dns-subdomains.txt` — fallback DNS brute wordlist
- `common.txt` — path fuzzing fallback
- `my-own-wordlist.txt` — your custom endpoints (editable from the UI)

The app can sync `my-own-wordlist.txt` to a GitHub repository if configured:
- `github_wordlist_repo`
- `github_wordlist_path`
- `github_wordlist_branch`

FFUF tools auto-detect SecLists paths on Kali:
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`

---

## Project Structure

```
ossd-project/
├── main.py                 # GUI application entry point
├── scan_runner.py          # Scan orchestration & tool runners
├── scan_storage.py         # Workspace & findings persistence
├── scan_resume.py          # Resume state helpers
├── scan_import_export.py   # Session import/export utilities
├── gui_helpers.py          # WrapDataTable, tool groups, UI styles
├── recon_patterns.py       # Sensitive/JS URL patterns & secret regex
├── url_utils.py            # URL normalization & deduplication
├── config_loader.py        # config.json loader & scope checks
├── export_results.py       # TXT & Excel export
├── html_report.py          # HTML report generator
├── wordlist_manager.py     # Wordlist & GitHub sync
├── config.example.json     # Configuration template
├── scope.txt               # In-scope domains (optional)
├── wordlists/              # Bundled & custom wordlists
├── assets/                 # App icon
└── scan_output/            # Default scan workspace
```

---

## Legal & Responsible Use

**Only use this tool on systems you own or have explicit written authorization to test.**

Unauthorized scanning, crawling, or probing of third-party infrastructure may violate computer crime laws and terms of service. The authors are not responsible for misuse. Always:

- Obtain proper scope and permission before scanning
- Respect rate limits and robots policies where applicable
- Follow your program's rules of engagement (bug bounty, pentest, etc.)
- Handle discovered credentials and sensitive data responsibly

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Tool shows **Skipped** | Install the required CLI binary or add the API key |
| No results in a tab | Check the log panel at the bottom for errors |
| Scan won't resume | Save session to JSON, reload, and click Resume |
| `httpx` not found | Install `httpx-toolkit` (Kali) or ProjectDiscovery `httpx` |
| Drag-and-drop not working | `pip install tkinterdnd2` and restart |
| Dialog errors on close | Fixed in recent versions — update to latest `main.py` |

---

## License:


