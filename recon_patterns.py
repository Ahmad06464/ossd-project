import re

SENSITIVE_EXT_INLINE = re.compile(
    r"\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|"
    r"key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|"
    r"sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)(?:[?#]|$)",
    re.I,
)

SENSITIVE_EXT_GREP = re.compile(
    r"\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|"
    r"key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|"
    r"sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$",
    re.I,
)

JS_URL_PATTERN = re.compile(r"\.js(?:[?#]|$)", re.I)

JS_SECRET_PATTERNS = [
    (re.compile(r"(?i)(aws_access_key\s*[:=]\s*['\"]?[A-Z0-9/+=]{16,})"), "aws_access_key"),
    (re.compile(r"(?i)(aws_secret_key\s*[:=]\s*['\"]?[^\s'\"]{16,})"), "aws_secret_key"),
    (re.compile(r"(?i)(api[_-]?key\s*[:=]\s*['\"]?[^\s'\"]{8,})"), "api_key"),
    (re.compile(r"(?i)(secret[_-]?(?:key|token)?\s*[:=]\s*['\"]?[^\s'\"]{8,})"), "secret"),
    (re.compile(r"(?i)(password\s*[:=]\s*['\"]?[^\s'\"]{4,})"), "password"),
    (re.compile(r"(?i)(oauth[_-]?token(?:_secret)?\s*[:=]\s*['\"]?[^\s'\"]{8,})"), "oauth_token"),
    (re.compile(r"(?i)(firebase[a-z0-9_./-]{8,})"), "firebase"),
    (re.compile(r"(?i)(slack[_-]?(?:token|webhook)[^\s'\"]{8,})"), "slack"),
    (re.compile(r"(?i)(heroku[^\s'\"]{8,})"), "heroku"),
    (re.compile(r"(?i)(['\"]?[A-Za-z0-9_./-]*\.env['\"]?)"), "env_ref"),
    (re.compile(r"(?i)(access[_-]?key\s*[:=]\s*['\"]?[^\s'\"]{8,})"), "access_key"),
    (re.compile(r"(?i)(token\s*[:=]\s*['\"]?[^\s'\"]{12,})"), "token"),
    (re.compile(r"(?i)(jdbc:[^\s'\"]+)"), "jdbc"),
    (re.compile(r"(?i)(swagger[^\s'\"]{4,})"), "swagger"),
    (re.compile(r"(?i)(BEGIN (?:RSA )?PRIVATE KEY)"), "private_key"),
    (re.compile(r"(?i)(ghp_[A-Za-z0-9_]{20,})"), "github_pat"),
    (re.compile(r"(?i)(AIza[0-9A-Za-z\-_]{35})"), "gcp_api_key"),
]

DORK_EXTENSIONS = (
    "doc", "docx", "odt", "pdf", "rtf", "ppt", "pptx", "csv", "xls", "xlsx",
    "txt", "xml", "json", "zip", "rar", "md", "log", "bak", "conf", "sql",
)


def build_sensitive_dork(domain):
    ext_clause = " OR ".join(f"ext:{ext}" for ext in DORK_EXTENSIONS)
    return f"site:*.{domain} ({ext_clause})"


def match_sensitive_url(url):
    url = (url or "").strip()
    if not url:
        return False, ""
    match = SENSITIVE_EXT_INLINE.search(url) or SENSITIVE_EXT_GREP.search(url.split("?")[0])
    if not match:
        return False, ""
    ext = match.group(0).lstrip(".").split("?")[0]
    return True, f"sensitive .{ext}"


def is_js_url(url):
    return bool(JS_URL_PATTERN.search(url or ""))


def scan_text_for_secrets(text, max_hits=5):
    if not text:
        return []
    hits = []
    seen = set()
    for pattern, label in JS_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(1) if match.lastindex else match.group(0)
            snippet = " ".join(snippet.split())
            key = (label, snippet[:80])
            if key in seen:
                continue
            seen.add(key)
            hits.append((label, snippet[:120]))
            if len(hits) >= max_hits:
                return hits
    return hits
