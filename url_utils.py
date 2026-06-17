import re
from urllib.parse import parse_qs, urlparse, urlunparse

PARAM_EXT_RE = re.compile(r"\.(php|asp|aspx|jsp|jspx)(?:\?|$)", re.IGNORECASE)
HAS_PARAM_RE = re.compile(r"[?&][^=]+=")


def normalize_url(url):
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    scheme = parsed.scheme.lower()
    return urlunparse((scheme, host, path, parsed.params, parsed.query, ""))


def dedupe_key(url):
    normalized = normalize_url(url)
    if not normalized:
        return ""
    parsed = urlparse(normalized)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    query = "&".join(sorted(parse_qs(parsed.query, keep_blank_values=True).keys()))
    return f"{host}{path}?{query}" if query else f"{host}{path}"


def is_param_candidate(url):
    if not HAS_PARAM_RE.search(url):
        return False
    return bool(PARAM_EXT_RE.search(url.split("?", 1)[0]))


def strip_param_values(url):
    base = url.split("#", 1)[0]
    if "?" not in base:
        return base
    path, query = base.split("?", 1)
    keys = []
    for part in query.split("&"):
        if "=" in part:
            keys.append(part.split("=", 1)[0] + "=")
        elif part:
            keys.append(part)
    return path + "?" + "".join(keys) if keys else path


def filter_param_urls(urls):
    seen = set()
    results = []
    for url in urls:
        if not is_param_candidate(url):
            continue
        cleaned = strip_param_values(normalize_url(url))
        key = dedupe_key(cleaned)
        if key and key not in seen:
            seen.add(key)
            results.append(cleaned)
    return results


def dedupe_urls(urls):
    seen = set()
    results = []
    for url in urls:
        key = dedupe_key(url)
        if key and key not in seen:
            seen.add(key)
            results.append(normalize_url(url) or url.strip())
    return results
