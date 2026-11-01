# PHNwn2Shell - passive IoC sensor (HTTP honeypot) for PHP2Shell, Node2Shell and HTTP2Shell
#
# Purpose: log what scanners and exploit tools send to a decoy that answers like
# a PHP/Apache site (ports 80 and 443) or a Node.js/Express site (port 3000),
# and feed those events to Wazuh as one JSON line per request. The sensor never
# executes what it receives, makes no outbound connections and downloads nothing.
#
# This file: Request analysis: multipart statistics, tool fingerprints, IoC extraction and stage assignment.
#
# Author: Kislley Rodrigues - Wazuh Ambassador
#
# References:
#   https://www.php.net/archive/2026.php#2026-10-21-5
#   https://www.wiz.io/blog/php2shell-php-rce
#   https://calif.io/php2shell/
#
# Part of PHP2Shell-Detection-with-Wazuh. Wazuh rules: rules/phnwn_rules.xml
# Installation: phnwn2shell/INSTALL.md

"""Request analysis: multipart statistics, tool fingerprints, IoCs, stage.

Everything here is passive text processing. Nothing is decoded with a
decompression library, nothing is executed and nothing is fetched.
"""

import base64
import binascii
import ipaddress
import re
import urllib.parse

BR_RE = re.compile(r"(^|[\s,;])br(\s*(;|,|$))", re.I)
BOUNDARY_RE = re.compile(r'boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))', re.I)
NAME_RE = re.compile(rb'(?:^|[;\s])name="([^"]*)"', re.I)
FILENAME_RE = re.compile(rb'filename="([^"]*)"', re.I)
# No leading word boundary: droppers glue the scheme to $IFS ("$IFShttp://...").
URL_RE = re.compile(
    r"""(?:https?|ftp|tftp|ldaps?|rmi|dns|gopher)://[^\s'"<>`|;)$\\{}+]{4,300}""",
    re.I)
# JNDI callback with nested lookups kept verbatim: ${jndi:ldap://h-${sys:x}.id.example}
JNDI_URL_RE = re.compile(
    r"\$\{jndi:((?:ldaps?|rmi|dns|iiop|corba|nis|https?)://"
    r"(?:[^\s'\"<>`{}$|;]|\$\{[^{}$]{1,80}\}){4,400})\}?", re.I)
# Log4j default lookup: ${anything:-value}. The key can hold colons and junk.
LOOKUP_DEFAULT_RE = re.compile(r"\$\{[^${}]*?:-([^${}]*)\}")
LOOKUP_CASE_RE = re.compile(r"\$\{(lower|upper):([^${}]*)\}", re.I)
LOG4J_PASSES = 12
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_RE = re.compile(r"[A-Za-z0-9+/]{24,400}={0,2}")
CODE_RE = re.compile(
    r"<\?(?:php|=)|\b(?:system|exec|passthru|shell_exec|popen|proc_open|eval|"
    r"assert|base64_decode)\s*\(|"
    r"\b(?:curl|wget|tftp|busybox|chmod|certutil|powershell)"
    r"(?:\s+|\$\{?IFS\b\}?)\S|\$\{?IFS\b|"
    r"/bin/(?:ba)?sh\b|\bbash\s+-[ic]\b|"
    r"\|\s*(?:ba|z|da)?sh\b|\bbase64\s+-d\b|"
    r"\b(?:python[0-9.]*|perl|ruby|php|node)\s+-[ce]\b|\bnc(?:at)?\s+-[a-z]*e\b|"
    r"\bcmd(?:\.exe)?\s*/c\b|/dev/tcp/|\bcat\s+/etc/(?:passwd|shadow)|"
    r"\b(?:child_process|execsync|process\.mainmodule)\b|\bjndi:|"
    r"\(\)\s*\{\s*:\s*;\s*\}", re.I)
# Injection syntax, independent of any specific CVE or command.
INJ_RE = re.compile(r"\$\{|\$\(|`|\(\)\s*\{|<\?|%\{|\{\{", re.I)
SERIALIZED_RE = re.compile(r"(?:^|[|;{])[OaCr]:\d+:")
SESS_PATH_RE = re.compile(r"/sess_[A-Za-z0-9,-]{8,}", re.I)
PROBE_MARKER = b"___PHP2SHELL_PROBE_"

# Boundary prefixes seen in public tooling (lower case, prefix match).
BOUNDARY_FAMILIES = (
    ("scanbound", "ikow_scanner"), ("writebound", "ikow_scanner"),
    ("oomprobe", "ikow_scanner"), ("p2shell", "p2shell_tool"),
    ("p2s", "p2s_tool"), ("nucleiboundary", "nuclei"), ("atk", "atk_tool"),
    ("chkbnd", "manual_curl"),
)
# User agent substrings (lower case).
UA_FAMILIES = (
    ("node2shell-check", "node2shell_check"), ("php2shell", "php2shell_ua"),
    ("php-session-startup-rce", "php_session_startup_rce"),
    ("nuclei", "nuclei"), ("zgrab", "zgrab"), ("b8rat", "b8rat"),
    ("company-php-audit", "php_audit"), ("fasthttp", "fasthttp"),
    ("python-requests", "python_requests"), ("curl/", "curl"),
    ("go-http-client", "go_http_client"), ("masscan", "masscan"),
    ("palo alto networks", "palo_alto_xpanse"),
    ("cortex-xpanse", "palo_alto_xpanse"), ("awscan-agent", "awscan"),
    ("censysinspect", "censys"), ("nmap scripting engine", "nmap_nse"),
    ("sqlmap", "sqlmap"), ("nikto", "nikto"), ("wpscan", "wpscan"),
    ("gobuster", "gobuster"), ("dirbuster", "dirbuster"),
    ("libwww-perl", "libwww_perl"), ("python-urllib", "python_urllib"),
    ("wget/", "wget"), ("okhttp", "okhttp"),
    ("apache-httpclient", "apache_httpclient"),
)
# The sensor serves one page. Only these paths are a plain visit; anything
# else is a probe by construction, known or not.
ALLOWED_PATHS = {
    "php": frozenset({"/", "/index.php", "/favicon.ico", "/robots.txt",
                      "/sitemap.xml", "/humans.txt", "/ads.txt",
                      "/.well-known/security.txt"}),
    "node": frozenset({"/", "/favicon.ico", "/robots.txt", "/sitemap.xml",
                       "/humans.txt", "/ads.txt",
                       "/.well-known/security.txt"}),
}
# Labels for what an unlisted path is after (patterns, not a path list).
PATH_CATEGORIES = {
    "secrets": re.compile(
        r"/\.(?:env|git|svn|hg|aws|ssh|htaccess|htpasswd|ds_store)\b|"
        r"/(?:id_rsa|credentials)\b|/etc/(?:passwd|shadow)"),
    "wordpress": re.compile(r"/wp-(?:login|admin|content|includes|json)|/xmlrpc\.php"),
    "db_admin": re.compile(r"/(?:phpmyadmin|pma|adminer|myadmin)\b"),
    "java": re.compile(r"/actuator\b|/jmx-console|/manager/html|/solr/|/geoserver/|/jenkins"),
    "cgi_iot": re.compile(r"/cgi-bin/|/boaform/|/hnap1|/goform/|/setup\.cgi"),
    "webmail": re.compile(r"/(?:owa|ecp)/|/autodiscover/|/remote/login"),
    "vendor_dir": re.compile(r"/vendor/"),
    "config_backup": re.compile(
        r"/(?:config|configuration|settings|database|db)\.(?:php|json|ya?ml|inc|bak)\b|"
        r"/(?:backup|dump|db)\.(?:sql|zip|tar|tar\.gz|bak)\b"),
    "api_discovery": re.compile(r"/(?:api|v1|v2|swagger|openapi|graphql|rest)\b"),
    "server_info": re.compile(r"/server-status|/server-info|/phpinfo"),
}
TRAVERSAL_RE = re.compile(r"\.\.[/\\]", re.I)
WRAPPER_RE = re.compile(r"\b(?:php|data|expect|phar|zip|file)://", re.I)
RECON_SIGNALS = {"no_user_agent", "path_probe", "unlisted_path", "traversal",
                 "wrapper"}
# Headers never scanned: they carry nothing the client controls in a useful way.
SKIP_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
MAX_SCAN = 256 * 1024


def boundary_of(content_type: str) -> str | None:
    """Multipart boundary from a Content-Type header value."""
    match = BOUNDARY_RE.search(content_type or "")
    return (match.group(1) or match.group(2)) if match else None


def parse_multipart(body: bytes, boundary: str, max_parts: int = 20000) -> dict:
    """Bounded multipart statistics. Part contents are never kept, except a
    short prefix of the upload progress value."""
    delim = b"--" + boundary.encode("latin-1", "replace")
    out = {"parts": 0, "max_depth": 0, "filenames": [], "names_sample": [],
           "upload_progress_values": [], "phpsessid_field": False,
           "max_filename_len": 0, "probe_marker": False}
    pos = body.find(delim)
    while pos != -1 and out["parts"] < max_parts:
        start = pos + len(delim)
        if body[start:start + 2] == b"--":
            break
        if body[start:start + 2] == b"\r\n":
            start += 2
        hend = body.find(b"\r\n\r\n", start, start + 8192)
        if hend == -1:
            break
        headers = body[start:hend]
        nxt = body.find(delim, hend + 4)
        end = (nxt - 2) if nxt != -1 else len(body)
        out["parts"] += 1
        name_m = NAME_RE.search(headers)
        name = name_m.group(1).decode("latin-1") if name_m else ""
        out["max_depth"] = max(out["max_depth"], name.count("["))
        if len(out["names_sample"]) < 5:
            out["names_sample"].append(name[:120])
        if name == "PHPSESSID":
            out["phpsessid_field"] = True
        if name == "PHP_SESSION_UPLOAD_PROGRESS" and \
                len(out["upload_progress_values"]) < 3:
            out["upload_progress_values"].append(
                body[hend + 4:min(end, hend + 4 + 200)].decode("latin-1"))
        file_m = FILENAME_RE.search(headers)
        if file_m:
            raw = file_m.group(1)
            out["max_filename_len"] = max(out["max_filename_len"], len(raw))
            if PROBE_MARKER in raw:
                out["probe_marker"] = True
            if len(out["filenames"]) < 10:
                out["filenames"].append(raw[:200].decode("latin-1"))
        pos = nxt
    return out


def resolve_lookups(text: str) -> str:
    """Resolve Log4j style nested lookups so an obfuscated keyword becomes
    visible: ${x:-j}${y:-n}... becomes jn... Only the literal forms are
    resolved (default value, lower, upper). Environment, system and JNDI
    lookups are never evaluated. Pure text work, bounded in passes and size."""
    if "${" not in text:
        return text
    for _ in range(LOG4J_PASSES):
        out = LOOKUP_DEFAULT_RE.sub(r"\1", text)
        out = LOOKUP_CASE_RE.sub(
            lambda m: m.group(2).lower() if m.group(1).lower() == "lower"
            else m.group(2).upper(), out)
        if out == text:
            break
        text = out
    return text


def log4j_signals(*texts: str) -> list:
    """Signals for JNDI lookups, plain or obfuscated, in any text."""
    out = []
    raw_hit = resolved_hit = False
    for text in texts:
        if not text or "${" not in text:
            continue
        resolved = resolve_lookups(text)
        if re.search(r"\$\{jndi:", text, re.I):
            raw_hit = True
        if re.search(r"\$\{jndi:", resolved, re.I):
            resolved_hit = True
    if resolved_hit:
        out.append("log4j_jndi")
        if not raw_hit:
            out.append("log4j_obfuscated")
    return out


def decode(text: str, passes: int = 3) -> str:
    """Percent-decode up to a few times so double encoding does not hide a marker."""
    for _ in range(passes):
        out = urllib.parse.unquote(text)
        if out == text:
            break
        text = out
    return text


def path_signals(path: str, query: str, persona: str = "php") -> list:
    """Recon signals from the URL: path outside the persona page, known
    categories, traversal and URL wrappers."""
    out = []
    target = decode(path).lower().rstrip("/") or "/"
    if target not in ALLOWED_PATHS.get(persona, ALLOWED_PATHS["php"]):
        out.append("unlisted_path")
    for name, pattern in PATH_CATEGORIES.items():
        if pattern.search(target):
            out.append("path_cat:" + name)
    if any(sig.startswith("path_cat:") for sig in out):
        out.append("path_probe")
    raw = decode(path + "?" + query)
    if TRAVERSAL_RE.search(raw):
        out.append("traversal")
    if WRAPPER_RE.search(raw):
        out.append("wrapper")
    return out


HEADER_KEEP = 1500
MAX_FLAGGED = 6


def header_findings(headers: dict) -> dict:
    """Headers whose value carries code or injection syntax. Their values are
    scanned for IoCs too; the rest of the headers are left alone so that the
    info URL of a self-identified scanner is not reported as a payload URL.
    Values are scanned after resolving nested lookups, and a resolved copy is
    kept next to the raw value when they differ."""
    flagged, resolved, code_text = {}, {}, []
    code = inj = False
    for name, value in headers.items():
        if name in SKIP_HEADERS:
            continue
        raw = decode(value[:4000])
        text = resolve_lookups(raw)
        is_code = bool(CODE_RE.search(text))
        is_inj = bool(INJ_RE.search(text))
        if (is_code or is_inj) and len(flagged) < MAX_FLAGGED:
            flagged[name] = value[:HEADER_KEEP]
            if text != raw:
                resolved[name] = text[:HEADER_KEEP]
        if is_code:
            code_text.append(text)
        code, inj = code or is_code, inj or is_inj
    return {"flagged": flagged, "resolved": resolved, "code": code,
            "inj": inj, "code_text": " ".join(code_text)}


def body_has_injection(body: bytes) -> bool:
    """Injection syntax in the first 64 KiB of the body."""
    return bool(INJ_RE.search(body[:65536].decode("latin-1")))


def describe_client(family: str, user_agent: str) -> str:
    """Tool label that is never empty: the family, or what the user agent is."""
    if family != "none":
        return family
    if not user_agent:
        return "no_ua"
    if user_agent.lower().startswith("mozilla/"):
        return "browser_ua"
    return "custom_ua"


def tool_family(headers: dict, boundary: str | None, body: bytes) -> tuple:
    """(family, signals) from user agent, boundary prefix and body marker."""
    signals = []
    family = "none"
    ua = headers.get("user-agent", "")
    if not ua:
        signals.append("no_user_agent")
    ual = ua.lower()
    for needle, fam in UA_FAMILIES:
        if needle in ual:
            family = fam
            signals.append("ua_" + fam)
            break
    if boundary:
        bl = boundary.lower().lstrip("-")
        for prefix, fam in BOUNDARY_FAMILIES:
            if bl.startswith(prefix):
                signals.append("boundary_" + fam)
                if family == "none":
                    family = fam
                break
        if re.search(r"(.)\1{40,}", boundary):
            signals.append("boundary_repeated_char")
    if body and PROBE_MARKER in body[:2 * 1024 * 1024]:
        signals.append("probe_marker")
        if family == "none":
            family = "ikow_scanner"
    return family, signals


def extract_iocs(path: str, query: str, body: bytes,
                 header_text: str = "") -> dict:
    """URLs, IPv4 addresses and base64-embedded URLs found in the request.
    Nested Log4j lookups are resolved first; a JNDI callback is kept with its
    inner lookups (for example ${sys:java.version}) as one URL."""
    raw_text = decode(path + "?" + query) + " " + \
        body[:MAX_SCAN].decode("latin-1") + " " + header_text
    text = resolve_lookups(raw_text)
    urls = []
    ips = []

    def add_urls(blob):
        for m in JNDI_URL_RE.finditer(blob):
            if m.group(1) not in urls and len(urls) < 20:
                urls.append(m.group(1))
        for m in URL_RE.finditer(JNDI_URL_RE.sub(" ", blob)):
            if m.group(0) not in urls and len(urls) < 20:
                urls.append(m.group(0))

    add_urls(text)
    for token in B64_RE.findall(text)[:20]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4),
                                   validate=True)
        except (binascii.Error, ValueError):
            continue
        add_urls(raw[:4096].decode("latin-1"))
    for m in IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_global and str(ip) not in ips and len(ips) < 20:
            ips.append(str(ip))
    return {"urls": urls, "ips": ips,
            "code_marker": bool(CODE_RE.search(text) or
                                CODE_RE.search(text.replace("+", " "))),
            "sess_path": bool(SESS_PATH_RE.search(path + "?" + query))}


def php_stage(mp: dict | None, iocs: dict, family: str, signals: list,
              body_len: int, filenames_text: str, deviates: bool = False) -> str:
    """Highest stage reached on the PHP persona."""
    serialized = bool(SERIALIZED_RE.search(filenames_text))
    if iocs["code_marker"] or iocs["sess_path"] or serialized or iocs["urls"]:
        return "exploit"
    if mp:
        if body_len >= 1024 * 1024 or mp["max_depth"] >= 50 or \
                mp["parts"] >= 500:
            return "oom_probe"
        if mp["upload_progress_values"] and \
                (mp["phpsessid_field"] or mp["filenames"]):
            return "arm"
        if mp["upload_progress_values"]:
            return "probe"
    if "content_encoding_br" in signals:
        return "br_large" if body_len >= 1024 * 1024 else "br_probe"
    if family != "none" or RECON_SIGNALS & set(signals):
        return "recon"
    return "deviation" if deviates else "survey"


def node_stage(headers: dict, body_len: int, large: int, family: str,
               signals: list, iocs: dict | None = None,
               deviates: bool = False) -> str:
    """Highest stage reached on the Node persona."""
    if iocs and (iocs["code_marker"] or iocs["urls"] or iocs["sess_path"]):
        return "exploit"
    if BR_RE.search(headers.get("content-encoding", "")):
        return "br_large" if body_len >= large else "br_probe"
    if family != "none" or RECON_SIGNALS & set(signals):
        return "recon"
    return "deviation" if deviates else "survey"
