# PHNwn2Shell - passive IoC sensor (HTTP honeypot) for PHP2Shell, Node2Shell and HTTP2Shell
#
# Purpose: log what scanners and exploit tools send to a decoy that answers like
# a PHP/Apache site (ports 80 and 443) or a Node.js/Express site (port 3000),
# and feed those events to Wazuh as one JSON line per request. The sensor never
# executes what it receives, makes no outbound connections and downloads nothing.
#
# This file: HTTP listeners (PHP and Node.js personas), event writer and data store.
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

"""PHNwn2Shell HTTP sensor.

One process, several listeners. Each listener has a persona:
  php  - Apache 2.4 with mod_php (PHP2Shell)
  node - Express (Node2Shell / HTTP2Shell, inbound direction)

Safety properties by construction:
  * no subprocess, eval, exec, dynamic import or shell emulation;
  * no outbound connections (no fetching, no enrichment, no notifiers);
  * no decompression of any kind (zlib, gzip, brotli are never imported);
  * request bytes are only stored as <sha256>.bin inside the data directory.
"""

import hashlib
import json
import os
import re
import ssl
import threading
import urllib.parse
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, analysis

KEEP_HEADERS = (
    "host", "user-agent", "content-type", "content-length", "content-encoding",
    "transfer-encoding", "accept", "accept-encoding", "connection", "cookie",
    "x-forwarded-for", "origin", "referer", "next-action",
)
# Field caps. Together they keep one event well under the 64 KiB line limit
# of the Wazuh analysis engine (see the worst case test).
PATH_CAP = 2048
QUERY_CAP = 2048
UA_CAP = 1500
HEADER_CAP = 512
# Public indicators of React Server Components (Flight) deserialization abuse.
FLIGHT_RE = re.compile(
    rb"__proto__:then|\"status\"\s*:\s*\"resolved_model\"|\$\d+:__proto__|"
    rb"\"_formData\"\s*:|\"_prefix\"\s*:")
PHP_PAGE = (
    b"<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
    b"<title>Example Logistics LLC</title></head>\n<body>"
    b"<h1>Example Logistics LLC</h1><p>Logistics that just works.</p>"
    b"</body>\n</html>\n"
)


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _listeners(spec: str) -> list:
    out = []
    for item in filter(None, (s.strip() for s in spec.split(","))):
        port, _, persona = item.partition(":")
        if persona not in ("php", "node"):
            raise ValueError(f"bad listener '{item}', use PORT:php or PORT:node")
        out.append((int(port), persona))
    return out


class Config:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """Settings from PHNWN_* environment variables."""

    def __init__(self):
        env = os.environ.get
        self.bind = env("PHNWN_BIND", "0.0.0.0")
        self.listen = _listeners(env("PHNWN_LISTEN", "8080:php,3000:node"))
        self.tls_listen = _listeners(env("PHNWN_TLS_LISTEN", ""))
        self.tls_cert = env("PHNWN_TLS_CERT", "")
        self.tls_key = env("PHNWN_TLS_KEY", "")
        self.data_dir = Path(env("PHNWN_DATA_DIR", "./data"))
        self.sensor = env("PHNWN_SENSOR", "phnwn2shell-01")
        self.php_version = env("PHNWN_PHP_VERSION", "8.3.6")
        self.server_header = env("PHNWN_SERVER_HEADER", "Apache/2.4.58 (Ubuntu)")
        self.max_body = _int("PHNWN_MAX_BODY", 32 * 1024 * 1024)
        self.quota = _int("PHNWN_DISK_QUOTA_MB", 2048) * 1024 * 1024
        self.max_concurrency = _int("PHNWN_MAX_CONCURRENCY", 32)
        self.socket_timeout = _int("PHNWN_SOCKET_TIMEOUT", 30)
        self.large_body = _int("PHNWN_BR_LARGE_BODY", 1024 * 1024)
        self.trust_xff = env("PHNWN_TRUST_XFF", "0") == "1"


class EventLog:  # pylint: disable=too-few-public-methods
    """Thread-safe JSON lines writer; reopens the file if it is rotated."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._fh = self._open()

    def _open(self):
        # long-lived handle, reopened on rotation
        return open(self.path, "a", encoding="utf-8", buffering=1)  # pylint: disable=consider-using-with

    def emit(self, action: str, sensor: str, **fields) -> dict:
        """Write one event and return it."""
        event = {
            "@timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "event": {"kind": "alert" if fields.pop("alert", False) else "event",
                      "module": "phnwn2shell",
                      "dataset": "phnwn2shell.events", "action": action},
            "observer": {"name": sensor, "type": "honeypot",
                         "version": __version__},
        }
        event.update(fields)
        line = json.dumps(event, ensure_ascii=False, default=str)
        with self._lock:
            if not self.path.exists():
                self._fh.close()
                self._fh = self._open()
            self._fh.write(line + "\n")
        return event


class Store:
    """Content-addressed body storage with a hard disk quota."""

    def __init__(self, directory: Path, quota: int):
        self.dir = directory
        self.quota = quota
        self._lock = threading.Lock()
        self.used = sum(p.stat().st_size for p in directory.glob("*.bin"))

    def put(self, sha: str, data: bytes) -> str | None:
        """Store as <sha>.bin (mode 0400); None when over quota."""
        path = self.dir / f"{sha}.bin"
        with self._lock:
            if path.exists():
                return str(path)
            if self.used + len(data) > self.quota:
                return None
            path.write_bytes(data)
            path.chmod(0o400)
            self.used += len(data)
        return str(path)


class Handler(BaseHTTPRequestHandler):  # pylint: disable=too-many-instance-attributes
    """Answers like the persona. Whatever the client sends is only recorded."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.cfg.socket_timeout)

    def _client(self) -> dict:
        ip, port = self.client_address[0], self.client_address[1]
        if self.server.cfg.trust_xff:
            xff = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if xff:
                ip = xff
        return {"ip": ip, "port": port}

    def _read_chunked(self, cap: int) -> tuple:
        data = bytearray()
        truncated = False
        while not truncated:
            line = self.rfile.readline(1024)
            try:
                size = int(line.split(b";")[0].strip() or b"x", 16)
            except ValueError:
                return bytes(data), True
            if size == 0:
                while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                    pass
                break
            remaining = size
            while remaining:
                chunk = self.rfile.read(min(remaining, 1 << 20))
                if not chunk:
                    return bytes(data), True
                remaining -= len(chunk)
                room = cap - len(data)
                if room > 0:
                    data += chunk[:room]
                if len(data) >= cap:
                    truncated = True
            self.rfile.readline(8)
        return bytes(data), truncated

    def _read_body(self) -> tuple:
        cap = self.server.cfg.max_body
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            data, truncated = self._read_chunked(cap)
            return data, truncated, None
        try:
            declared = max(int(self.headers.get("Content-Length") or 0), 0)
        except ValueError:
            declared = 0
        take = min(declared, cap)
        data = bytearray()
        while len(data) < take:
            chunk = self.rfile.read(min(1 << 20, take - len(data)))
            if not chunk:
                break
            data += chunk
        return bytes(data), declared > take or len(data) < take, declared

    def _send(self, code: int, payload: bytes, ctype: str, extra=()):
        persona = self.server.persona
        self.send_response_only(code)
        if persona == "php":
            self.send_header("Server", self.server.cfg.server_header)
            self.send_header("X-Powered-By", f"PHP/{self.server.cfg.php_version}")
        else:
            self.send_header("X-Powered-By", "Express")
        for key, value in extra:
            self.send_header(key, value)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Date", formatdate(usegmt=True))
        self.send_header("Connection",
                         "close" if self.close_connection else "keep-alive")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _respond(self, path: str, stage: str, has_progress: bool):
        if self.server.persona == "php":
            if stage == "oom_probe":
                # what an unpatched worker looks like to a scanner: empty 500
                self.close_connection = True
                self._send(500, b"", "text/html; charset=UTF-8")
            elif path.lower().endswith((".php", "/")):
                extra = []
                if has_progress:
                    sid = hashlib.md5(os.urandom(16)).hexdigest()  # nosec - cookie value only
                    extra.append(("Set-Cookie", f"PHPSESSID={sid}; path=/"))
                self._send(200, PHP_PAGE, "text/html; charset=UTF-8", extra)
            else:
                msg = ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                       "<html><head><title>404 Not Found</title></head>"
                       "<body><h1>Not Found</h1><p>The requested URL was not "
                       "found on this server.</p></body></html>\n")
                self._send(404, msg.encode(), "text/html; charset=iso-8859-1")
        else:
            if self.command in ("POST", "PUT", "PATCH"):
                self._send(200, b'{"received":true}',
                           "application/json; charset=utf-8")
            elif path == "/":
                self._send(200, b'{"status":"ok","service":"api"}',
                           "application/json; charset=utf-8")
            else:
                msg = f"Cannot {self.command} {path}"
                self._send(404, ("<!DOCTYPE html>\n<html lang=\"en\">\n<head>"
                                 "<meta charset=\"utf-8\"><title>Error</title>"
                                 "</head>\n<body>\n<pre>" + msg +
                                 "</pre>\n</body>\n</html>\n").encode(),
                           "text/html; charset=utf-8")

    def _analyse(self, body: bytes, hdrs: dict, path: str, query: str) -> dict:
        cfg = self.server.cfg
        boundary = analysis.boundary_of(hdrs.get("content-type", ""))
        mp = None
        if boundary and "multipart/" in hdrs.get("content-type", "").lower() \
                and body:
            mp = analysis.parse_multipart(body, boundary)
        family, signals = analysis.tool_family(hdrs, boundary, body)
        hf = analysis.header_findings(hdrs)
        iocs = analysis.extract_iocs(path, query, body, hf["code_text"])
        iocs["code_marker"] = iocs["code_marker"] or hf["code"]
        persona = self.server.persona
        signals += analysis.path_signals(path, query, persona)
        if hf["inj"] or analysis.INJ_RE.search(
                analysis.decode(path + "?" + query)) or \
                analysis.body_has_injection(body):
            signals.append("inj_syntax")
        signals += analysis.log4j_signals(
            analysis.decode(path + "?" + query),
            body[:analysis.MAX_SCAN].decode("latin-1"), *hdrs.values())
        if "next-action" in hdrs:
            signals.append("next_action_header")
        if body and FLIGHT_RE.search(body[:65536]):
            signals.append("rsc_flight_body")
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            signals.append("chunked_body")
        if analysis.BR_RE.search(hdrs.get("content-encoding", "")):
            signals.append("content_encoding_br")
        deviates = (self.command not in ("GET", "HEAD") or bool(body) or
                    bool(query) or "inj_syntax" in signals or
                    "chunked_body" in signals or
                    "content_encoding_br" in signals)
        if persona == "php":
            fn_text = " ".join((mp or {}).get("filenames", []) +
                               (mp or {}).get("upload_progress_values", []))
            stage = analysis.php_stage(mp, iocs, family, signals, len(body),
                                       fn_text, deviates)
        else:
            stage = analysis.node_stage(hdrs, len(body), cfg.large_body,
                                        family, signals, iocs, deviates)
        return {"mp": mp, "boundary": boundary, "family": family,
                "signals": signals, "iocs": iocs, "stage": stage,
                "flagged": hf["flagged"], "resolved": hf["resolved"]}

    def _handle(self):
        cfg = self.server.cfg
        if not self.server.slots.acquire(blocking=False):
            self.close_connection = True
            return
        try:
            body, truncated, declared = self._read_body()
            if truncated:
                self.close_connection = True
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            split = urllib.parse.urlsplit(self.path)
            path = split.path or "/"
            client = self._client()
            sha = hashlib.sha256(body).hexdigest() if body else None
            stored = self.server.store.put(sha, body) if body else None
            res = self._analyse(body, hdrs, path, split.query)
            mp, iocs = res["mp"], res["iocs"]
            fields = {
                "alert": res["stage"] not in ("survey", "deviation"),
                "srcip": client["ip"], "source": client,
                "url": {"path": path[:PATH_CAP], "path_len": len(path),
                        "query": split.query[:QUERY_CAP],
                        "query_len": len(split.query)},
                "http": {"request": {
                    "method": self.command,
                    "version": self.request_version,
                    "headers": {k: v[:HEADER_CAP] for k, v in hdrs.items()
                                if k in KEEP_HEADERS},
                    "header_order": ",".join(self.headers.keys())[:400],
                    "flagged_headers": res["flagged"],
                    "flagged_resolved": res["resolved"],
                    "body": {"bytes": len(body), "declared": declared,
                             "truncated": truncated}}},
                "user_agent": {"original": hdrs.get("user-agent", "")[:UA_CAP],
                               "length": len(hdrs.get("user-agent", ""))},
                "phnwn": {"persona": self.server.persona,
                          "listener_port": self.server.server_address[1],
                          "tls": self.server.tls, "stage": res["stage"],
                          "tool": analysis.describe_client(
                              res["family"], hdrs.get("user-agent", "")),
                          "signals": ",".join(res["signals"])},
                "ioc": {"url_count": len(iocs["urls"]),
                        "ip_count": len(iocs["ips"]),
                        "urls_csv": ",".join(iocs["urls"]),
                        "ips_csv": ",".join(iocs["ips"]),
                        "code_marker": iocs["code_marker"],
                        "sess_path": iocs["sess_path"]},
            }
            if getattr(self.connection, "_phnwn_tls", None):
                fields["tls"] = self.connection._phnwn_tls  # pylint: disable=protected-access
            if mp:
                fields["multipart"] = {
                    "boundary": (res["boundary"] or "")[:120],
                    "parts": mp["parts"], "max_depth": mp["max_depth"],
                    "phpsessid_field": mp["phpsessid_field"],
                    "max_filename_len": mp["max_filename_len"],
                    "filenames_csv": ",".join(mp["filenames"])[:600],
                    "names_sample": ",".join(mp["names_sample"])[:400],
                    "upload_progress_values": ",".join(
                        mp["upload_progress_values"])[:400]}
            if body:
                fields["file"] = {"sha256": sha, "size": len(body),
                                  "path": stored, "stored": stored is not None}
            self.server.log.emit("http_request", cfg.sensor, **fields)
            self._respond(path, res["stage"],
                          bool(mp and mp["upload_progress_values"]))
        finally:
            self.server.slots.release()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle
    do_OPTIONS = _handle


class Listener(ThreadingHTTPServer):
    """One persona on one port, sharing log, store and concurrency cap."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(self, cfg, port, persona, shared, tls_ctx=None):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self.cfg = cfg
        self.persona = persona
        self.log, self.store, self.slots = shared
        self.tls_ctx = tls_ctx
        self.tls = tls_ctx is not None
        super().__init__((cfg.bind, port), Handler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_ctx is None:
            return sock, addr
        wrapped = self.tls_ctx.wrap_socket(
            sock, server_side=True, do_handshake_on_connect=False)
        wrapped.settimeout(self.cfg.socket_timeout)
        return wrapped, addr

    def process_request_thread(self, request, client_address):
        if self.tls_ctx is not None:
            try:
                request.do_handshake()
                request._phnwn_tls = {  # pylint: disable=protected-access
                    "version": request.version(),
                    "cipher": (request.cipher() or ("",))[0],
                    "sni": getattr(request, "_phnwn_sni", None)}
            except (ssl.SSLError, OSError):
                self.shutdown_request(request)
                return
        super().process_request_thread(request, client_address)


def _tls_context(cfg):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)

    def sni(sock, name, _ctx):
        sock._phnwn_sni = name  # pylint: disable=protected-access

    ctx.set_servername_callback(sni)
    return ctx


def build(cfg: Config) -> list:
    """Create all listeners (not yet serving)."""
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    (cfg.data_dir / "bodies").mkdir(exist_ok=True)
    shared = (EventLog(cfg.data_dir / "events.jsonl"),
              Store(cfg.data_dir / "bodies", cfg.quota),
              threading.BoundedSemaphore(cfg.max_concurrency))
    listeners = [Listener(cfg, port, persona, shared)
                 for port, persona in cfg.listen]
    if cfg.tls_listen:
        ctx = _tls_context(cfg)
        listeners += [Listener(cfg, port, persona, shared, ctx)
                      for port, persona in cfg.tls_listen]
    return listeners


def main():
    """Run all listeners until interrupted."""
    cfg = Config()
    listeners = build(cfg)
    listeners[0].log.emit(
        "sensor_started", cfg.sensor,
        listen=",".join(f"{ls.server_address[1]}:{ls.persona}"
                        f"{':tls' if ls.tls else ''}" for ls in listeners))
    threads = [threading.Thread(target=ls.serve_forever, daemon=True)
               for ls in listeners[1:]]
    for thread in threads:
        thread.start()
    try:
        listeners[0].serve_forever()
    except KeyboardInterrupt:
        pass
