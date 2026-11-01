# PHNwn2Shell - installation

PHNwn2Shell is a passive, low-interaction sensor for PHP2Shell, Node2Shell and HTTP2Shell. It answers HTTP like an Apache/mod_php host (ports 80 and 443) and an Express host (port 3000), writes every request as one JSON line, and the Wazuh agent ships that file to the manager. The detection rules are in `rules/phnwn_rules.xml` (rule block 100220 - 100229).

It runs no shell and executes nothing it receives. It makes no outbound connections and downloads nothing. Run it on a dedicated host: a systemd sandbox is not a VM.

Files in this folder:

| File | Installed as |
|---|---|
| `__init__.py`, `__main__.py`, `analysis.py`, `server.py` | `/opt/phnwn2shell/phnwn2shell/` |
| `phnwn2shell.service` | `/etc/systemd/system/phnwn2shell.service` |

## Requirements

- Ubuntu 24.04 LTS (lab host: Ubuntu 24.04.5 LTS, Python 3.12.3)
- Python 3 standard library only, no pip packages
- `openssl` for the self-signed certificate
- Inbound access to TCP 80, 443 and 3000
- A Wazuh agent on the same host, registered to your manager

## 1. Install the sensor (sensor host, as root)

Run from the root of this repository.

```bash
id phnwn >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin phnwn

install -d -m 0755 /opt/phnwn2shell/phnwn2shell
install -m 0644 phnwn2shell/__init__.py phnwn2shell/__main__.py phnwn2shell/analysis.py phnwn2shell/server.py /opt/phnwn2shell/phnwn2shell/
chown -R root:root /opt/phnwn2shell

install -d -m 0750 -o phnwn -g phnwn /var/lib/phnwn2shell
```

## 2. TLS certificate (sensor host, as root)

A self-signed certificate is enough for a honeypot.

```bash
install -d -m 0750 -o root -g phnwn /etc/phnwn2shell
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=localhost" \
  -keyout /etc/phnwn2shell/key.pem -out /etc/phnwn2shell/cert.pem
chgrp phnwn /etc/phnwn2shell/*.pem
chmod 0640 /etc/phnwn2shell/*.pem
```

## 3. Configuration (sensor host, as root)

```bash
cat > /etc/phnwn2shell.env <<'EOT'
PHNWN_BIND=0.0.0.0
PHNWN_LISTEN=80:php,3000:node
PHNWN_TLS_LISTEN=443:php
PHNWN_TLS_CERT=/etc/phnwn2shell/cert.pem
PHNWN_TLS_KEY=/etc/phnwn2shell/key.pem
PHNWN_SENSOR=phnwn-01
EOT
```

`PHNWN_LISTEN` is a list of `port:persona` pairs, where the persona is `php` (Apache with mod_php) or `node` (Express). `PHNWN_SENSOR` is the name written into every event: use a different value on each sensor. The other variables read by `server.py` are optional: `PHNWN_DATA_DIR`, `PHNWN_PHP_VERSION`, `PHNWN_SERVER_HEADER`, `PHNWN_MAX_BODY`, `PHNWN_DISK_QUOTA_MB`, `PHNWN_MAX_CONCURRENCY`, `PHNWN_SOCKET_TIMEOUT`, `PHNWN_BR_LARGE_BODY` and `PHNWN_TRUST_XFF`.

## 4. Start the service (sensor host, as root)

```bash
install -m 0644 phnwn2shell/phnwn2shell.service /etc/systemd/system/phnwn2shell.service
systemctl daemon-reload
systemctl enable --now phnwn2shell
systemctl is-active phnwn2shell
```

The unit runs the sensor as the unprivileged user `phnwn` with only `CAP_NET_BIND_SERVICE`, a read-only file system except `/var/lib/phnwn2shell`, a syscall filter, `AF_INET` and `AF_INET6` sockets only, and memory, task and CPU limits.

Check that it listens and that it logs:

```bash
ss -ltn | grep -E ':(80|443|3000) '
curl -si http://127.0.0.1/ | head -n 5
tail -n 1 /var/lib/phnwn2shell/events.jsonl
```

## 5. Send the log to Wazuh (sensor host, as root)

Add this block to `/var/ossec/etc/ossec.conf` on the agent, then restart it:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/phnwn2shell/events.jsonl</location>
</localfile>
```

```bash
systemctl restart wazuh-agent
```

## 6. Install the rules (Wazuh manager, as root)

```bash
cp rules/phnwn_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/phnwn_rules.xml
chmod 660 /var/ossec/etc/rules/phnwn_rules.xml

# Syntax check - silent on success
/var/ossec/bin/wazuh-analysisd -t

systemctl restart wazuh-manager
```

If the manager already has custom rules, check that the IDs 100220 - 100229 are free before copying.

## Update and removal

To update, copy the four `.py` files again as in step 1 and run `systemctl restart phnwn2shell`. To remove:

```bash
systemctl disable --now phnwn2shell
rm -f /etc/systemd/system/phnwn2shell.service /etc/phnwn2shell.env
rm -rf /opt/phnwn2shell /etc/phnwn2shell
```

The events in `/var/lib/phnwn2shell` are not removed by these commands.
