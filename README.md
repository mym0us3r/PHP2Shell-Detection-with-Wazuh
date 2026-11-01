# PHP2Shell Detection with Wazuh 4.14.8 (4.14.x series) - CVE-2026-109618 and CVE-2026-109619

> **Detection engineering for the PHP2Shell memory-safety flaws · Apache mod_php on Linux · lab-validated on Ubuntu 24.04 LTS**

> **Update (November 1, 2026 - 12:00, UTC-3):** v1.2 adds a post-exploitation layer. Rules 100140 and 100141 flag commands run by the web server account (auditd), and rules 100142, 100143 and 100144 flag PHP files created, modified and deleted under `/var/www` (FIM). All five rules were validated with real events in the Wazuh Dashboard.
>
> Prints (in `docs/`):
>
> - `rules_100140_100141.png`
> - `rules_100142_100143_100144.png`

![wazuh: 4.14.x series](https://img.shields.io/badge/wazuh-4.14.x%20series-005571) ![validated on: 4.14.8](https://img.shields.io/badge/validated%20on-4.14.8-005571) ![status: lab-validated](https://img.shields.io/badge/status-lab--validated-4c1) ![platform: Linux](https://img.shields.io/badge/platform-Linux-555) ![PHP2Shell: CVE-2026-109618 and 109619](https://img.shields.io/badge/PHP2Shell-CVE--2026--109618%20and%20109619-d73a49) ![Vuln: PHP2Shell](https://img.shields.io/badge/family-PHP2Shell-d73a49) ![Vuln: HTTP2Shell](https://img.shields.io/badge/family-HTTP2Shell-d73a49) ![Vuln: Node2Shell](https://img.shields.io/badge/family-Node2Shell-d73a49) ![sensor: PHNwn2Shell](https://img.shields.io/badge/sensor-PHNwn2Shell-6f42c1) ![type: HoneyPot](https://img.shields.io/badge/type-HoneyPot-6f42c1) ![custom rules: 11](https://img.shields.io/badge/custom%20rules-11-4c1) ![decoders: 3](https://img.shields.io/badge/decoders-3-4c1) ![SCA checks: 5](https://img.shields.io/badge/SCA%20checks-5-4c1) ![telemetry: auditd](https://img.shields.io/badge/telemetry-auditd-fe7d37) ![telemetry: FIM](https://img.shields.io/badge/telemetry-FIM-fe7d37) ![telemetry: Apache logs](https://img.shields.io/badge/telemetry-Apache%20logs-fe7d37) ![CVSS: v4 9.2](https://img.shields.io/badge/CVSS-v4%209.2-d73a49) ![MITRE: T1190](https://img.shields.io/badge/MITRE-T1190-d73a49) ![MITRE: T1499](https://img.shields.io/badge/MITRE-T1499-d73a49) ![MITRE: T1005](https://img.shields.io/badge/MITRE-T1005-d73a49) ![MITRE: T1059](https://img.shields.io/badge/MITRE-T1059-d73a49) ![MITRE: T1505](https://img.shields.io/badge/MITRE-T1505-d73a49) ![MITRE: T1070](https://img.shields.io/badge/MITRE-T1070-d73a49)  

---

## What is PHP2Shell?

PHP2Shell is a family of memory-safety bugs in the PHP engine. A fatal error, most usefully an out-of-memory fatal at `memory_limit`, interrupts a non-atomic internal operation and leaves state behind that later code trusts. The flaws are remote and unauthenticated, do not depend on a bug in the application, and reach back to PHP 5.4 according to the researchers.

Two CVEs describe the issues, titled as in the PHP security advisory:

- **CVE-2026-109618, RCE via OOM corruption**: out-of-memory handling can interrupt PHP while internal request data is only partially initialized, and request cleanup may then treat the invalid data as valid.
- **CVE-2026-109619, RCE via stale global state**: request-owned internal state can survive after its backing memory has been freed, and a later request handled by the same worker may use that stale state before normal initialization resets it.

Wiz Research also describes a remote process-memory disclosure in which reclaimed heap contents are URL-encoded into a `PHPSESSID` response cookie. The advisory lists its interim measures under each CVE separately, and the rules in this repository treat the observable symptoms as consistent with both CVEs.

Researchers demonstrated unauthenticated RCE against WordPress, Drupal and Joomla.

Because the exploit runs below the application layer, application logs show little. The Wiz advisory lists the observable signals this repository detects: multipart requests followed by memory-limit errors, repeated HTTP 500 responses, malformed or oversized `PHPSESSID` response cookies, and PHP worker churn.

> Disclosed by Wiz Research (Sagi Tzadik, Shir Tamari, Nir Ohfeld, Tomer Schwartz), with a technical write-up by Calif. Fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35.

---

## Official References

| Resource | Link |
|---|---|
| PHP security advisory (2026-10-21) | https://www.php.net/archive/2026.php#2026-10-21-5 |
| PHP pre-announcement with the CVSS score (2026-10-20) | https://www.php.net/archive/2026.php#2026-10-20-1 |
| Wiz Research write-up | https://www.wiz.io/blog/php2shell-php-rce |
| Calif technical write-up | https://calif.io/php2shell/ |
| Wazuh rules syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html |
| Wazuh decoders syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html |
| Wazuh custom SCA policies | https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html |
| MITRE ATT&CK T1190 | https://attack.mitre.org/techniques/T1190/ |

---

## Why a Dedicated Detection Layer

An unpatched PHP engine cannot be told apart from a patched one by looking at `php -v` on distributions that backport the fix. On Ubuntu 24.04 the package `8.3.6-0ubuntu0.24.04.13` contains the fix while `php -v` still reports 8.3.6. Detection therefore has two independent layers:

```
Layer 1 - Behavior (rules)   : OOM fatals, repeated 500s, worker churn,
                               chunked multipart, anomalous PHPSESSID cookie
Layer 2 - Exposure (SCA)     : package revision with the backport,
                               interim mitigations from the PHP advisory
```

The rules detect the observable pre-conditions and symptoms described in the official sources. A single event does not prove exploitation, and the rule descriptions say "consistent with" on purpose.

---

## What Changed in v1.2

- **A third layer.** Layers 1 and 2 above are unchanged. v1.2 adds a post-exploitation layer: what happens on the host after a request succeeds.
- **auditd.** New `auditd/php2shell.rules` records every `execve` made by the Apache account (`euid=33`, key `php2shell_exec`). Rule 100140 (level 8) flags any process started by that account. Rule 100141 (level 12) is the high-confidence subset: a shell, interpreter or download tool. The key is not in the native `audit-keys` list, so native rule 80792 does not also fire.
- **FIM.** Rule 100142 (level 10) flags a new PHP-executable file (`.php`, `.php[0-9]`, `.phtml`, `.phar`, `.pht`, `.phps`) under `/var/www`, rule 100143 (level 8) flags a modified one, and rule 100144 (level 6) flags a deleted one. They inherit from the native FIM rules 554, 550 and 553.
- **Rule IDs.** The new rules stay inside this repository's block (100100 to 100199). Rules 100100 to 100131, the decoder and the SCA policy are unchanged.
- **References.** The header of `php2shell_rules.xml` now lists the Wazuh documentation for system call monitoring and file integrity monitoring.
- **Validation.** Rules 100140 and 100141 were tested with `wazuh-logtest` and with real auditd events. Rules 100142, 100143 and 100144 were tested with a real file created, modified and deleted under `/var/www/html`. The evidence is in the Validation and Validation Evidence (v1.2) sections.

---

## What Changed in v1.1

- **CVE attribution.** Rule 100131 and the README now follow the titles in the PHP advisory and name both CVEs.
- **No cookies in alerts.** Rules 100130 and 100131 use `no_full_log`, and the decoder no longer extracts the `Set-Cookie` header into a field. Rule 100131 matches the raw log line inside the analysis engine, so the cookie values are never stored in the alert. A sibling decoder stores only the first 8 characters of a `PHPSESSID` cookie in `data.phpsessid_prefix`, enough to see the shape of an anomalous value.
- **`same_srcip`.** Rules 100101 and 100120 use `same_srcip`.
- **SCA effective values.** Checks 109601 to 109604 pass when the installed package carries the vendor backport, or when the interim mitigation is effective. The effective value is computed by the PHP CLI started with the Apache `php.ini` and the Apache `conf.d` scan directory, and read with `ini_get()`, so every drop-in is applied in the order PHP loads them. A patched host is no longer penalized for interim mitigations it does not need.
- **SCA check 109604.** New check that searches `/etc/apache2` and the `.htaccess` files under `/var/www` for `php_value`, `php_admin_value`, `php_flag` and `php_admin_flag` lines that undo a mitigation. Commented lines are ignored, and `php_admin_value memory_limit -1`, the setting the advisory recommends, is not flagged.

---

## Exploit Chain

```
Step 1: multipart POST          chunked or lengthless body bypasses post_max_size
Step 2: filename="" parts       nested empty-filename parts exhaust memory_limit
Step 3: fatal error     [!]     TRIGGER - allocation fails at a chosen point
Step 4: stale state             cleanup still runs in mod_php, pointers reference freed heap
Step 5: next multipart request  freed heap is URL-encoded into the PHPSESSID cookie
Step 6: RCE                     unauthenticated code execution (WordPress, Drupal, Joomla)
```

![PHP2Shell exploit chain](docs/exploit_chain_timeline.png)

`post_max_size` is compared with the declared `Content-Length`, not with the bytes actually read, so chunked HTTP/1.1 and lengthless HTTP/2 multipart requests bypass it. On mod_php the request cleanup still runs after a startup fatal, which is why mod_php carries the highest risk. On PHP-FPM a startup failure exits the worker, and exploitation needs a post-startup decoding operation.

---

## Repository Structure

```
PHP2Shell-Detection-with-Wazuh/
│
├── SECURITY.md                              # Vulnerability reporting policy
│
├── rules/
│   └── php2shell_rules.xml                  # 11 Wazuh rules (100100-100144)
│
├── decoders/
│   └── php2shell_decoders.xml               # parent decoder and two sibling field decoders for the php2shell access log
│
├── apache/
│   └── php2shell-logformat.conf             # LogFormat and CustomLog for Apache 2.4
│
├── auditd/
│   └── php2shell.rules                      # execve audit rules for the Apache account (key php2shell_exec)
│
├── sca/
│   └── php2shell_cve_2026_109618_109619.yml # SCA policy - Ubuntu 24.04, PHP 8.3, mod_php
│
└── docs/
    ├── exploit_chain_timeline.png           # Exploit chain diagram
    ├── rule_100130_v11.png                  # Rule 100130, v1.1 alert (no full_log, no set_cookie)
    ├── rule_100131_v11.png                  # Rule 100131, v1.1 alert (no full_log, no set_cookie)
    ├── rule_100131-rev2.png                 # Rule 100131 with data.phpsessid_prefix (sibling decoder)
    ├── rules_100101_100120_v11.png          # Rules 100101 and 100120 with same_srcip
    ├── rules_100100_100101.png              # Rules 100100 and 100101, OOM fatals
    ├── sca_policy.png                       # SCA v1.0, unpatched endpoint (25%)
    ├── sca_policy_pos_up.png                # SCA v1.0, patched endpoint (50%)
    ├── sca_policy_revision.png              # SCA v1.1 final commands, patched endpoint (100%)
    ├── sca_policy_revision-2_score80.png    # SCA v1.1 final commands, mitigations through conf.d (80%)
    ├── sca_policy_revision-2_score20.png    # SCA v1.1 final commands, no mitigation and Apache override (20%)
    ├── sca_events.png                       # SCA events indexed in Discover (v1.0)
    ├── rules_100140_100141.png              # Rules 100140 and 100141, commands run by the web server account
    └── rules_100142_100143_100144.png       # Rules 100142, 100143 and 100144, PHP file created, modified and deleted
```

---

## Detection Architecture

### Rule Chain

| Rule | Parent | Signal | Level | Evidence |
|---|---|---|---|---|
| **100100** | 30301 | PHP `Allowed memory size ... exhausted` fatal in the Apache error log | 6 | Logtest and Discover |
| **100101** | 100100, `same_srcip` | 6 OOM fatals in 120 s from one IP | 10 | Logtest and Discover |
| **100110** | 30304, frequency | 4 Apache worker segmentation faults in 120 s | 13 | Logtest only |
| **100120** | 31122, `same_srcip` | 5 HTTP 500 responses in 60 s from one IP | 8 | Logtest and Discover |
| **100130** | php2shell-accesslog | Multipart request with `Transfer-Encoding: chunked` | 7 | Logtest and Discover |
| **100131** | php2shell-accesslog | `PHPSESSID` response cookie with `%XX` bytes or 64+ characters | 10 | Logtest and Discover |
| **100140** | 80700, key `php2shell_exec` | Any process executed by the web server account | 8 | Logtest and Discover |
| **100141** | 100140 | Web server account started a shell, interpreter or download tool | 12 | Logtest and Discover |
| **100142** | 554 | New PHP-executable file under `/var/www` | 10 | Discover |
| **100143** | 550 | Modified PHP-executable file under `/var/www` | 8 | Discover |
| **100144** | 553 | Deleted PHP-executable file under `/var/www` | 6 | Discover |

> **Engineering notes from validation on Wazuh 4.14.8**
>
> - The native PHP fatal chain (31402, 31405, 31420) does not match the Apache 2.4 error log format. In `wazuh-logtest` the event stops at rule 30301, so rule 100100 inherits from 30301 and matches the message itself.
> - Native Apache 2.4 segfault events end at rule 30304, not 30104. Frequency rules count only events whose final matched rule is the referenced SID, so 100110 uses 30304.
> - Access log events with status 500 end at rule 31122, so 100120 uses 31122 and not 31120.
> - The native `web-accesslog` decoder has a prematch that accepts extra tokens before the bracketed timestamp, so any combined-style prefix is claimed by it. The `php2shell` format is key=value without brackets, which the native decoder does not match.
> - Rules 100130 and 100131 use `no_full_log`. Rule 100131 matches the raw log line with a PCRE2 `regex`, which still works when `full_log` is omitted from the alert.

### Post-exploitation rules (v1.2)

The rules above watch the request and the engine. These five rules watch what happens on the host after a request succeeds: a process started by the web server account, or a PHP file that appears, changes or disappears in the web root. They do not depend on Apache logs.

**Rule 100140 - any process executed by the web server account (level 8, T1059).** The auditd rules in `auditd/php2shell.rules` record every `execve` made with `euid=33` under the key `php2shell_exec`. Rule 100140 inherits from native rule 80700 (auditd, messages grouped) and matches that key. A PHP process rarely starts other programs, so each hit is worth a look, but legitimate helpers such as a mail transfer agent used by `mail()` also raise it. Treat it as a hunting signal. The key is not in the native `audit-keys` list, so native rule 80792 does not fire for these events and there is no duplicate alert.

**Rule 100141 - shell, interpreter or download tool started by the web server account (level 12, T1059.004).** It is a child of 100140 that matches the executable path: `sh`, `bash`, `dash`, `ash`, `zsh`, `busybox`, `python`, `perl`, `php`, `nc`, `ncat`, `netcat`, `curl` and `wget`, in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and the `local` variants of these. These are the programs an attacker reaches for after code execution, so this is the rule to notify on. The alert description carries the executable, for example `/usr/bin/dash`.

**Rule 100142 - new PHP-executable file in the web root (level 10, T1505.003).** It inherits from native FIM rule 554 (file added) and matches paths under `/var/www` that end in `.php`, `.php[0-9]`, `.phtml`, `.phar`, `.pht` or `.phps`. A web shell dropped after exploitation lands here. Deployments also create PHP files, so ignore your release directories in `<syscheck>` or override the level in a local rule.

**Rule 100143 - modified PHP-executable file in the web root (level 8, T1505.003).** It inherits from native FIM rule 550 (checksum changed) with the same path match. It catches code implanted into an existing script. Updates of the application also modify PHP files.

**Rule 100144 - deleted PHP-executable file in the web root (level 6, T1070.004).** It inherits from native FIM rule 553 (file deleted) with the same path match. Removing a dropped file is the indicator removal technique, so a 100144 on the same path as an earlier 100142 is the sequence to look for. The level is low on purpose because releases and plugin updates also delete PHP files.

### Decoder

The `php2shell-accesslog` decoder and its child extract `srcip`, `protocol` (method), `url`, `id` (status), `content_type`, `transfer_encoding` and `content_length` from the custom access log line. The `Set-Cookie` header is intentionally not extracted. A sibling decoder, which Wazuh evaluates in parallel because it has the same name and parent, stores only the first 8 characters of a `PHPSESSID` response cookie in `phpsessid_prefix`. The two child decoders must stay adjacent and keep the same name.

---

## Deployment

### Step 1 - Add the Apache log format (endpoint)

Add the two lines from `apache/php2shell-logformat.conf` inside the VirtualHost you want to monitor, then validate and reload:

```bash
apachectl configtest && systemctl reload apache2
chown root:adm /var/log/apache2/php2shell_access.log && chmod 640 /var/log/apache2/php2shell_access.log
```

### Step 2 - Collect the logs (endpoint `ossec.conf`)

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/php2shell_access.log</location>
</localfile>
```

The first two feed the native Apache rules that rules 100100, 100110 and 100120 inherit from. The third feeds the decoder for rules 100130 and 100131.

### Step 3 - Deploy decoder and rules (manager)

```bash
cp decoders/php2shell_decoders.xml /var/ossec/etc/decoders/
cp rules/php2shell_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/php2shell_decoders.xml /var/ossec/etc/rules/php2shell_rules.xml
chmod 660 /var/ossec/etc/decoders/php2shell_decoders.xml /var/ossec/etc/rules/php2shell_rules.xml

# Syntax check - silent on success
/var/ossec/bin/wazuh-analysisd -t

systemctl restart wazuh-manager
```

`wazuh-logtest` reads the running `wazuh-analysisd`, so the manager restart is required before testing new rules or decoders.

### Step 4 - Deploy the SCA policy (endpoint)

```bash
mkdir -p /var/ossec/etc/custom-sca
cp sca/php2shell_cve_2026_109618_109619.yml /var/ossec/etc/custom-sca/
chown root:wazuh /var/ossec/etc/custom-sca/php2shell_cve_2026_109618_109619.yml
chmod 640 /var/ossec/etc/custom-sca/php2shell_cve_2026_109618_109619.yml
```

Register it inside the `<sca>` block of the endpoint `ossec.conf` and restart the agent:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <policies>
    <policy>/var/ossec/etc/custom-sca/php2shell_cve_2026_109618_109619.yml</policy>
  </policies>
</sca>
```

```bash
systemctl restart wazuh-agent
```

Checks 109601 to 109603 run the PHP CLI binary `php8.3` with the Apache `php.ini` and `conf.d`, so the `php8.3-cli` package must be installed on the endpoint. The policy was tested configured in the agent's local `ossec.conf`, where `sca.remote_commands` is not required for the command rules (`c:`) it uses. Delivery through centralized configuration (`agent.conf`) was not tested.

### Step 5 - Collect post-exploitation telemetry (endpoint)

Install and start auditd (Debian and Ubuntu), then install the audit rules, load them and confirm the key is active:

```bash
apt install -y auditd audispd-plugins
systemctl enable --now auditd
cp auditd/php2shell.rules /etc/audit/rules.d/php2shell.rules
augenrules --load
auditctl -l | grep php2shell_exec
```

`euid=33` is `www-data` on Debian and Ubuntu. Confirm it with `id -u www-data`, and use the Apache account UID of your distribution otherwise. Add the audit log and the web root to the endpoint `ossec.conf`:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<syscheck>
  <directories realtime="yes" check_all="yes">/var/www/html</directories>
</syscheck>
```

If the sites live in other directories under `/var/www`, add each one as another `<directories>` entry: the rules match any PHP-executable path under `/var/www`. If a `<syscheck>` block already exists in the file, add only the `<directories>` line to it. Restart the agent:

```bash
systemctl restart wazuh-agent
```

Rules 100140 and 100141 need `auditd` running on the endpoint. Web applications that deploy by writing or removing PHP files will raise 100142, 100143 and 100144, so exclude release directories with an `<ignore>` entry in `<syscheck>` or override the rule level in a local rule.

---

## Validation

### Decoder and rules by logtest (manager)

```bash
cat <<'EOF' | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E '^\s+(name|srcip|url|transfer_encoding|id|level|phpsessid_prefix):|Alert to be generated|full event'
php2shell ip=127.0.0.1 ts="2026-10-22T11:45:00-0300" req="POST / HTTP/1.1" status=200 bytes=531 ref="-" ua="curl/8.5.0" ct="multipart/form-data; boundary=------------------------abc" te="chunked" cl="-" sc="-"
php2shell ip=127.0.0.1 ts="2026-10-22T11:45:00-0300" req="GET /cookie_test.php HTTP/1.1" status=200 bytes=531 ref="-" ua="curl/8.5.0" ct="-" te="-" cl="-" sc="PHPSESSID=a%00b%FF%41%7F%7F; path=/"
php2shell ip=10.0.0.9 ts="2026-10-22T11:45:00-0300" req="GET /x.php HTTP/1.1" status=200 bytes=531 ref="-" ua="curl/8.5.0" ct="-" te="-" cl="-" sc="PHPSESSID=abcdefghijklmnopqrstuvwxyz012345; path=/"
php2shell ip=10.0.0.9 ts="2026-10-22T11:45:00-0300" req="GET /y.php HTTP/1.1" status=200 bytes=531 ref="-" ua="curl/8.5.0" ct="-" te="-" cl="-" sc="foo=a%00b, PHPSESSID=abc123"
EOF
```

Observed result: line 1 fires 100130 (level 7) and line 2 fires 100131 (level 10) with `phpsessid_prefix: 'a%00b%FF'`. Line 3, a normal 32-character session ID, and line 4, a `%XX` value in a different cookie with a normal `PHPSESSID`, fire nothing. No decoded field holds a full cookie.

### Real events on the lab endpoint

These steps generate events with benign requests. They reproduce the observable symptoms, not an exploit.

```bash
# Rule 100130 - multipart request with chunked Transfer-Encoding
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'Transfer-Encoding: chunked' -F 'a=b' http://localhost/
```

```php
<?php
// Lab test: benign trigger that emits a percent-encoded PHPSESSID response cookie.
setcookie('PHPSESSID', "a\x00b\xffA\x7f");
```

```bash
# Rule 100131 - save the script above as /var/www/html/cookie_test.php
curl -si http://localhost/cookie_test.php | grep -i '^set-cookie'
```

```php
<?php
// Lab test: benign memory_limit exhaustion (lab only, never on a production host).
$a = [];
while (true) { $a[] = str_repeat('A', 1048576); }
```

```bash
# Rules 100100, 100101 and 100120 - save the script above as /var/www/html/oom_test.php
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w '%{http_code} ' http://localhost/oom_test.php; done; echo
```

### auditd rules by logtest (manager, v1.2)

The three lines below are auditd records written in the format of the decoder example in the Wazuh ruleset. Run each one on the manager:

```bash
echo 'type=SYSCALL msg=audit(1762005000.123:9001): arch=c000003e syscall=59 success=yes exit=0 a0=55d0c8a0 a1=55d0c8c0 a2=55d0c8e0 a3=7ffd1a2b3c4d items=2 ppid=1234 pid=1240 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="dash" exe="/usr/bin/dash" key="php2shell_exec"' | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E 'name:|audit\.(key|exe|euid)|id:|level:|description:|Alert to be generated|\*\*Phase'

echo 'type=SYSCALL msg=audit(1762005001.456:9002): arch=c000003e syscall=59 success=yes exit=0 a0=55d0c8a0 a1=55d0c8c0 a2=55d0c8e0 a3=7ffd1a2b3c4d items=2 ppid=1240 pid=1241 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="id" exe="/usr/bin/id" key="php2shell_exec"' | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E 'name:|audit\.(key|exe|euid)|id:|level:|description:|Alert to be generated|\*\*Phase'

echo 'type=SYSCALL msg=audit(1762005002.789:9003): arch=c000003e syscall=59 success=yes exit=0 a0=55d0c8a0 a1=55d0c8c0 a2=55d0c8e0 a3=7ffd1a2b3c4d items=2 ppid=1240 pid=1242 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="id" exe="/usr/bin/id" key="audit-wazuh-c"' | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E 'audit\.(key|exe)|id:|level:|description:|Alert to be generated|\*\*Phase'
```

Observed result: the decoder is `auditd` and the fields `audit.key`, `audit.exe` and `audit.euid` are extracted. Line 1 (`/usr/bin/dash`) fires rule 100141 (level 12, `T1059.004`). Line 2 (`/usr/bin/id`) fires rule 100140 (level 8, `T1059`) and does not reach 100141. Line 3 uses the native key `audit-wazuh-c`: only native rule 80792 fires, and rules 100140 and 100141 stay silent.

### auditd and FIM rules on real events (v1.2)

Run these on the endpoint after Step 5. Each command is a benign action and does not exploit anything:

```bash
# Rules 100141 (the shell) and 100140 (the id command it starts)
sudo -u www-data /bin/sh -c 'id'
sudo ausearch -k php2shell_exec -i --start recent

# Rule 100142 (new PHP file), then 100143 (modified PHP file), then 100144 (deleted PHP file)
echo '<?php // php2shell v1.2 test ?>' | sudo tee /var/www/html/php2shell_v12_test.php >/dev/null
sleep 8
echo '<?php // php2shell v1.2 test, modified ?>' | sudo tee /var/www/html/php2shell_v12_test.php >/dev/null
sleep 8
sudo rm -f /var/www/html/php2shell_v12_test.php
```

Observed result: `ausearch` returns the raw records with `key=php2shell_exec` and `euid=www-data` for `exe=/usr/bin/dash` and `exe=/usr/bin/id`. Each execution of the command raises rule 100141 (the shell) and rule 100140 (the `id` process). The file sequence raises rule 100142 at 12:00:39, rule 100143 at 12:00:47 and rule 100144 at 12:00:55, all for `/var/www/html/php2shell_v12_test.php`. Check them in Discover with `rule.id:(100140 OR 100141 OR 100142 OR 100143 OR 100144)`.

---

## Validation Evidence

All screenshots come from the Wazuh Dashboard on the lab agent `labnix`. Environment: Wazuh 4.14.8 manager, Ubuntu 24.04.5 endpoint, Apache 2.4.58 prefork with mod_php 8.3.6.

### Rules 100130 and 100131 - alerts without cookies

Each screenshot lists the v1.1 alert in the top row (15:23:52) and the v1.0 alert of the same rule in the bottom row. The v1.1 alert has no `full_log` and no `data.set_cookie`. The v1.0 alert carried the raw log line, which for rule 100131 included the response cookie of the lab test page (`cookie_test.php`).

![Rule 100130 in v1.1](docs/rule_100130_v11.png)

![Rule 100131 in v1.1](docs/rule_100131_v11.png)

After the sibling decoder was added, a new `cookie_test.php` request produced the top row below (17:18:13). `data.phpsessid_prefix` holds the 8 character prefix `a%00b%FF`, while `full_log` and `data.set_cookie` stay empty. The two older rows are the v1.1 alert before the prefix field (15:23:52) and the v1.0 alert with the raw cookie (12:09:16).

![Rule 100131 with phpsessid_prefix](docs/rule_100131-rev2.png)

### Rules 100101 and 100120 with `same_srcip`

The v1.1 alerts (15:23:58 and 15:24:00) fire on the same OOM and HTTP 500 sequence as the v1.0 alerts of the earlier runs (11:24 and 12:10).

![Rules 100101 and 100120 in v1.1](docs/rules_100101_100120_v11.png)

### Rules 100100 and 100101 - OOM fatals and repetition

Rule 100100 is unchanged in v1.1.

![Rules 100100 and 100101](docs/rules_100100_100101.png)

### SCA policy v1.0 - exposure on the unpatched and the patched endpoint

On the unpatched endpoint the score is 25%.

![SCA v1.0 unpatched](docs/sca_policy.png)

After package `php8.3-common 8.3.6-0ubuntu0.24.04.13` is installed, check 109600 changes to Passed and the score rises to 50%. Checks 109601 and 109602 stay Failed because those interim mitigations were not applied. This is the behavior that v1.1 changes, since a patched host does not need interim mitigations.

![SCA v1.0 patched](docs/sca_policy_pos_up.png)

The SCA results reach the indexer as events:

![SCA events in Discover](docs/sca_events.png)

### SCA policy v1.1 - patched endpoint

With the backport installed, all five checks pass and the score is 100%. Scan end time 17:04:35. The dashboard lists only the package command as target, because the `any` condition stops at the first passing rule.

![SCA v1.1 patched](docs/sca_policy_revision.png)

### SCA policy v1.1 - effective value computed with ini_get

To test the mitigation commands on a host that carries the backport, the package comparison in the policy was temporarily raised from `>= 13` to `>= 99` so that check 109600 fails, simulating a host without the backport. The test files were removed and the policy was restored afterwards (SHA-256 verified).

A drop-in `/etc/php/8.3/apache2/conf.d/99-php2shell-test.ini` with `memory_limit = -1`, `post_max_size = 32M` and `session.upload_progress.enabled = Off` was created. Run with the Apache `php.ini` and `conf.d`, `ini_get()` returned `-1`, `0` and `32`. Checks 109601 to 109604 pass through the PHP CLI commands and only 109600 fails. The score is 80% (scan end 17:10:07).

![SCA v1.1 mitigation through conf.d](docs/sca_policy_revision-2_score80.png)

The drop-in was removed, so the directives return to `128M`, `8M` and upload progress enabled, and the line `php_value memory_limit 128M` was written to `/etc/apache2/conf-enabled/zz-php2shell-test.conf`. Checks 109601 and 109602 fail because `ini_get()` returns the unmitigated values, and check 109604 fails because of the Apache override. Check 109603 passes because the default `post_max_size` of 8M is within the 32M limit. The score is 20% (scan end 17:14:09).

![SCA v1.1 no mitigation and Apache override](docs/sca_policy_revision-2_score20.png)

The shell logic of the five checks was also exercised outside Wazuh against 35 configurations with PHP 8.3.6: `conf.d` ordering, units (K, M, G and bytes), `0` and `-1` values, quoted values, `On`, `Off`, `0`, `No` and `false` for the boolean, overrides through symlinked Apache sites, `.htaccess` files, commented lines and upper case directive names.

---

## Validation Evidence (v1.2)

The screenshots in this section come from the Wazuh Dashboard on the agent `phnwn2shell-01`, an Ubuntu endpoint with auditd and FIM in real time on `/var/www/html`, reporting to the Wazuh 4.14.8 manager. That endpoint has no Apache or PHP installed, because rules 100140 to 100144 depend on the `www-data` UID and on the `/var/www` path, not on the web server process.

### Rules 100140 and 100141 - commands run by the web server account

Two runs of `sudo -u www-data /bin/sh -c 'id'`, at 11:57:35 and 11:57:41 (UTC-3). Each run produces rule 100141 for the shell (`/usr/bin/dash`, level 12) and rule 100140 for the `id` process it starts (`/usr/bin/id`, level 8). `data.audit.euid` and `data.audit.uid` are 33 in every alert.

![Rules 100140 and 100141](docs/rules_100140_100141.png)

### Rules 100142, 100143 and 100144 - PHP file created, modified and deleted

One test file, `/var/www/html/php2shell_v12_test.php`, created at 12:00:39 (rule 100142, level 10), modified at 12:00:47 (rule 100143, level 8) and deleted at 12:00:55 (rule 100144, level 6).

![Rules 100142, 100143 and 100144](docs/rules_100142_100143_100144.png)

---

## SCA Policy Summary

Scope: Ubuntu 24.04 LTS, PHP 8.3, Apache 2 with mod_php. The policy only runs where `/etc/php/8.3/apache2/php.ini` and the `php8.3-common` package exist.

| Check | Title | Passes when |
|---|---|---|
| 109600 | PHP 8.3 package includes the vendor backport (`8.3.6-0ubuntu0.24.04.13` or later) | The Ubuntu package revision is 13 or later |
| 109601 | `session.upload_progress.enabled` is disabled | The package has the backport, or the effective value is `Off` or `0` |
| 109602 | `memory_limit` is `-1` | The package has the backport, or the effective value is `-1` |
| 109603 | `post_max_size` is 32M or lower | The package has the backport, or the effective value is 32M or lower |
| 109604 | No Apache or `.htaccess` override undoes the mitigation | The package has the backport, or no `php_value`, `php_admin_value`, `php_flag` or `php_admin_flag` line under `/etc/apache2` or in `.htaccess` files under `/var/www` sets `memory_limit` to anything but `-1`, `post_max_size` above 32M or unlimited, or `session.upload_progress.enabled` on |

The effective value of a directive is what `ini_get()` returns when the PHP CLI is started with `-c /etc/php/8.3/apache2/php.ini` and `PHP_INI_SCAN_DIR=/etc/php/8.3/apache2/conf.d`. `post_max_size` is converted to MiB and rounded up, and `0` (unlimited) fails. Checks 109601 to 109604 use the condition `any`, so a host with the backport passes them. They are partial mitigations from the PHP advisory. Updating PHP is the only complete fix, and `memory_limit=-1` increases exhaustion risk, so pair it with a container or cgroup memory limit.

---

## Limitations

- **Session cookies in the log file.** The `php2shell` LogFormat records the full `Set-Cookie` response header, which includes every cookie the application sets in a response. Since v1.1 the decoder does not extract it, rules 100130 and 100131 omit `full_log`, and only a truncated 8 character `PHPSESSID` prefix reaches the alert, so alerts carry no cookies. Leaked memory can hold passwords, tokens and API keys (Wiz), so also restrict who can read rule 100131 alerts. The log file `php2shell_access.log` and, if `logall_json` is enabled, the Wazuh archives still contain the raw line. Treat both as sensitive: restrict the log file to `root:adm` with mode 640, keep retention short, restrict access to the archives, and enable the format only on hosts under review.
- **Rule 100110 is validated by logtest only.** Crashing a production-like worker on purpose is invasive, so no real segfault event was generated. Segfaults also have benign causes, such as defective extensions, and the rule carries no source IP because Apache logs worker exits without a client address.
- **Rule 100120 can be noisy** on sites with legitimate bursts of HTTP 500. Tune the level and frequency to your baseline.
- **Chunked detection is HTTP/1.1 only.** HTTP/2 lengthless multipart requests, also described by Calif, carry no `Transfer-Encoding` header and are not covered by rule 100130.
- **PHP-FPM was not tested.** The lab runs mod_php. The rules operate on Apache logs, but exploitation paths differ on PHP-FPM, as described by the researchers. The policy reads the Apache SAPI configuration only and does not cover FPM pool settings.
- **SCA effective values come from the files of the Apache SAPI.** `ini_get()` reflects `php.ini` and `conf.d` and needs the `php8.3-cli` package. Check 109604 searches `/etc/apache2` and `.htaccess` files under `/var/www`. It does not read `.htaccess` files elsewhere, configuration included from outside `/etc/apache2`, `[PATH=]` and `[HOST=]` sections, or values set by the application at runtime. `post_max_size` overrides are matched for values in M, G or 9 or more digits of bytes.
- **The SCA policy is specific to Ubuntu 24.04 with PHP 8.3 and Apache mod_php.** Other distributions and PHP branches need their own revision checks.
- **The v1.2 rules were validated with benign commands and a test file.** Rules 100140 to 100144 were exercised with `sudo -u www-data /bin/sh -c 'id'` and a PHP file created, modified and deleted under `/var/www/html`, not with a live PHP2Shell exploitation.
- **The auditd rules are tied to one UID.** `auditd/php2shell.rules` uses `euid=33`. On RHEL-family hosts or custom Apache accounts the value must change, otherwise nothing is recorded. PHP-FPM pools running under another user are not covered unless that UID is added.
- **Rule 100140 is broad by design.** Legitimate helpers started by the web server, such as a mail transfer agent used by `mail()`, raise it. Use rule 100141 for notifications and keep 100140 for hunting.
- **FIM is path and extension based.** Rules 100142, 100143 and 100144 do not inspect content, and a web shell written with another extension that the server still executes is not matched. FIM in `realtime` mode relies on inotify watch limits for large trees.
- **FIM does not tell who wrote the file.** `whodata` mode adds the user and process, but it depends on auditd and on its own audit rules, which were not tested together with `php2shell.rules`.

---

## Remediation

Apply the PHP security update. This is the only complete fix.

```bash
# Ubuntu 24.04 - package revision with the backport
apt update && apt install libapache2-mod-php8.3 php8.3-cli php8.3-common php8.3-opcache php8.3-readline
systemctl restart apache2
```

Fixed upstream in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, with source backports for 7.4, 8.0 and 8.1 listed in the advisory. For interim mitigations, see SCA checks 109601 to 109604 and the PHP advisory. On PHP 8.5 the advisory also lists `fatal_error_backtraces=0`, which this policy does not check because it targets PHP 8.3.

---

## Author

**Kislley Rodrigues** (m0us3r) - Wazuh Ambassador | Detection Engineering | Blue Team

## Wazuh

This project was developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Wazuh is a free, open source security platform that provides unified XDR and SIEM capabilities. Learn more at [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

## Validation environment

The rules, decoder and SCA policy were validated in a lab with the following versions:

- Wazuh manager: 4.14.8
- Agent OS: Ubuntu 24.04.5 LTS
- Web server: Apache 2.4.58 (prefork, mod_php)
- PHP: 8.3.6 (package 8.3.6-0ubuntu0.24.04.13 is the patched build)

The auditd and FIM rules (100140 to 100144) were validated on a second Wazuh agent, `phnwn2shell-01`, an Ubuntu endpoint with auditd and FIM in real time on `/var/www/html`, reporting to the same 4.14.8 manager. That endpoint has no Apache or PHP installed.

## Acknowledgments

Special thanks to Katia Bukcovac and Farouk Musa from the Wazuh team for their support of the Ambassador Program and for the technical review of this work.
