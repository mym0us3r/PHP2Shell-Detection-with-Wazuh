# Security Policy

This repository contains detection content for PHP2Shell (CVE-2026-109618 and CVE-2026-109619): Wazuh rules, decoders, an Apache LogFormat and a Security Configuration Assessment (SCA) policy. It contains no exploit code.

## Supported Versions

There are no release branches. Only the latest commit on `main` is maintained.

| Component | Tested on | Supported |
|---|---|---|
| Wazuh manager and agent | 4.14.8 | Yes |
| Apache | 2.4.58 with mod_php 8.3.6 | Yes |
| Ubuntu | 24.04 LTS | Yes |
| Other Wazuh, Apache or PHP versions | Not tested | Best effort |

## What to Report

Please report any of the following:

- A bypass or false negative in a rule, for example a request that triggers the PHP2Shell conditions but evades rules 100100 to 100131.
- A regular expression in the decoders or rules that can be abused for excessive CPU use (ReDoS) or log injection against the Wazuh manager.
- A rule or decoder that can be abused to suppress other alerts or to flood the manager with events.
- Instructions in this repository that create a security risk. One known case is documented in the README: the `php2shell` LogFormat records the full `Set-Cookie` response header, so the log file must be treated as sensitive.
- Sensitive data committed by mistake, such as keys, tokens or internal hostnames.

Out of scope:

- Vulnerabilities in PHP itself. Report them to the PHP project through its official security channels.
- Vulnerabilities in Wazuh itself. Report them to Wazuh through its official disclosure process.
- Detection gaps already listed in the Limitations section of the README (HTTP/2 lengthless bodies, PHP-FPM, rule 100110 validated by logtest only).

## How to Report

Use GitHub private vulnerability reporting: open the **Security** tab of this repository and select **Report a vulnerability**. Please do not open a public issue for a vulnerability.

Include the Wazuh version, the rule or decoder ID, a sample log line (remove any real session cookies, IP addresses and hostnames) and the output of `wazuh-logtest` that shows the problem.

## What to Expect

- Acknowledgment of the report within 7 days.
- A first assessment, including whether the report is accepted or declined and why, within 14 days.
- If accepted, a fix is published on `main` and the reporter is credited in the commit message unless anonymity is requested.
- If declined, a short explanation is provided.

These are best-effort targets from a single maintainer.

## Maintainer

Kislley Rodrigues - Wazuh Ambassador Program
