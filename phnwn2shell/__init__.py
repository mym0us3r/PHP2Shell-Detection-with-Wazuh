# PHNwn2Shell - passive IoC sensor (HTTP honeypot) for PHP2Shell, Node2Shell and HTTP2Shell
#
# Purpose: log what scanners and exploit tools send to a decoy that answers like
# a PHP/Apache site (ports 80 and 443) or a Node.js/Express site (port 3000),
# and feed those events to Wazuh as one JSON line per request. The sensor never
# executes what it receives, makes no outbound connections and downloads nothing.
#
# This file: Package definition: version string and entry point import.
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

"""PHNwn2Shell: low-interaction honeypot for PHP2Shell, Node2Shell and HTTP2Shell."""

__version__ = "0.1.0"
