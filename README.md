# Cerberus-CVE Assessment Situation v3.0

## Overview

Cerberus-CVE is a comprehensive scanning and exploitation framework for two critical CVEs with real command execution and post-exploitation automation.

**Disclaimer: This tool is for authorized security testing and educational purposes only.**

## Targeted CVEs

### CVE-2025-9491 POC - Remote Code Execution
- **Type**: Remote Code Execution Vulnerability
- **Scanning**: Automated detection of RCE endpoints and suspicious services
- **Exploitation**: Real command execution through multiple injection vectors
- **Payloads**: Command injection, PHP code injection, template injection
- **Validation**: Actual command execution verification with test commands

### CVE-2025-59287 POC - Privilege Escalation  
- **Type**: Local Privilege Escalation Vulnerability
- **Scanning**: Real privilege escalation vector identification
- **Exploitation**: SUID binary exploitation, sudo misconfigurations
- **Techniques**: Binary privilege escalation, capability abuse, cron job exploitation
- **Post-Exploitation**: Interactive shells, data exfiltration, lateral movement

## Features

- **Real Command Execution**: Multiple injection methods (Command, PHP, Template)
- **Advanced CVE Detection**: Specific scanning for CVE-2025-9491 and CVE-2025-59287
- **Privilege Escalation Automation**: Real-world privilege escalation techniques
- **Lateral Movement**: SSH key discovery and credential extraction
- **Data Exfiltration**: Automated collection of sensitive files and configurations
- **TOR Integration**: Anonymous operations with multiple verification methods
- **Comprehensive Reporting**: Multiple formats (TXT, CSV, JSON) with evidence archiving
- **Interactive Shell**: Real command execution interface
- **Post-Exploitation Menu**: Persistent access and continued exploitation

## Installation

```bash
git clone https://github.com/ekomsSavior/Cerebus.git
cd Cerebus

pip install requests pysocks urllib3 readline --break-system-packages

```

## Usage


```bash

sudo systemctl start tor@default

python3 cerberus.py 

```

## CVE-Specific Capabilities

### CVE-2025-9491 Exploitation POC
- Endpoint discovery (/api/v1/execute, /admin/command, /cgi-bin/exec, etc.)
- Multiple injection payload testing (GET/POST parameters)
- Service detection and banner grabbing
- Real command execution validation
- Information disclosure testing

### CVE-2025-59287 Privilege Escalation POC
- SUID binary identification and exploitation
- Sudo privilege enumeration and abuse
- Capability discovery and exploitation
- Cron job analysis
- Writable system file identification
- Post-exploitation menu with continued access

## Command Execution Methods

- **Command Injection**: ;command;, |command, `command`, $(command), ||command, &&command
- **PHP Injection**: system(), exec(), shell_exec(), passthru(), backticks
- **Template Injection**: Jinja2, Smarty, and other template engines
- **Parameter Testing**: ip, host, cmd, command, exec, system, query, input, data, username, password, file, path

## Privilege Escalation Techniques

- **SUID Binaries**: bash, dash, find, nmap, vim, less, more, awk, perl, python
- **Sudo Exploitation**: bash, sh, su, passwd, vi, nmap, find, awk, perl, python
- **Capability Abuse**: getcap enumeration and exploitation
- **Cron Job Manipulation**: /etc/cron*, /var/spool/cron analysis

## Output and Reporting

The tool generates comprehensive evidence and reports:

- **Text Reports**: Detailed findings with timestamps and evidence
- **CSV Reports**: Structured data for analysis and reporting
- **JSON Reports**: Machine-readable output for automation
- **Evidence Archives**: ZIP files containing extracted sensitive data
- **Credential Files**: Structured password and configuration data
- **SSH Key Storage**: Extracted SSH keys and authorized_keys

## Legal and Ethical Use

This tool is intended exclusively for:
- Authorized penetration testing with written permission.

Users must obtain proper authorization before scanning or testing any system. The developer assumes no responsibility for misuse of this tool.
