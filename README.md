# Cerberus Security Assessment & Exploitation
![Cerberus Banner](https://github.com/user-attachments/assets/ad22fcf5-2fcb-4592-8f5f-79fea1975008)

<img width="1024" height="1536" alt="Cerberus Interface" src="https://github.com/user-attachments/assets/b193a2ab-0f4c-4f92-9dc5-c6585df29f5b" />

## Overview

Cerberus is a comprehensive, intelligent security assessment framework featuring advanced RCE exploitation, real command execution, and automated post-exploitation capabilities. This enhanced version represents a complete evolution from previous iterations with sophisticated exploitation techniques and intelligent vulnerability assessment.

**Disclaimer: This tool is for authorized security testing, educational purposes, and professional penetration testing only.**

## Installation

```bash
git clone https://github.com/ekomsSavior/Cerberus.git
cd Cerberus

# Install dependencies

sudo apt update && sudo apt install tor

pip install requests pysocks urllib3 readline --break-system-packages

```

![Screenshot_2025-11-04_02_21_16](https://github.com/user-attachments/assets/def699c1-3a3c-476b-9e8b-0891f173c14c)


## Usage

always start tor first

```bash
sudo systemctl start tor@default
```

then run Cerberus

```bash
sudo python3 cerberus.py
```

The framework operates in interactive mode, guiding you through:

1. **Target Specification**: IP/hostname and port configuration
2. **Scan Type Selection**: Quick scan, full assessment, or specific module execution
3. **TOR Integration**: Optional anonymous operations
4. **Automated Exploitation**: Intelligent vulnerability detection and exploitation
5. **Post-Exploitation**: Interactive menu for continued access and data exfiltration

## Advanced Exploitation Modules

### WebShellDeployer
- **PHP Shell Deployment**: Multiple shell types (basic, advanced, obfuscated, mini, base64)
- **Deployment Methods**: File upload, file write, log poisoning, template injection
- **ASP/X Shells**: Windows-specific web shell deployment
- **Automated Testing**: Shell functionality verification

### FrameworkExploiter
- **Spring RCE**: Multiple CVE exploitation including Spring4Shell
- **Laravel Exploitation**: Debug mode RCE, token unserialization attacks
- **WordPress Targeting**: Vulnerable plugin detection and exploitation
- **Authentication Bypass**: Framework-specific credential testing

### IntelligentRCEExploiter
- **Multi-Vector Attacks**: JSON-RPC, REST API, command injection, deserialization
- **Template Injection**: SSTI, Jinja2, Twig exploitation
- **Advanced Command Injection**: Windows and Linux payload sets
- **Intelligent Detection**: Success validation and response analysis

### ServiceSpecificExploiter
- **Web Service Attacks**: Directory traversal, file inclusion, admin panel discovery
- **FTP Exploitation**: Anonymous access testing, credential brute forcing
- **SSH Analysis**: Common credential testing and service enumeration
- **DNS Attacks**: Zone transfer testing, recursion verification
- **SMB/RDP**: Anonymous share discovery, service vulnerability assessment

## Command Execution Engine

### Execution Methods
- **Command Injection**: `;command;`, `|command`, `` `command` ``, `$(command)`, `||command`, `&&command`
- **PHP Code Execution**: `system()`, `exec()`, `shell_exec()`, `passthru()`, backticks, base64 encoding
- **Template Injection**: Jinja2, Smarty, Twig template engine exploitation
- **Deserialization Attacks**: PHP, Java, Python object injection
- **SSRF Exploitation**: Internal service access and command execution

### Parameter Testing
Comprehensive parameter testing across:
- `ip`, `host`, `cmd`, `command`, `exec`, `system`, `query`, `input`
- `data`, `username`, `password`, `file`, `path`, `url`, `page`, `template`

## Privilege Escalation Framework

### SUID Binary Exploitation
- **Automated Detection**: `find / -perm -4000` analysis
- **Binary Exploitation**: bash, dash, find, nmap, vim, less, more, awk, perl, python
- **Exploit Payloads**: Context-aware exploitation commands for each binary

### Sudo Misconfiguration
- **Permission Enumeration**: `sudo -l` analysis and exploitation
- **Pattern Recognition**: Automated detection of exploitable sudo configurations
- **Privilege Escalation**: Root access through misconfigured sudo rights

### System Analysis
- **Cron Job Examination**: `/etc/cron*`, `/var/spool/cron` analysis
- **Capability Discovery**: `getcap -r /` capability enumeration
- **Writable File Identification**: System file permission analysis

## Post-Exploitation Menu

### Interactive Features
- **Real Interactive Shell**: Fully functional command execution interface
- **Data Exfiltration**: Automated collection of sensitive files and configurations
- **System Intelligence**: Comprehensive system information gathering
- **Network Reconnaissance**: Internal network mapping and service discovery
- **Lateral Movement**: SSH key discovery, credential harvesting, internal exploitation
- **Persistence Mechanisms**: Cron jobs, backdoor deployment, service installation

### Data Collection
- **System Information**: Kernel, CPU, memory, disk usage, processes
- **Network Intelligence**: Interfaces, routing, ARP tables, active connections
- **Sensitive Files**: Password files, configuration files, SSH keys, database dumps
- **User Data**: Home directories, browser data, application configurations

## Output and Reporting

### Comprehensive Reporting
- **Text Reports**: Detailed assessment findings with timestamps and evidence
- **Structured Data**: Machine-readable output for automation and analysis
- **Evidence Archives**: ZIP files containing extracted sensitive data and configurations
- **Execution Logs**: Complete exploitation timeline and methodology

### Evidence Management
- **Automated Archiving**: Structured evidence collection and preservation
- **Credential Storage**: Secure password and configuration data management
- **SSH Key Repository**: Extracted SSH keys and authorized_keys files
- **Sensitive Data**: Protected storage of exfiltrated information

## Legal and Ethical Use

### Authorized Usage Only
This framework is intended exclusively for:
- Authorized penetration testing with written permission

**Cerberus Security Assessment Framework v5.1 - Advanced Intelligence for Modern Security Testing**

<img width="1024" height="1536" alt="Cerberus Demonstration" src="https://github.com/user-attachments/assets/592c1c01-ff00-44b1-9061-0039ac3891c6" />

![Cerberus Architecture](https://github.com/user-attachments/assets/03ab0d16-b536-4dac-8bfa-836526a17fb0)
