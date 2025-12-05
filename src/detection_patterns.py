"""
Phase 2: Enhanced Detection Patterns

This module contains 10+ new detection patterns for advanced threat detection:
1. Credential Theft Detection
2. Persistence Mechanism Detection  
3. Lateral Movement Detection
4. Privilege Escalation Detection
5. Data Exfiltration Detection
6. Ransomware Behavior Detection
7. Rootkit Detection
8. Memory Injection Detection
9. Token Manipulation Detection
10. Registry Modification Detection
11. Service Manipulation Detection
12. Scheduled Task Abuse Detection
"""

from typing import List, Dict, Optional, Any
import re


class AdvancedDetectionPatterns:
    """Advanced detection patterns for Phase 2."""
    
    def __init__(self):
        # Credential theft patterns
        self.credential_tools = [
            "mimikatz", "lazagne", "procdump", "pwdump", "gsecdump",
            "wce.exe", "fgdump", "cachedump", "lslsass", "nanodump",
            "dumpert", "eviltree", "handlekatz", "physmem2profit"
        ]
        
        self.credential_processes = [
            "lsass.exe", "sam", "security", "ntds.dit"
        ]
        
        # Persistence mechanisms
        self.persistence_registry_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            r"SYSTEM\CurrentControlSet\Services",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            r"SOFTWARE\Classes\Protocols\Handler",
            r"SOFTWARE\Classes\Protocols\Filter"
        ]
        
        self.persistence_startup_paths = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        ]
        
        # Lateral movement tools
        self.lateral_movement_tools = [
            "psexec", "psexesvc", "paexec", "winexe", "wmic", "winrs",
            "dcom", "wmiprvse", "schtasks", "at.exe", "sc.exe",
            "powershell -computer", "invoke-command", "enter-pssession"
        ]
        
        # Privilege escalation indicators
        self.privesc_tools = [
            "juicy", "potato", "printspoofer", "sweetpotato", "roguepotato",
            "psgetsystem", "elevate.exe", "uac", "eventvwr", "fodhelper"
        ]
        
        # Data exfiltration patterns
        self.exfil_tools = [
            "ftp", "scp", "sftp", "rsync", "rclone", "megasync",
            "dropbox", "onedrive", "googledrive", "curl", "wget",
            "certutil -urlcache", "bitsadmin", "powershell download"
        ]
        
        # Ransomware indicators
        self.ransomware_extensions = [
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
            ".locky", ".cerber", ".wannacry", ".petya", ".ryuk",
            ".maze", ".sodinokibi", ".revil", ".conti", ".lockbit"
        ]
        
        self.ransomware_behaviors = [
            "vssadmin delete shadows",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            "wbadmin delete catalog",
            "wbadmin delete systemstatebackup",
            "net stop \"sql server\"",
            "net stop \"exchange\""
        ]
        
        # Rootkit indicators
        self.rootkit_signatures = [
            "\\Device\\PhysicalMemory",
            "\\Device\\RawDisk",
            "\\DosDevices\\Global\\",
            "SIDT", "SSDT", "FOPS", "DKOM",
            "ZwQuerySystemInformation hooking"
        ]
        
        # Token manipulation
        self.token_abuse_indicators = [
            "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
            "SeRestorePrivilege", "SeTakeOwnershipPrivilege"
        ]
    
    def _ensure_dict(self, item):
        """Helper to ensure item is a dict, return empty dict if not."""
        return item if isinstance(item, dict) else {}
    
    def _ensure_list(self, data):
        """Helper to ensure data is a list, filter out non-dict items."""
        if not data:
            return []
        if not isinstance(data, list):
            data = [data]
        return [item for item in data if isinstance(item, dict)]
    
    def detect_credential_theft(
        self, 
        processes: List[Dict], 
        handles: List[Dict],
        analysis
    ) -> List[Dict]:
        """
        Detect credential theft attempts.
        
        MITRE ATT&CK:
        - T1003: OS Credential Dumping
        - T1003.001: LSASS Memory
        - T1003.002: Security Account Manager
        - T1003.003: NTDS
        """
        findings = []
        
        for proc in processes:
            pid = proc.get('PID', 0)
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            ppid = proc.get('PPID', 0)
            
            # Detect credential dumping tools
            for tool in self.credential_tools:
                if tool in proc_name or tool in cmdline:
                    findings.append({
                        'type': 'Credential Theft',
                        'severity': 'CRITICAL',
                        'pid': pid,
                        'process': proc_name,
                        'method': f'Credential Dumping Tool: {tool}',
                        'mitre': 'T1003',
                        'confidence': 95,
                        'description': f'Known credential dumping tool detected: {tool}'
                    })
            
            # Detect LSASS access
            if 'lsass' in cmdline or 'lsass.dmp' in cmdline:
                findings.append({
                    'type': 'Credential Theft',
                    'severity': 'CRITICAL',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'LSASS Memory Access',
                    'mitre': 'T1003.001',
                    'confidence': 90,
                    'description': 'Process attempting to access LSASS memory'
                })
            
            # Detect SAM/SECURITY registry access
            if 'reg save' in cmdline and ('sam' in cmdline or 'security' in cmdline):
                findings.append({
                    'type': 'Credential Theft',
                    'severity': 'CRITICAL',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'SAM Registry Dumping',
                    'mitre': 'T1003.002',
                    'confidence': 95,
                    'description': 'Registry hive dumping detected (SAM/SECURITY)'
                })
            
            # Detect NTDS.dit access
            if 'ntds.dit' in cmdline or 'ntdsutil' in proc_name:
                findings.append({
                    'type': 'Credential Theft',
                    'severity': 'CRITICAL',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'NTDS.dit Extraction',
                    'mitre': 'T1003.003',
                    'confidence': 95,
                    'description': 'Active Directory database extraction attempt'
                })
        
        # Check handles for LSASS access
        for handle in handles:
            if handle.get('HandleType') == 'Process':
                handle_name = handle.get('Name', '').lower()
                if 'lsass.exe' in handle_name:
                    findings.append({
                        'type': 'Credential Theft',
                        'severity': 'CRITICAL',
                        'pid': handle.get('PID', 0),
                        'method': 'LSASS Process Handle',
                        'mitre': 'T1003.001',
                        'confidence': 85,
                        'description': 'Open handle to LSASS process detected'
                    })
        
        return findings
    
    def detect_persistence_mechanisms(
        self, 
        registry_data: List[Dict],
        scheduled_tasks: List[Dict],
        services: List[Dict],
        processes: List[Dict]
    ) -> List[Dict]:
        """
        Detect persistence mechanisms.
        
        MITRE ATT&CK:
        - T1547: Boot or Logon Autostart Execution
        - T1053: Scheduled Task/Job
        - T1543: Create or Modify System Process
        - T1546: Event Triggered Execution
        """
        findings = []
        registry_data = self._ensure_list(registry_data)
        scheduled_tasks = self._ensure_list(scheduled_tasks)
        services = self._ensure_list(services)
        processes = self._ensure_list(processes)
        
        # Registry persistence
        for reg_entry in registry_data:
            reg_path = reg_entry.get('Path', '')
            reg_value = reg_entry.get('Value', '').lower()
            
            for persist_key in self.persistence_registry_keys:
                if persist_key.lower() in reg_path.lower():
                    # Check for suspicious values
                    suspicious = any(x in reg_value for x in [
                        'powershell', 'cmd.exe', 'wscript', 'cscript',
                        'regsvr32', 'rundll32', 'mshta', 'certutil',
                        '.bat', '.vbs', '.js', '.ps1', 'temp\\', 'appdata\\'
                    ])
                    
                    if suspicious:
                        findings.append({
                            'type': 'Persistence',
                            'severity': 'HIGH',
                            'method': 'Registry Run Key',
                            'registry_path': reg_path,
                            'value': reg_value,
                            'mitre': 'T1547.001',
                            'confidence': 80,
                            'description': f'Suspicious registry persistence: {reg_path}'
                        })
        
        # Scheduled task persistence
        for task in scheduled_tasks:
            task_name = task.get('TaskName', '')
            task_action = task.get('Actions', '').lower()
            
            suspicious_task = any(x in task_action for x in [
                'powershell', 'cmd.exe', 'wscript', 'cscript',
                'regsvr32', 'rundll32', 'certutil', 'bitsadmin',
                'temp\\', 'appdata\\', 'programdata\\'
            ])
            
            if suspicious_task:
                findings.append({
                    'type': 'Persistence',
                    'severity': 'HIGH',
                    'method': 'Scheduled Task',
                    'task_name': task_name,
                    'action': task_action,
                    'mitre': 'T1053.005',
                    'confidence': 75,
                    'description': f'Suspicious scheduled task: {task_name}'
                })
        
        # Service persistence
        for service in services:
            svc_name = service.get('Name', '')
            svc_binary = service.get('BinaryPath', '').lower()
            svc_type = service.get('ServiceType', '')
            
            suspicious_service = any(x in svc_binary for x in [
                'powershell', 'cmd.exe', 'rundll32', 'regsvr32',
                'temp\\', 'appdata\\', 'programdata\\', 'users\\'
            ])
            
            if suspicious_service or 'UserMode' in svc_type:
                findings.append({
                    'type': 'Persistence',
                    'severity': 'HIGH',
                    'method': 'Windows Service',
                    'service_name': svc_name,
                    'binary': svc_binary,
                    'mitre': 'T1543.003',
                    'confidence': 80,
                    'description': f'Suspicious service: {svc_name}'
                })
        
        # WMI event subscription persistence
        for proc in processes:
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            
            if 'wmic' in proc_name and 'eventvns' in cmdline:
                findings.append({
                    'type': 'Persistence',
                    'severity': 'HIGH',
                    'pid': proc.get('PID', 0),
                    'process': proc_name,
                    'method': 'WMI Event Subscription',
                    'mitre': 'T1546.003',
                    'confidence': 85,
                    'description': 'WMI event subscription for persistence'
                })
        
        return findings
    
    def detect_lateral_movement(self, processes: List[Dict], network: List[Dict]) -> List[Dict]:
        """
        Detect lateral movement attempts.
        
        MITRE ATT&CK:
        - T1021: Remote Services
        - T1021.001: Remote Desktop Protocol
        - T1021.002: SMB/Windows Admin Shares
        - T1021.003: Distributed Component Object Model
        - T1021.006: Windows Remote Management
        """
        findings = []
        processes = self._ensure_list(processes)
        network = self._ensure_list(network)
        
        for proc in processes:
            pid = proc.get('PID', 0)
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            
            # PsExec detection
            if 'psexec' in proc_name or 'paexec' in proc_name:
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'HIGH',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'PsExec',
                    'mitre': 'T1021.002',
                    'confidence': 90,
                    'description': 'PsExec tool detected for remote execution'
                })
            
            # WMIC remote execution
            if 'wmic' in proc_name and '/node:' in cmdline:
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'HIGH',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'WMIC Remote Execution',
                    'mitre': 'T1047',
                    'confidence': 85,
                    'description': 'WMIC remote command execution detected'
                })
            
            # WinRM detection
            if 'winrs' in proc_name or 'invoke-command' in cmdline:
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'MEDIUM',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'Windows Remote Management',
                    'mitre': 'T1021.006',
                    'confidence': 80,
                    'description': 'WinRM remote execution detected'
                })
            
            # PowerShell remoting
            if 'powershell' in proc_name and ('enter-pssession' in cmdline or '-computername' in cmdline):
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'MEDIUM',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'PowerShell Remoting',
                    'mitre': 'T1021.006',
                    'confidence': 75,
                    'description': 'PowerShell remoting detected'
                })
        
        # Network-based lateral movement indicators
        for conn in network:
            remote_addr = conn.get('RemoteAddr', '')
            remote_port = conn.get('RemotePort', 0)
            local_port = conn.get('LocalPort', 0)
            
            # SMB connections (445, 139)
            if remote_port in [445, 139] or local_port in [445, 139]:
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'MEDIUM',
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'method': 'SMB Connection',
                    'mitre': 'T1021.002',
                    'confidence': 60,
                    'description': f'SMB connection to {remote_addr}:{remote_port}'
                })
            
            # RDP connections (3389)
            if remote_port == 3389 or local_port == 3389:
                findings.append({
                    'type': 'Lateral Movement',
                    'severity': 'MEDIUM',
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'method': 'RDP Connection',
                    'mitre': 'T1021.001',
                    'confidence': 70,
                    'description': f'RDP connection to {remote_addr}:3389'
                })
        
        return findings
    
    def detect_privilege_escalation(self, processes: List[Dict], handles: List[Dict]) -> List[Dict]:
        """
        Detect privilege escalation attempts.
        
        MITRE ATT&CK:
        - T1068: Exploitation for Privilege Escalation
        - T1134: Access Token Manipulation
        - T1548: Abuse Elevation Control Mechanism
        """
        findings = []
        processes = self._ensure_list(processes)
        handles = self._ensure_list(handles)
        
        for proc in processes:
            pid = proc.get('PID', 0)
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            
            # Potato family exploits
            for tool in self.privesc_tools:
                if tool in proc_name or tool in cmdline:
                    findings.append({
                        'type': 'Privilege Escalation',
                        'severity': 'CRITICAL',
                        'pid': pid,
                        'process': proc_name,
                        'method': f'Privilege Escalation Tool: {tool}',
                        'mitre': 'T1068',
                        'confidence': 95,
                        'description': f'Known privilege escalation tool: {tool}'
                    })
            
            # UAC bypass techniques
            uac_bypass_indicators = [
                'eventvwr.exe', 'fodhelper.exe', 'computerdefaults.exe',
                'sdclt.exe', 'silentcleanup', 'disk cleanup'
            ]
            
            for indicator in uac_bypass_indicators:
                if indicator in proc_name:
                    # Check if launched from suspicious parent
                    if any(x in cmdline for x in ['powershell', 'cmd.exe', 'wscript']):
                        findings.append({
                            'type': 'Privilege Escalation',
                            'severity': 'HIGH',
                            'pid': pid,
                            'process': proc_name,
                            'method': 'UAC Bypass',
                            'mitre': 'T1548.002',
                            'confidence': 85,
                            'description': f'Potential UAC bypass via {indicator}'
                        })
            
            # Token impersonation
            if 'token' in cmdline and ('impersonate' in cmdline or 'steal' in cmdline):
                findings.append({
                    'type': 'Privilege Escalation',
                    'severity': 'HIGH',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'Token Impersonation',
                    'mitre': 'T1134',
                    'confidence': 90,
                    'description': 'Token impersonation detected'
                })
        
        return findings
    
    def detect_data_exfiltration(self, processes: List[Dict], network: List[Dict]) -> List[Dict]:
        """
        Detect data exfiltration attempts.
        
        MITRE ATT&CK:
        - T1020: Automated Exfiltration
        - T1041: Exfiltration Over C2 Channel
        - T1048: Exfiltration Over Alternative Protocol
        - T1567: Exfiltration Over Web Service
        """
        findings = []
        processes = self._ensure_list(processes)
        network = self._ensure_list(network)
        
        for proc in processes:
            pid = proc.get('PID', 0)
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            
            # Exfiltration tools
            for tool in self.exfil_tools:
                if tool in proc_name or tool in cmdline:
                    findings.append({
                        'type': 'Data Exfiltration',
                        'severity': 'HIGH',
                        'pid': pid,
                        'process': proc_name,
                        'method': f'Exfiltration Tool: {tool}',
                        'mitre': 'T1048',
                        'confidence': 80,
                        'description': f'Data exfiltration tool detected: {tool}'
                    })
            
            # Cloud storage sync
            cloud_indicators = ['dropbox', 'onedrive', 'googledrive', 'mega', 'box.com']
            for cloud in cloud_indicators:
                if cloud in cmdline:
                    findings.append({
                        'type': 'Data Exfiltration',
                        'severity': 'MEDIUM',
                        'pid': pid,
                        'process': proc_name,
                        'method': 'Cloud Storage',
                        'mitre': 'T1567.002',
                        'confidence': 70,
                        'description': f'Cloud storage usage detected: {cloud}'
                    })
        
        # Network-based exfiltration
        for conn in network:
            remote_addr = conn.get('RemoteAddr', '')
            remote_port = conn.get('RemotePort', 0)
            
            # FTP (21), SFTP (22), HTTP (80), HTTPS (443)
            exfil_ports = [21, 22, 80, 443, 8080, 8443]
            if remote_port in exfil_ports:
                findings.append({
                    'type': 'Data Exfiltration',
                    'severity': 'MEDIUM',
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'method': f'Network Transfer (Port {remote_port})',
                    'mitre': 'T1041',
                    'confidence': 50,
                    'description': f'Potential exfiltration to {remote_addr}:{remote_port}'
                })
        
        return findings
    
    def detect_ransomware_behavior(self, processes: List[Dict], files: List[Dict]) -> List[Dict]:
        """
        Detect ransomware behavior patterns.
        
        MITRE ATT&CK:
        - T1486: Data Encrypted for Impact
        - T1490: Inhibit System Recovery
        - T1489: Service Stop
        """
        findings = []
        processes = self._ensure_list(processes)
        files = self._ensure_list(files)
        
        for proc in processes:
            pid = proc.get('PID', 0)
            proc_name = proc.get('ImageFileName', '').lower()
            cmdline = proc.get('CommandLine', '').lower()
            
            # Ransomware behaviors
            for behavior in self.ransomware_behaviors:
                if behavior.lower() in cmdline:
                    findings.append({
                        'type': 'Ransomware',
                        'severity': 'CRITICAL',
                        'pid': pid,
                        'process': proc_name,
                        'method': 'System Recovery Inhibition',
                        'command': behavior,
                        'mitre': 'T1490',
                        'confidence': 95,
                        'description': f'Ransomware behavior detected: {behavior}'
                    })
            
            # Mass file encryption indicators
            if 'cipher' in proc_name or 'encrypt' in cmdline:
                findings.append({
                    'type': 'Ransomware',
                    'severity': 'CRITICAL',
                    'pid': pid,
                    'process': proc_name,
                    'method': 'File Encryption',
                    'mitre': 'T1486',
                    'confidence': 90,
                    'description': 'File encryption activity detected'
                })
        
        # Check for ransomware file extensions
        for file_obj in files:
            file_path = file_obj.get('Path', '').lower()
            
            for ext in self.ransomware_extensions:
                if file_path.endswith(ext):
                    findings.append({
                        'type': 'Ransomware',
                        'severity': 'CRITICAL',
                        'file': file_path,
                        'method': 'Ransomware File Extension',
                        'extension': ext,
                        'mitre': 'T1486',
                        'confidence': 95,
                        'description': f'Ransomware file extension detected: {ext}'
                    })
        
        return findings
    
    def detect_rootkit_indicators(self, drivers: List[Dict], processes: List[Dict]) -> List[Dict]:
        """
        Detect rootkit indicators.
        
        MITRE ATT&CK:
        - T1014: Rootkit
        - T1542: Pre-OS Boot
        - T1556: Modify Authentication Process
        """
        findings = []
        drivers = self._ensure_list(drivers)
        processes = self._ensure_list(processes)
        
        # Check for suspicious drivers
        for driver in drivers:
            driver_name = driver.get('Name', '').lower()
            driver_path = driver.get('Path', '').lower()
            
            suspicious_driver = any(x in driver_path for x in [
                'temp\\', 'appdata\\', 'programdata\\', 'users\\'
            ])
            
            if suspicious_driver:
                findings.append({
                    'type': 'Rootkit',
                    'severity': 'CRITICAL',
                    'driver': driver_name,
                    'path': driver_path,
                    'method': 'Suspicious Driver Location',
                    'mitre': 'T1014',
                    'confidence': 85,
                    'description': f'Suspicious driver location: {driver_path}'
                })
            
            # Known rootkit signatures
            for sig in self.rootkit_signatures:
                if sig.lower() in driver_name or sig.lower() in driver_path:
                    findings.append({
                        'type': 'Rootkit',
                        'severity': 'CRITICAL',
                        'driver': driver_name,
                        'signature': sig,
                        'method': 'Rootkit Signature',
                        'mitre': 'T1014',
                        'confidence': 90,
                        'description': f'Rootkit signature detected: {sig}'
                    })
        
        # Check for hidden/unlisted processes (DKOM)
        process_pids = {proc.get('PID') for proc in processes if proc.get('PID') is not None}
        
        # Detect PID gaps (potential DKOM)
        if process_pids and len(process_pids) > 0:
            max_pid = max(process_pids)
            if max_pid and max_pid > 0:
                expected_count = max_pid // 4  # Rough estimate
                
                if len(process_pids) < expected_count * 0.7:  # 30% gap threshold
                    findings.append({
                        'type': 'Rootkit',
                        'severity': 'HIGH',
                        'method': 'Process Hiding (DKOM)',
                        'mitre': 'T1014',
                        'confidence': 70,
                        'description': 'Potential DKOM-based process hiding detected'
                    })
        
        return findings
