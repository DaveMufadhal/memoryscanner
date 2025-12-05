"""
Advanced Detection Engine Enhancements
Implements behavioral analysis, LOLBin detection, entropy analysis, and statistical baselines
"""

from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import re
import math


class EnhancedDetectionEngine:
    """
    Advanced detection engine with behavioral analysis and statistical baselines.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.detection_cfg = config.get("detection_engine", {})
        
        # LOLBins (Living Off the Land Binaries) database
        self.lolbins = self._load_lolbins_database()
        
        # Statistical baselines for normal system behavior
        self.baselines = self._initialize_baselines()
        
        # Known mutex patterns (malware families)
        self.malware_mutex_patterns = self._load_malware_mutex_patterns()
        
        # API hook indicators
        self.hooked_apis = [
            "NtCreateFile", "NtReadFile", "NtWriteFile",
            "NtCreateProcess", "NtOpenProcess", "NtTerminateProcess",
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "NtSetContextThread", "NtGetContextThread",
            "NtResumeThread", "NtSuspendThread",
            "GetProcAddress", "LoadLibraryA", "CreateRemoteThread"
        ]
    
    def _load_lolbins_database(self) -> Dict[str, Dict]:
        """
        Load Living Off the Land Binaries (LOLBins) database.
        These are legitimate Windows binaries that can be abused by attackers.
        """
        return {
            # Script Execution
            "powershell.exe": {
                "category": "Script Execution",
                "legitimate_use": "System administration, scripting",
                "abuse_indicators": [
                    r"-enc(odedcommand)?",
                    r"-e\s+[A-Za-z0-9+/=]+",
                    r"invoke-expression",
                    r"iex",
                    r"downloadstring",
                    r"webclient",
                    r"-w(indowstyle)?\s+hidden",
                    r"-nop",
                    r"bypass",
                    r"unrestricted"
                ],
                "suspicious_parents": ["winword.exe", "excel.exe", "outlook.exe", 
                                      "acrord32.exe", "iexplore.exe", "chrome.exe"],
                "mitre": "T1059.001"
            },
            "cmd.exe": {
                "category": "Script Execution",
                "legitimate_use": "Command line interface",
                "abuse_indicators": [
                    r"/c\s+echo",
                    r"/c\s+powershell",
                    r"/c\s+certutil",
                    r"/c\s+bitsadmin",
                    r"&&",
                    r"\|\|",
                    r"^\s*@"
                ],
                "suspicious_parents": ["winword.exe", "excel.exe", "outlook.exe", 
                                      "acrord32.exe", "iexplore.exe", "chrome.exe"],
                "mitre": "T1059.003"
            },
            "wscript.exe": {
                "category": "Script Execution",
                "legitimate_use": "Windows Script Host",
                "abuse_indicators": [r"\.vbs", r"\.js", r"\.wsf"],
                "suspicious_parents": ["winword.exe", "excel.exe", "outlook.exe"],
                "mitre": "T1059.005"
            },
            "cscript.exe": {
                "category": "Script Execution",
                "legitimate_use": "Windows Script Host (console)",
                "abuse_indicators": [r"\.vbs", r"\.js", r"\.wsf"],
                "suspicious_parents": ["winword.exe", "excel.exe", "outlook.exe"],
                "mitre": "T1059.005"
            },
            "mshta.exe": {
                "category": "Script Execution",
                "legitimate_use": "HTML Application Host",
                "abuse_indicators": [r"http", r"javascript:", r"vbscript:"],
                "suspicious_parents": ["*"],  # Always suspicious
                "mitre": "T1218.005"
            },
            
            # File Download
            "certutil.exe": {
                "category": "File Download",
                "legitimate_use": "Certificate management",
                "abuse_indicators": [
                    r"-urlcache",
                    r"-split",
                    r"-f",
                    r"http"
                ],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1105"
            },
            "bitsadmin.exe": {
                "category": "File Download",
                "legitimate_use": "Background Intelligent Transfer Service",
                "abuse_indicators": [
                    r"/transfer",
                    r"/download",
                    r"http"
                ],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1105"
            },
            
            # Process Manipulation
            "rundll32.exe": {
                "category": "Process Manipulation",
                "legitimate_use": "Run DLL functions",
                "abuse_indicators": [
                    r"javascript:",
                    r"vbscript:",
                    r"http",
                    r"\.txt",
                    r"\.log",
                    r"comsvcs\.dll.*minidump"
                ],
                "suspicious_parents": ["*"],
                "mitre": "T1218.011"
            },
            "regsvr32.exe": {
                "category": "Process Manipulation",
                "legitimate_use": "Register DLLs",
                "abuse_indicators": [
                    r"/s",
                    r"/i:http",
                    r"scrobj\.dll"
                ],
                "suspicious_parents": ["*"],
                "mitre": "T1218.010"
            },
            
            # Credential Access
            "reg.exe": {
                "category": "Credential Access",
                "legitimate_use": "Registry operations",
                "abuse_indicators": [
                    r"save.*sam",
                    r"save.*system",
                    r"save.*security",
                    r"query.*currentversion\\\\run"
                ],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1003.002"
            },
            
            # Reconnaissance
            "net.exe": {
                "category": "Reconnaissance",
                "legitimate_use": "Network commands",
                "abuse_indicators": [
                    r"net\s+(user|group|localgroup)",
                    r"net\s+view",
                    r"net\s+share"
                ],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1087"
            },
            "whoami.exe": {
                "category": "Reconnaissance",
                "legitimate_use": "Display user information",
                "abuse_indicators": [r"/all", r"/priv", r"/groups"],
                "suspicious_parents": ["*"],
                "mitre": "T1033"
            },
            "tasklist.exe": {
                "category": "Reconnaissance",
                "legitimate_use": "List processes",
                "abuse_indicators": [r"/v", r"/svc"],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1057"
            },
            "systeminfo.exe": {
                "category": "Reconnaissance",
                "legitimate_use": "System information",
                "abuse_indicators": ["*"],
                "suspicious_parents": ["cmd.exe", "powershell.exe"],
                "mitre": "T1082"
            }
        }
    
    def _initialize_baselines(self) -> Dict[str, Dict]:
        """
        Initialize statistical baselines for normal system behavior.
        """
        return {
            "process_counts": {
                "svchost.exe": {"min": 5, "max": 25, "typical": 12},
                "explorer.exe": {"min": 1, "max": 3, "typical": 1},
                "chrome.exe": {"min": 0, "max": 50, "typical": 10},
                "firefox.exe": {"min": 0, "max": 30, "typical": 8},
            },
            "thread_counts": {
                "explorer.exe": {"min": 10, "max": 60, "typical": 35},
                "svchost.exe": {"min": 2, "max": 50, "typical": 15},
                "system": {"min": 50, "max": 150, "typical": 80},
            },
            "handle_counts": {
                "explorer.exe": {"min": 200, "max": 1500, "typical": 800},
                "svchost.exe": {"min": 50, "max": 800, "typical": 300},
                "chrome.exe": {"min": 100, "max": 5000, "typical": 1000},
            },
            "network_ports": {
                "established_typical": {"min": 5, "max": 100, "typical": 30},
                "listening_typical": {"min": 10, "max": 50, "typical": 25},
            }
        }
    
    def _load_malware_mutex_patterns(self) -> List[Dict]:
        """
        Load known malware mutex patterns.
        Mutexes are used by malware to ensure single instance execution.
        """
        return [
            {"pattern": r"^[A-F0-9]{32}$", "description": "MD5-like mutex (generic malware)"},
            {"pattern": r"^[A-F0-9]{40}$", "description": "SHA1-like mutex (generic malware)"},
            {"pattern": r"^Global\\\\[A-F0-9]{8,}$", "description": "Global random mutex"},
            {"pattern": r"^Local\\\\[A-F0-9]{8,}$", "description": "Local random mutex"},
            {"pattern": r"(?i)carbanak", "description": "Carbanak banking trojan"},
            {"pattern": r"(?i)emotet", "description": "Emotet malware"},
            {"pattern": r"(?i)trickbot", "description": "TrickBot malware"},
            {"pattern": r"(?i)ryuk", "description": "Ryuk ransomware"},
            {"pattern": r"(?i)wannacry", "description": "WannaCry ransomware"},
            {"pattern": r"(?i)petya", "description": "Petya/NotPetya ransomware"},
            {"pattern": r"(?i)mimikatz", "description": "Mimikatz credential dumper"},
            {"pattern": r"3749282D-C8XX-", "description": "Cobalt Strike beacon"},
            {"pattern": r"(?i)BIOMUTEX", "description": "Generic malware mutex"},
        ]
    
    def detect_lolbin_abuse(self, process: Dict, command_line: str, 
                           parent_name: str) -> Optional[Dict]:
        """
        Detect abuse of Living Off the Land Binaries (LOLBins).
        
        Returns finding if abuse is detected, None otherwise.
        """
        proc_name = process.get("ImageFileName", "").lower()
        
        if proc_name not in self.lolbins:
            return None
        
        lolbin_info = self.lolbins[proc_name]
        abuse_score = 0
        indicators = []
        
        # Check command line for abuse indicators
        if command_line:
            for indicator in lolbin_info.get("abuse_indicators", []):
                if re.search(indicator, command_line, re.IGNORECASE):
                    abuse_score += 10
                    indicators.append(f"Command pattern: {indicator}")
        
        # Check parent process
        suspicious_parents = lolbin_info.get("suspicious_parents", [])
        if "*" in suspicious_parents or parent_name.lower() in [p.lower() for p in suspicious_parents]:
            abuse_score += 15
            indicators.append(f"Suspicious parent: {parent_name}")
        
        # Determine if this is abuse
        if abuse_score >= 10:
            return {
                "pid": process.get("PID", 0),
                "process": proc_name,
                "category": lolbin_info["category"],
                "parent": parent_name,
                "command_line": command_line,
                "indicators": indicators,
                "abuse_score": abuse_score,
                "mitre": lolbin_info.get("mitre", "T1218"),
                "severity": "HIGH" if abuse_score >= 20 else "MEDIUM",
                "reason": f"LOLBin abuse detected: {proc_name} ({lolbin_info['category']})"
            }
        
        return None
    
    def analyze_process_entropy(self, hexdump: str, disasm: str) -> Dict:
        """
        Calculate Shannon entropy of process memory to detect packed/obfuscated code.
        High entropy (>7.0) indicates encryption/packing.
        """
        if not hexdump:
            return {"entropy": 0.0, "is_packed": False}
        
        # Extract hex bytes
        hex_bytes = re.findall(r'[0-9a-f]{2}', hexdump.lower())
        
        if len(hex_bytes) < 100:  # Need sufficient data
            return {"entropy": 0.0, "is_packed": False}
        
        # Calculate Shannon entropy
        byte_counts = defaultdict(int)
        for byte in hex_bytes:
            byte_counts[byte] += 1
        
        total_bytes = len(hex_bytes)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Analyze characteristics
        is_packed = entropy > 7.0
        is_encrypted = entropy > 7.5
        has_high_randomness = entropy > 7.8
        
        # Check for common packing signatures
        packer_signatures = {
            "UPX": b"UPX!",
            "ASPack": b"ASPack",
            "PECompact": b"PECompact",
            "Themida": b"Themida",
            "VMProtect": b"VMProtect",
        }
        
        detected_packer = None
        hexdump_bytes = hexdump.encode('latin1', errors='ignore')
        for packer, signature in packer_signatures.items():
            if signature in hexdump_bytes:
                detected_packer = packer
                break
        
        return {
            "entropy": round(entropy, 3),
            "is_packed": is_packed,
            "is_encrypted": is_encrypted,
            "has_high_randomness": has_high_randomness,
            "detected_packer": detected_packer,
            "severity": "HIGH" if is_packed else "LOW"
        }
    
    def detect_statistical_anomalies(self, processes: List[Dict]) -> List[Dict]:
        """
        Detect statistical anomalies by comparing against normal baselines.
        """
        anomalies = []
        
        # Count process instances
        process_counts = defaultdict(int)
        for proc in processes:
            proc_name = proc.get("ImageFileName", "").lower()
            process_counts[proc_name] += 1
        
        # Check against baselines
        for proc_name, count in process_counts.items():
            if proc_name in self.baselines["process_counts"]:
                baseline = self.baselines["process_counts"][proc_name]
                
                if count < baseline["min"] or count > baseline["max"]:
                    anomalies.append({
                        "type": "process_count_anomaly",
                        "process": proc_name,
                        "observed": count,
                        "expected_range": f"{baseline['min']}-{baseline['max']}",
                        "typical": baseline["typical"],
                        "severity": "MEDIUM" if count > baseline["max"] else "LOW",
                        "reason": f"Abnormal instance count for {proc_name}: {count} (expected {baseline['min']}-{baseline['max']})"
                    })
        
        # Check individual process attributes
        for proc in processes:
            proc_name = proc.get("ImageFileName", "").lower()
            threads = proc.get("Threads", 0)
            handles = proc.get("Handles", 0)
            
            # Thread count anomalies
            if proc_name in self.baselines["thread_counts"]:
                baseline = self.baselines["thread_counts"][proc_name]
                if threads > baseline["max"]:
                    anomalies.append({
                        "type": "thread_count_anomaly",
                        "pid": proc.get("PID", 0),
                        "process": proc_name,
                        "observed": threads,
                        "max_expected": baseline["max"],
                        "severity": "MEDIUM",
                        "reason": f"Excessive threads in {proc_name}: {threads} (max expected {baseline['max']})"
                    })
            
            # Handle count anomalies
            if proc_name in self.baselines["handle_counts"]:
                baseline = self.baselines["handle_counts"][proc_name]
                if handles > baseline["max"]:
                    anomalies.append({
                        "type": "handle_count_anomaly",
                        "pid": proc.get("PID", 0),
                        "process": proc_name,
                        "observed": handles,
                        "max_expected": baseline["max"],
                        "severity": "MEDIUM",
                        "reason": f"Excessive handles in {proc_name}: {handles} (max expected {baseline['max']})"
                    })
        
        return anomalies
    
    def detect_mutex_artifacts(self, handles: List[Dict]) -> List[Dict]:
        """
        Analyze handles for malware mutex patterns.
        """
        findings = []
        
        for handle in handles:
            handle_type = handle.get("HandleType", "")
            handle_name = handle.get("HandleValue", "")
            
            if handle_type != "Mutant" or not handle_name:
                continue
            
            # Check against known malware mutex patterns
            for mutex_pattern in self.malware_mutex_patterns:
                if re.search(mutex_pattern["pattern"], str(handle_name)):
                    findings.append({
                        "type": "malware_mutex",
                        "pid": handle.get("PID", 0),
                        "process": handle.get("Process", ""),
                        "mutex_name": handle_name,
                        "description": mutex_pattern["description"],
                        "severity": "HIGH",
                        "reason": f"Known malware mutex pattern: {mutex_pattern['description']}",
                        "mitre": "T1106"
                    })
                    break
        
        return findings
    
    def detect_hollowed_process(self, process: Dict, vad_info: List[Dict]) -> Optional[Dict]:
        """
        Detect process hollowing by analyzing VAD characteristics.
        
        Indicators:
        - Executable memory not backed by file
        - Mismatched image base addresses
        - Suspicious memory protection changes
        """
        proc_name = process.get("ImageFileName", "").lower()
        pid = process.get("PID", 0)
        
        # Count characteristics
        unbacked_exec = 0
        rwx_regions = 0
        private_exec = 0
        
        for vad in vad_info:
            if vad.get("PID") != pid:
                continue
            
            protection = vad.get("Protection", "")
            private_mem = vad.get("PrivateMemory", 0)
            tag = vad.get("Tag", "")
            
            if "EXECUTE" in protection:
                if private_mem == 1:
                    unbacked_exec += 1
                    private_exec += 1
                
                if "READ" in protection and "WRITE" in protection:
                    rwx_regions += 1
        
        # Determine if hollowed
        hollow_score = 0
        indicators = []
        
        if unbacked_exec >= 2:
            hollow_score += 30
            indicators.append(f"{unbacked_exec} unbacked executable regions")
        
        if rwx_regions >= 1:
            hollow_score += 20
            indicators.append(f"{rwx_regions} RWX memory regions")
        
        if private_exec >= 3:
            hollow_score += 25
            indicators.append(f"{private_exec} private executable regions")
        
        if hollow_score >= 40:
            return {
                "type": "process_hollowing",
                "pid": pid,
                "process": proc_name,
                "hollow_score": hollow_score,
                "indicators": indicators,
                "unbacked_exec": unbacked_exec,
                "rwx_regions": rwx_regions,
                "private_exec": private_exec,
                "severity": "CRITICAL" if hollow_score >= 60 else "HIGH",
                "reason": f"Process hollowing detected in {proc_name}",
                "mitre": "T1055.012"
            }
        
        return None
    
    def detect_api_hooks(self, malfind_output: List[Dict]) -> List[Dict]:
        """
        Detect API hooks by analyzing memory for hook patterns.
        
        Common hook patterns:
        - JMP instructions at API entry points
        - Modified function prologues
        - Inline patches
        """
        findings = []
        
        for region in malfind_output:
            disasm = region.get("Disasm", "").lower()
            hexdump = region.get("Hexdump", "").lower()
            
            if not disasm:
                continue
            
            # Check for common hook patterns
            hook_patterns = [
                {"pattern": r"^(e9|eb|ff 25)", "desc": "JMP hook (inline redirect)"},
                {"pattern": r"^(48 b8|48 bb).*ff e[0-3]", "desc": "MOV+JMP hook (x64)"},
                {"pattern": r"^(c7 [0-4][0-5]).*c3", "desc": "Inline patch with RET"},
                {"pattern": r"^(90{5,})", "desc": "NOP sled (function replaced)"},
            ]
            
            for hook_pattern in hook_patterns:
                if re.search(hook_pattern["pattern"], hexdump.replace(" ", "")):
                    findings.append({
                        "type": "api_hook",
                        "pid": region.get("PID", 0),
                        "process": region.get("Process", ""),
                        "address": hex(region.get("Start VPN", 0)),
                        "hook_type": hook_pattern["desc"],
                        "severity": "HIGH",
                        "reason": f"API hook detected: {hook_pattern['desc']}",
                        "mitre": "T1056.004"
                    })
                    break
        
        return findings
    
    def analyze_behavioral_patterns(self, processes: List[Dict], 
                                   cmdlines: List[Dict],
                                   network: List[Dict]) -> Dict:
        """
        Comprehensive behavioral analysis across multiple data sources.
        """
        behavior_analysis = {
            "persistence_attempts": [],
            "lateral_movement": [],
            "data_staging": [],
            "credential_access": [],
            "defense_evasion": [],
        }
        
        # Build process-cmdline map
        cmdline_map = {}
        for cmd in cmdlines:
            cmdline_map[cmd.get("PID", 0)] = cmd.get("Args", "")
        
        for proc in processes:
            pid = proc.get("PID", 0)
            proc_name = proc.get("ImageFileName", "").lower()
            cmdline = cmdline_map.get(pid, "").lower()
            
            # Detect persistence attempts
            if "schtasks" in proc_name or "at.exe" in proc_name:
                behavior_analysis["persistence_attempts"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": "Scheduled Task",
                    "mitre": "T1053"
                })
            
            if "sc.exe" in proc_name and ("create" in cmdline or "config" in cmdline):
                behavior_analysis["persistence_attempts"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": "Service Creation",
                    "mitre": "T1543.003"
                })
            
            # Detect lateral movement
            if proc_name in ["psexec.exe", "wmic.exe", "winrs.exe"]:
                behavior_analysis["lateral_movement"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": proc_name.replace(".exe", "").upper(),
                    "mitre": "T1021"
                })
            
            # Detect data staging
            if "7z" in proc_name or "winrar" in proc_name or "zip" in cmdline:
                behavior_analysis["data_staging"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": "Archive Creation",
                    "mitre": "T1560"
                })
            
            # Detect credential access
            if "procdump" in proc_name or "mimikatz" in proc_name:
                behavior_analysis["credential_access"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": "Credential Dumping Tool",
                    "mitre": "T1003"
                })
            
            # Detect defense evasion
            if "taskkill" in proc_name and ("av" in cmdline or "defender" in cmdline):
                behavior_analysis["defense_evasion"].append({
                    "pid": pid,
                    "process": proc_name,
                    "method": "AV Termination",
                    "mitre": "T1562.001"
                })
        
        return behavior_analysis
