from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

class AnalysisResult:
    """Container for analysis results and findings."""
    
    def __init__(self):
        self.findings = []
        self.suspicious_processes = []
        self.suspicious_connections = []
        self.code_injections = []
        self.yara_matches = []
        self.mitre_techniques = []
        
        # ADD THESE: MITRE ATT&CK category containers
        self.credential_access = []
        self.defense_evasion = []
        self.discovery = []
        self.execution = []
        self.persistence = []
        self.privilege_escalation = []
        self.lateral_movement = []
        self.collection = []
        self.exfiltration = []
        self.command_and_control = []
        
        # ADD THESE: Missing attributes
        self.suspicious_network = []
        self.injected_code = []
        
        self.score = 0
        self.risk_level = "UNKNOWN"
        
        self.summary = {}
        self.statistics = {}
        
        # Raw outputs from Volatility plugins
        self.raw_outputs = {}
        
        # Parsed data storage
        self.parsed_data = {}
    
    def add_finding(self, severity: str, category: str, description: str, 
                    process_name: str = None, pid: int = None, 
                    mitre_technique: str = None) -> None:
        """Add a security finding to the analysis."""
        finding = {
            "severity": severity,
            "category": category,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        
        if process_name:
            finding["process_name"] = process_name
        if pid:
            finding["pid"] = pid
        if mitre_technique:
            finding["mitre_technique"] = mitre_technique
            # Also add to mitre_techniques list if not already present
            if not any(t.get('technique') == mitre_technique for t in self.mitre_techniques):
                self.mitre_techniques.append({
                    'technique': mitre_technique,
                    'name': category
                })
        
        self.findings.append(finding)
        
        # Increment score based on severity
        severity_scores = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 10,
            "LOW": 5,
            "INFO": 1
        }
        self.score += severity_scores.get(severity.upper(), 0)
    
    def calculate_risk_level(self, scoring_config: dict) -> None:
        """
        Determine overall risk level based on accumulated score.
        """
        critical = scoring_config.get("critical_risk", 100)
        high = scoring_config.get("high_risk", 50)
        medium = scoring_config.get("medium_risk", 30)
        low = scoring_config.get("low_risk", 10)
        
        if self.score >= critical:
            self.risk_level = "CRITICAL"
        elif self.score >= high:
            self.risk_level = "HIGH"
        elif self.score >= medium:
            self.risk_level = "MEDIUM"
        elif self.score >= low:
            self.risk_level = "LOW"
        else:
            self.risk_level = "CLEAN"


def basic_process_analysis(pslist_output: str, config: dict, result: AnalysisResult) -> None:
    """
    Analyze process list output from Volatility with context-aware detection.
    """
    # Store raw output
    result.parsed_data['pslist_raw'] = pslist_output
    
    detection_cfg = config.get("analysis", {})
    malware_tools = [x.lower() for x in detection_cfg.get("malware_tools", [])]
    remote_access_tools = [x.lower() for x in detection_cfg.get("remote_access_tools", [])]
    legitimate_processes = [x.lower() for x in detection_cfg.get("legitimate_processes", [])]
    suspicious_relations = detection_cfg.get("suspicious_parent_child", [])
    
    processes = pslist_output if isinstance(pslist_output, list) else []
    
    # Build process tree for parent-child analysis
    proc_map = {}
    for proc in processes:
        pid = proc.get("PID", 0)
        proc_map[pid] = proc
    
    for proc in processes:
        proc_name = proc.get("ImageFileName", "").lower()
        pid = proc.get("PID", 0)
        ppid = proc.get("PPID", 0)
        
        # Skip if whitelisted legitimate process
        if proc_name in legitimate_processes:
            continue
        
        # HIGH CONFIDENCE: Known malware tools
        for malware_name in malware_tools:
            if malware_name in proc_name:
                finding = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": proc_name,
                    "reason": f"Known malware/hacking tool detected: {proc_name}",
                    "severity": "CRITICAL"
                }
                result.suspicious_processes.append(finding)
                result.score += 30
                
                # MITRE mapping
                if "mimikatz" in proc_name or "dump" in proc_name:
                    result.mitre_techniques.append({
                        "technique": "T1003",
                        "name": "OS Credential Dumping",
                        "description": f"Detected {proc_name} - credential dumping tool"
                    })
                    result.credential_access.append(finding)
                break
        
        # MEDIUM CONFIDENCE: Remote access tools (check context)
        for rat_name in remote_access_tools:
            if rat_name in proc_name:
                parent_proc = proc_map.get(ppid, {})
                parent_name = parent_proc.get("ImageFileName", "").lower()
                
                # Flag if parent is suspicious
                if parent_name not in ["services.exe", "svchost.exe", "explorer.exe"]:
                    finding = {
                        "pid": pid,
                        "ppid": ppid,
                        "name": proc_name,
                        "reason": f"Remote access tool with suspicious parent: {parent_name}",
                        "severity": "HIGH"
                    }
                    result.suspicious_processes.append(finding)
                    result.score += 20
                break
        
        # CONTEXT-AWARE: Check parent-child relationships
        parent_proc = proc_map.get(ppid, {})
        parent_name = parent_proc.get("ImageFileName", "").lower()
        
        for relation in suspicious_relations:
            suspicious_parents = [x.lower() for x in relation.get("parent", [])]
            suspicious_children = [x.lower() for x in relation.get("child", [])]
            severity = relation.get("severity", "MEDIUM")
            
            # Check if current process matches suspicious parent-child pattern
            if parent_name in suspicious_parents and proc_name in suspicious_children:
                finding = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": proc_name,
                    "reason": f"Suspicious: {parent_name} spawned {proc_name} (possible code execution)",
                    "severity": severity
                }
                result.suspicious_processes.append(finding)
                
                score_map = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
                result.score += score_map.get(severity, 10)
                
                result.mitre_techniques.append({
                    "technique": "T1204",
                    "name": "User Execution",
                    "description": f"{parent_name} spawned {proc_name}"
                })
                break
        
        # ANOMALY: Process with PPID 0 (excluding system processes)
        if ppid == 0 and proc_name not in ["system", "idle", "registry", "[system process]"]:
            finding = {
                "pid": pid,
                "ppid": ppid,
                "name": proc_name,
                "reason": "Orphaned process (PPID=0) - possible process hollowing/injection",
                "severity": "HIGH"
            }
            result.suspicious_processes.append(finding)
            result.score += 25
            
            result.mitre_techniques.append({
                "technique": "T1055",
                "name": "Process Injection",
                "description": f"Orphaned process: {proc_name}"
            })


def basic_network_analysis(netscan_output: str, config: dict, result: AnalysisResult) -> None:
    """
    Analyze network connections from Volatility netscan with reduced false positives.
    """
    # Store raw output
    result.parsed_data['netscan_raw'] = netscan_output
    
    detection_cfg = config.get("analysis", {})
    suspicious_ports = detection_cfg.get("suspicious_ports", [4444, 5555, 6666, 31337, 1337])
    
    connections = netscan_output if isinstance(netscan_output, list) else []
    
    for conn in connections:
        local_port = conn.get("LocalPort")
        foreign_addr = conn.get("ForeignAddr", "")
        foreign_port = conn.get("ForeignPort")
        state = conn.get("State", "")
        owner_pid = conn.get("PID", 0)
        owner_process = conn.get("Owner", "").lower()
        
        # Skip localhost connections (not external threats)
        if foreign_addr in ["0.0.0.0", "127.0.0.1", "::", "::1", "*"]:
            continue
        
        # HIGH CONFIDENCE: Known malicious ports
        if local_port in suspicious_ports or foreign_port in suspicious_ports:
            finding = {
                "local_port": local_port,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "state": state,
                "pid": owner_pid,
                "process": owner_process,
                "reason": f"Connection on known malicious port {local_port or foreign_port} (Metasploit/RAT)",
                "severity": "CRITICAL"
            }
            result.suspicious_network.append(finding)
            result.score += 30
            
            result.mitre_techniques.append({
                "technique": "T1071",
                "name": "Application Layer Protocol",
                "description": f"Malicious port {local_port or foreign_port} used by PID {owner_pid}"
            })
        
        # MEDIUM CONFIDENCE: Non-browser using HTTP/HTTPS
        elif foreign_port in [80, 443] and state == "ESTABLISHED":
            # Only flag if NOT from a browser or update service
            if owner_process and not any(browser in owner_process for browser in ["chrome", "firefox", "iexplore", "msedge", "update", "svchost"]):
                finding = {
                    "local_port": local_port,
                    "foreign_addr": foreign_addr,
                    "foreign_port": foreign_port,
                    "state": state,
                    "pid": owner_pid,
                    "process": owner_process,
                    "reason": f"Non-browser process using HTTP/HTTPS: {owner_process}",
                    "severity": "MEDIUM"
                }
                result.suspicious_network.append(finding)
                result.score += 15


def analyze_malfind(malfind_output: str, result: AnalysisResult, config: dict = None) -> None:
    """
    Analyze malfind output for code injection indicators with whitelist filtering.
    """
    # Store raw output
    result.parsed_data['malfind_raw'] = malfind_output
    
    if config is None:
        config = {}
    
    detection_cfg = config.get("analysis", {})
    malfind_whitelist = [x.lower() for x in detection_cfg.get("malfind_whitelist", [])]
    
    injections = malfind_output if isinstance(malfind_output, list) else []
    
    for injection in injections:
        pid = injection.get("PID", 0)
        process = injection.get("Process", "").lower()
        protection = injection.get("Protection", "")
        
        # Skip whitelisted legitimate processes that commonly have RWX memory
        if any(whitelist_proc in process for whitelist_proc in malfind_whitelist):
            continue
        
        # Only flag PAGE_EXECUTE_READWRITE which is highly suspicious
        # (legitimate processes use PAGE_EXECUTE_READ for code sections)
        if "PAGE_EXECUTE_READWRITE" in protection:
            finding = {
                "pid": pid,
                "process": process,
                "protection": protection,
                "reason": "PAGE_EXECUTE_READWRITE memory in non-whitelisted process - likely code injection",
                "severity": "HIGH"
            }
            result.injected_code.append(finding)
            result.score += 25
            
            result.mitre_techniques.append({
                "technique": "T1055",
                "name": "Process Injection",
                "description": f"Suspicious executable memory in {process} (PID: {pid})"
            })


def generate_summary(result: AnalysisResult, config: Dict) -> None:
    """
    Generate executive summary of findings.
    """
    summary_lines = []
    
    if result.score == 0:
        summary_lines.append("✓ No significant suspicious activity detected.")
    else:
        summary_lines.append(f"⚠ RISK LEVEL: {result.risk_level}")
        summary_lines.append(f"Total Risk Score: {result.score}")
        summary_lines.append("")
        
        if result.credential_access:
            summary_lines.append(f"🔴 Credential Access Activity: {len(result.credential_access)} findings")
        
        if result.injected_code:
            summary_lines.append(f"🔴 Code Injection Detected: {len(result.injected_code)} instances")
        
        if result.suspicious_processes:
            summary_lines.append(f"⚠ Suspicious Processes: {len(result.suspicious_processes)}")
        
        if result.suspicious_network:
            summary_lines.append(f"⚠ Suspicious Network Connections: {len(result.suspicious_network)}")
        
        if result.mitre_techniques:
            summary_lines.append("")
            summary_lines.append("MITRE ATT&CK Techniques Detected:")
            unique_techniques = {t['technique']: t for t in result.mitre_techniques}
            for tech_id, tech in unique_techniques.items():
                summary_lines.append(f"  - {tech_id}: {tech['name']}")
    
    result.summary = "\n".join(summary_lines)