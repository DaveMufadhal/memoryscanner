from typing import Dict, List, Any, Optional

class AnalysisResult:
    """
    Container for analysis findings with MITRE ATT&CK mapping.
    """
    def __init__(self):
        self.suspicious_processes: List[Dict[str, Any]] = []
        self.suspicious_network: List[Dict[str, Any]] = []
        self.yara_matches: List[Dict[str, Any]] = []
        self.injected_code: List[Dict[str, Any]] = []
        self.credential_access: List[Dict[str, Any]] = []
        self.mitre_techniques: List[Dict[str, str]] = []
        self.score: int = 0
        self.risk_level: str = "LOW"
        self.summary: str = ""
        self.raw_outputs: Dict[str, Any] = {}

    def calculate_risk_level(self, thresholds: Dict[str, int]) -> None:
        """Calculate overall risk level based on score."""
        if self.score >= thresholds.get("critical_risk", 100):
            self.risk_level = "CRITICAL"
        elif self.score >= thresholds.get("high_risk", 50):
            self.risk_level = "HIGH"
        elif self.score >= thresholds.get("medium_risk", 30):
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"


def basic_process_analysis(
    pslist_output: Dict,
    config: Dict,
    result: AnalysisResult,
) -> None:
    """
    Enhanced process analysis with MITRE ATT&CK mapping.
    """
    if "error" in pslist_output:
        result.summary += f"[!] Error running pslist: {pslist_output['error']}\n"
        return
    
    detection_cfg = config.get("detection", {})
    suspicious_names = detection_cfg.get("suspicious_process_names", [])
    high_risk_processes = detection_cfg.get("high_risk_processes", [])
    
    processes = pslist_output if isinstance(pslist_output, list) else []
    
    for proc in processes:
        proc_name = proc.get("ImageFileName", "").lower()
        pid = proc.get("PID", 0)
        ppid = proc.get("PPID", 0)
        
        # Check for suspicious process names
        for sus_name in suspicious_names:
            if sus_name.lower() in proc_name:
                finding = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": proc_name,
                    "reason": f"Matches suspicious name pattern: {sus_name}",
                    "severity": "HIGH"
                }
                result.suspicious_processes.append(finding)
                result.score += 15
                
                # MITRE mapping for suspicious tools
                if "mimikatz" in proc_name or "procdump" in proc_name:
                    result.mitre_techniques.append({
                        "technique": "T1003",
                        "name": "Credential Dumping",
                        "description": f"Detected {proc_name} - known credential dumping tool"
                    })
                    result.credential_access.append(finding)
                
                if "powershell" in proc_name or "cmd.exe" in proc_name:
                    result.mitre_techniques.append({
                        "technique": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "description": f"Suspicious execution of {proc_name}"
                    })
        
        # Check for high-risk process access
        if "lsass.exe" in proc_name:
            # LSASS is often targeted for credential theft
            result.credential_access.append({
                "pid": pid,
                "ppid": ppid,
                "name": proc_name,
                "reason": "LSASS process detected - monitor for dumping attempts",
                "severity": "CRITICAL"
            })
            result.score += 5
        
        # Detect process injection indicators (suspicious parent-child relationships)
        if ppid == 0 and proc_name not in ["system", "idle", "registry"]:
            result.suspicious_processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": proc_name,
                "reason": "Suspicious PPID 0 - possible process hollowing",
                "severity": "HIGH"
            })
            result.score += 20
            result.mitre_techniques.append({
                "technique": "T1055",
                "name": "Process Injection",
                "description": f"Process {proc_name} has suspicious parent relationship"
            })


def basic_network_analysis(
    netscan_output: Dict,
    config: Dict,
    result: AnalysisResult,
) -> None:
    """
    Enhanced network analysis with C2 detection.
    """
    if "error" in netscan_output:
        result.summary += f"[!] Error running netscan: {netscan_output['error']}\n"
        return
    
    detection_cfg = config.get("detection", {})
    suspicious_ports = detection_cfg.get("suspicious_ports", [4444, 5555, 6666, 31337])
    
    connections = netscan_output if isinstance(netscan_output, list) else []
    
    for conn in connections:
        local_port = conn.get("LocalPort")
        foreign_addr = conn.get("ForeignAddr", "")
        foreign_port = conn.get("ForeignPort")
        state = conn.get("State", "")
        owner_pid = conn.get("PID", 0)
        
        # Flag suspicious ports (possible C2 communication)
        if local_port in suspicious_ports or foreign_port in suspicious_ports:
            finding = {
                "local_port": local_port,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "state": state,
                "pid": owner_pid,
                "reason": f"Suspicious port {local_port or foreign_port} detected - common C2 channel",
                "severity": "HIGH"
            }
            result.suspicious_network.append(finding)
            result.score += 25
            
            result.mitre_techniques.append({
                "technique": "T1071",
                "name": "Application Layer Protocol",
                "description": f"Suspicious network connection on port {local_port or foreign_port}"
            })
        
        # Flag established connections to non-standard ports
        if state == "ESTABLISHED" and foreign_port and foreign_port > 49152:
            result.suspicious_network.append({
                "local_port": local_port,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "state": state,
                "pid": owner_pid,
                "reason": "Connection to high ephemeral port - possible C2",
                "severity": "MEDIUM"
            })
            result.score += 10


def analyze_malfind(
    malfind_output: Dict,
    result: AnalysisResult,
) -> None:
    """
    Analyze memory sections for injected code.
    """
    if "error" in malfind_output:
        result.summary += f"[!] Error running malfind: {malfind_output['error']}\n"
        return
    
    injections = malfind_output if isinstance(malfind_output, list) else []
    
    for injection in injections:
        pid = injection.get("PID", 0)
        process = injection.get("Process", "")
        protection = injection.get("Protection", "")
        
        if "PAGE_EXECUTE" in protection:
            finding = {
                "pid": pid,
                "process": process,
                "protection": protection,
                "reason": "Executable memory region detected - possible code injection",
                "severity": "CRITICAL"
            }
            result.injected_code.append(finding)
            result.score += 30
            
            result.mitre_techniques.append({
                "technique": "T1055",
                "name": "Process Injection",
                "description": f"Code injection detected in {process} (PID: {pid})"
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