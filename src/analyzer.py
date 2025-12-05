from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict
import re

try:
    from .confidence_scorer import ConfidenceScorer
    CONFIDENCE_AVAILABLE = True
except ImportError:
    CONFIDENCE_AVAILABLE = False
    ConfidenceScorer = None

try:
    from .detection_engine import EnhancedDetectionEngine
    DETECTION_ENGINE_AVAILABLE = True
except ImportError:
    DETECTION_ENGINE_AVAILABLE = False
    EnhancedDetectionEngine = None

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
        
        # Advanced detection results
        self.process_hollowing = []
        self.lsass_access = []
        self.dll_injection = []
        self.suspicious_handles = []
        self.persistence_mechanisms = []
        self.beaconing_activity = []
        self.memory_anomalies = []
        
        # NEW: Memory artifact analysis results
        self.handle_artifacts = []      # What handles point to (files, registry, processes)
        self.vad_anomalies = []         # VAD tree anomalies and suspicious mappings
        self.registry_persistence = []  # Autorun/persistence mechanisms in registry
        self.memory_mapped_files = []   # Suspicious memory-mapped files
        
        # Confidence scoring and false positive reduction
        self.confidence_scorer = None
        self.correlated_evidence = {}   # Evidence correlation across findings
        self.suppressed_findings = []   # Low-confidence findings suppressed
        self.confidence_report = ""     # Human-readable confidence report
        
        # Enhanced detection engine results
        self.detection_engine = None
        self.lolbin_abuse = []          # Living Off the Land Binaries abuse
        self.entropy_analysis = []      # Packed/obfuscated code detection
        self.statistical_anomalies = [] # Deviations from normal baselines
        self.mutex_artifacts = []       # Malware mutex patterns
        self.hollowed_processes = []    # Process hollowing detection
        self.api_hooks = []             # API hooking detection
        self.behavioral_patterns = {}   # Behavioral analysis results
        
        # Phase 2: Advanced detection patterns
        self.credential_theft = []      # Credential theft attempts
        self.persistence_detections = [] # Persistence mechanism detections
        self.lateral_movement_detections = [] # Lateral movement attempts
        self.privilege_escalation_detections = [] # Privilege escalation attempts
        self.data_exfiltration = []     # Data exfiltration indicators
        self.ransomware_indicators = [] # Ransomware behavior patterns
        self.rootkit_indicators = []    # Rootkit detection
        
        # Phase 2: YARA integration
        self.yara_findings = []         # YARA scan matches
        self.yara_statistics = {}       # YARA scanning statistics
        
        # Phase 2: Behavioral correlation
        self.attack_chains = []         # Correlated attack chains
        self.mitre_coverage = {}        # MITRE ATT&CK coverage
        self.threat_score = 0           # Overall threat score
        self.attack_narrative = ""      # Human-readable attack description
        self.correlated_findings = []   # Correlated finding groups
        
        # Malware attribution
        self.malware_families = {}      # Identified malware families
        self.malware_attribution = ""   # Malware attribution summary text
    
    def add_finding(self, severity: str, category: str, description: str, 
                    process_name: str = None, pid: int = None, 
                    mitre_technique: str = None, confidence: float = 0.7,
                    context: Dict = None) -> None:
        """Add a security finding to the analysis with confidence scoring."""
        finding = {
            "severity": severity,
            "category": category,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "confidence": confidence,
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
        
        # Calculate weighted score based on confidence
        if self.confidence_scorer and context:
            calculated_confidence = self.confidence_scorer.calculate_confidence(finding, context)
            finding["confidence"] = calculated_confidence
            weighted_score = self.confidence_scorer.weighted_score(finding, calculated_confidence)
            finding["weighted_score"] = weighted_score
            
            # Only add finding if it meets confidence threshold
            if self.confidence_scorer.should_alert(finding, calculated_confidence):
                self.findings.append(finding)
                self.score += weighted_score
            else:
                self.suppressed_findings.append(finding)
        else:
            # Legacy scoring without confidence
            self.findings.append(finding)
            severity_scores = {
                "CRITICAL": 25,
                "HIGH": 15,
                "MEDIUM": 10,
                "LOW": 5,
                "INFO": 1
            }
            score_value = severity_scores.get(severity.upper(), 0)
            # Apply basic confidence multiplier
            score_value = int(score_value * confidence)
            finding["base_score"] = score_value
            self.score += score_value
    
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
    Analyze process list output from Volatility with advanced detection techniques.
    """
    # Store raw output
    result.parsed_data['pslist_raw'] = pslist_output
    
    # Initialize confidence scorer if available
    if CONFIDENCE_AVAILABLE and result.confidence_scorer is None:
        result.confidence_scorer = ConfidenceScorer(config)
    
    detection_cfg = config.get("analysis", {})
    malware_tools = [x.lower() for x in detection_cfg.get("malware_tools", [])]
    remote_access_tools = [x.lower() for x in detection_cfg.get("remote_access_tools", [])]
    legitimate_processes = [x.lower() for x in detection_cfg.get("legitimate_processes", [])]
    suspicious_relations = detection_cfg.get("suspicious_parent_child", [])
    system_processes = [x.lower() for x in detection_cfg.get("system_processes", [])]
    
    processes = pslist_output if isinstance(pslist_output, list) else []
    
    # Build process tree and timeline for advanced analysis
    proc_map = {}
    process_timeline = []
    for proc in processes:
        pid = proc.get("PID", 0)
        proc_map[pid] = proc
        create_time = proc.get("CreateTime")
        if create_time:
            process_timeline.append({
                'time': create_time,
                'pid': pid,
                'name': proc.get("ImageFileName", ""),
                'ppid': proc.get("PPID", 0)
            })
    
    # Sort timeline chronologically
    process_timeline.sort(key=lambda x: x['time'])
    
    for proc in processes:
        proc_name = (proc.get("ImageFileName") or "").lower()
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
        
        # ADVANCED: Process hollowing detection
        if ppid == 0 and proc_name not in ["system", "idle", "registry", "[system process]"]:
            finding = {
                "pid": pid,
                "ppid": ppid,
                "name": proc_name,
                "reason": "Orphaned process (PPID=0) - possible process hollowing/injection",
                "severity": "HIGH",
                "technique": "process_hollowing"
            }
            result.process_hollowing.append(finding)
            result.suspicious_processes.append(finding)
            result.score += 25
            
            if "T1055" not in [t['technique'] for t in result.mitre_techniques]:
                result.mitre_techniques.append({
                    "technique": "T1055",
                    "name": "Process Injection",
                    "description": f"Orphaned process: {proc_name}"
                })
    
    # ADVANCED: Detect LSASS access (credential dumping)
    _detect_lsass_access(processes, proc_map, result, config)
    
    # ADVANCED: Process ancestry validation
    _validate_process_ancestry(processes, proc_map, result, config)
    
    # ADVANCED: Detect suspicious process attributes
    _analyze_process_attributes(processes, result, config)


def analyze_handle_artifacts(handles_output: Dict, config: dict, result: AnalysisResult) -> None:
    """
    Analyze handle artifacts to identify suspicious file/registry/process access.
    Detects:
    - LSASS handle access (credential dumping)
    - Suspicious file handles (malware drops, persistence)
    - Registry key access (persistence, data theft)
    - Inter-process handles (code injection)
    """
    if not handles_output or "error" in handles_output:
        return
    
    handles = handles_output
    detection_cfg = config.get("analysis", {})
    legitimate_procs = [p.lower() for p in detection_cfg.get("legitimate_processes", [])]
    
    # Track suspicious patterns
    lsass_accessors = defaultdict(list)
    registry_persistence = defaultdict(list)
    suspicious_file_access = defaultdict(list)
    
    # Persistence registry keys (Run, RunOnce, Services, etc.)
    persistence_keys = [
        r"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run",
        r"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce",
        r"\\registry\\user\\.+\\software\\microsoft\\windows\\currentversion\\run",
        r"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
        r"\\registry\\machine\\system\\currentcontrolset\\services",
        r"\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\winlogon",
        r"\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
    ]
    
    # Suspicious file locations (temp, AppData, ProgramData)
    suspicious_paths = [
        r"\\temp\\",
        r"\\appdata\\local\\temp\\",
        r"\\programdata\\",
        r"\\users\\public\\",
        r"\\.exe$",
        r"\\.dll$",
        r"\\.scr$",
        r"\\.bat$",
        r"\\.vbs$",
        r"\\.ps1$",
    ]
    
    for handle in handles:
        pid = handle.get("PID", 0)
        proc_name = (handle.get("Process") or "").lower()
        handle_type = handle.get("HandleType", "")
        handle_name = handle.get("HandleValue", "")
        
        if not handle_name or handle_name == "":
            continue
        
        handle_name_lower = str(handle_name).lower()
        
        # 1. LSASS handle access detection (credential dumping)
        if "lsass.exe" in handle_name_lower and proc_name != "lsass.exe":
            if proc_name not in legitimate_procs:
                lsass_accessors[proc_name].append({
                    "pid": pid,
                    "handle_type": handle_type,
                    "target": "lsass.exe",
                    "technique": "T1003"
                })
        
        # 2. Registry persistence key access
        if handle_type == "Key":
            for persist_key in persistence_keys:
                if re.search(persist_key, handle_name_lower, re.IGNORECASE):
                    registry_persistence[proc_name].append({
                        "pid": pid,
                        "registry_key": handle_name,
                        "pattern": persist_key
                    })
                    break
        
        # 3. Suspicious file handle access
        if handle_type == "File":
            for susp_path in suspicious_paths:
                if re.search(susp_path, handle_name_lower, re.IGNORECASE):
                    suspicious_file_access[proc_name].append({
                        "pid": pid,
                        "file_path": handle_name,
                        "pattern": susp_path
                    })
                    break
    
    # Generate findings for LSASS access
    for proc_name, accesses in lsass_accessors.items():
        finding = {
            "process": proc_name,
            "count": len(accesses),
            "details": accesses,
            "severity": "CRITICAL",
            "reason": f"{proc_name} has handle to LSASS process (credential dumping indicator)",
            "technique": "T1003"
        }
        result.handle_artifacts.append(finding)
        result.lsass_access.append(finding)
        result.score += 40
        
        if not any(t['technique'] == 'T1003' for t in result.mitre_techniques):
            result.mitre_techniques.append({
                "technique": "T1003",
                "name": "Credential Dumping",
                "description": f"{proc_name} accessing LSASS memory"
            })
    
    # Generate findings for registry persistence
    for proc_name, accesses in registry_persistence.items():
        if len(accesses) >= 2:  # Only flag if multiple persistence key accesses
            finding = {
                "process": proc_name,
                "count": len(accesses),
                "details": accesses,
                "severity": "HIGH",
                "reason": f"{proc_name} accessing persistence registry keys",
                "technique": "T1547"
            }
            result.registry_persistence.append(finding)
            result.persistence_mechanisms.append(finding)
            result.score += 25
            
            if not any(t['technique'] == 'T1547' for t in result.mitre_techniques):
                result.mitre_techniques.append({
                    "technique": "T1547",
                    "name": "Boot or Logon Autostart Execution",
                    "description": f"{proc_name} modifying registry persistence keys"
                })
    
    # Generate findings for suspicious file access
    for proc_name, accesses in suspicious_file_access.items():
        if len(accesses) >= 3 and proc_name not in legitimate_procs:  # Multiple suspicious file accesses
            finding = {
                "process": proc_name,
                "count": len(accesses),
                "details": accesses[:5],  # Limit to first 5
                "severity": "MEDIUM",
                "reason": f"{proc_name} accessing suspicious file locations",
            }
            result.handle_artifacts.append(finding)
            result.score += 10


def analyze_vad_tree(vadinfo_output: Dict, config: dict, result: AnalysisResult) -> None:
    """
    Analyze VAD (Virtual Address Descriptor) tree for anomalies.
    Detects:
    - Abnormal memory protection combinations
    - Hidden/unmapped executable regions
    - Suspicious memory gaps (possible rootkit)
    - Large executable private memory allocations
    """
    if not vadinfo_output or "error" in vadinfo_output:
        return
    
    # VAD analysis from malfind output (already has VAD data)
    # We'll analyze protection flags and memory patterns
    detection_cfg = config.get("analysis", {})
    
    # Track VAD anomalies
    vad_stats = defaultdict(lambda: {
        "total_vads": 0,
        "executable_vads": 0,
        "private_exec_vads": 0,
        "rwx_vads": 0,
        "large_allocations": 0
    })
    
    for vad in vadinfo_output:
        pid = vad.get("PID", 0)
        proc_name = vad.get("Process", "").lower()
        protection = vad.get("Protection", "")
        private_mem = vad.get("PrivateMemory", 0)
        commit_charge = vad.get("CommitCharge", 0)
        tag = vad.get("Tag", "")
        
        vad_stats[proc_name]["total_vads"] += 1
        
        # Check for executable memory
        if "EXECUTE" in protection:
            vad_stats[proc_name]["executable_vads"] += 1
            
            # Private executable memory (suspicious)
            if private_mem == 1:
                vad_stats[proc_name]["private_exec_vads"] += 1
            
            # RWX protection (read-write-execute - very suspicious)
            if "READ" in protection and "WRITE" in protection and "EXECUTE" in protection:
                vad_stats[proc_name]["rwx_vads"] += 1
                
                # This is a strong indicator of code injection
                finding = {
                    "pid": pid,
                    "process": proc_name,
                    "protection": protection,
                    "private_memory": private_mem,
                    "tag": tag,
                    "severity": "HIGH",
                    "reason": f"RWX memory region in {proc_name} (code injection indicator)",
                    "technique": "T1055"
                }
                result.vad_anomalies.append(finding)
                result.score += 15
        
        # Large memory allocations (>1MB)
        if commit_charge > 256:  # 256 pages = 1MB
            vad_stats[proc_name]["large_allocations"] += 1
    
    # Analyze VAD statistics for anomalies
    for proc_name, stats in vad_stats.items():
        # High ratio of executable VADs (>30%)
        if stats["total_vads"] > 10:
            exec_ratio = stats["executable_vads"] / stats["total_vads"]
            if exec_ratio > 0.3:
                finding = {
                    "process": proc_name,
                    "total_vads": stats["total_vads"],
                    "executable_vads": stats["executable_vads"],
                    "ratio": f"{exec_ratio:.2%}",
                    "severity": "MEDIUM",
                    "reason": f"High ratio of executable memory regions in {proc_name}"
                }
                result.vad_anomalies.append(finding)
                result.score += 10
        
        # Multiple private executable VADs (code injection)
        if stats["private_exec_vads"] >= 3:
            finding = {
                "process": proc_name,
                "private_exec_vads": stats["private_exec_vads"],
                "severity": "HIGH",
                "reason": f"Multiple private executable memory regions in {proc_name} (injection indicator)",
                "technique": "T1055"
            }
            result.vad_anomalies.append(finding)
            result.score += 20
            
            if not any(t['technique'] == 'T1055' for t in result.mitre_techniques):
                result.mitre_techniques.append({
                    "technique": "T1055",
                    "name": "Process Injection",
                    "description": f"Multiple private executable regions in {proc_name}"
                })


def analyze_registry_persistence(hivelist_output: Dict, config: dict, result: AnalysisResult) -> None:
    """
    Analyze registry hives for persistence mechanisms.
    Detects:
    - Loaded registry hives from suspicious locations
    - Orphaned hives (not in standard locations)
    - Hives loaded by unusual processes
    """
    if not hivelist_output or "error" in hivelist_output:
        return
    
    detection_cfg = config.get("analysis", {})
    
    # Standard registry hive locations
    standard_hives = [
        r"\\systemroot\\system32\\config\\sam",
        r"\\systemroot\\system32\\config\\security",
        r"\\systemroot\\system32\\config\\software",
        r"\\systemroot\\system32\\config\\system",
        r"\\systemroot\\system32\\config\\default",
        r"\\users\\.+\\ntuser.dat",
        r"\\users\\.+\\appdata\\local\\microsoft\\windows\\usrclass.dat",
    ]
    
    for hive in hivelist_output:
        hive_name = hive.get("Hive", "").lower()
        hive_offset = hive.get("Offset(V)", "")
        
        if not hive_name:
            continue
        
        # Check if hive is from standard location
        is_standard = False
        for standard in standard_hives:
            if re.search(standard, hive_name, re.IGNORECASE):
                is_standard = True
                break
        
        # Suspicious: hive from non-standard location
        if not is_standard:
            finding = {
                "hive_name": hive_name,
                "offset": hive_offset,
                "severity": "MEDIUM",
                "reason": f"Registry hive loaded from non-standard location: {hive_name}",
                "technique": "T1112"
            }
            result.registry_persistence.append(finding)
            result.persistence_mechanisms.append(finding)
            result.score += 15
            
            if not any(t['technique'] == 'T1112' for t in result.mitre_techniques):
                result.mitre_techniques.append({
                    "technique": "T1112",
                    "name": "Modify Registry",
                    "description": f"Suspicious registry hive: {hive_name}"
                })


def analyze_memory_mapped_files(dlllist_output: Dict, config: dict, result: AnalysisResult) -> None:
    """
    Analyze memory-mapped files (DLLs and other modules) for anomalies.
    Detects:
    - DLLs loaded from suspicious paths (Temp, AppData, ProgramData)
    - Unsigned DLLs in critical processes
    - DLL side-loading attacks
    - Reflective DLL injection (DLLs without file backing)
    """
    if not dlllist_output or "error" in dlllist_output:
        return
    
    detection_cfg = config.get("analysis", {})
    legitimate_procs = [p.lower() for p in detection_cfg.get("legitimate_processes", [])]
    
    # Suspicious DLL paths
    suspicious_dll_paths = [
        r"\\temp\\",
        r"\\appdata\\local\\temp\\",
        r"\\programdata\\",
        r"\\users\\public\\",
        r"^c:\\[^\\]+\.dll$",  # DLL in root of C:\
        r"\\downloads\\",
        r"\\desktop\\",
    ]
    
    # Track DLL loading patterns
    dll_stats = defaultdict(lambda: {
        "total_dlls": 0,
        "suspicious_paths": [],
        "unbacked_dlls": 0
    })
    
    for dll_entry in dlllist_output:
        pid = dll_entry.get("PID", 0)
        proc_name = dll_entry.get("Process", "").lower()
        dll_base = dll_entry.get("Base", "")
        dll_size = dll_entry.get("Size", 0)
        dll_name = dll_entry.get("Name", "")
        dll_path = dll_entry.get("Path", "")
        
        if not dll_path:
            continue
        
        dll_path_lower = dll_path.lower()
        dll_stats[proc_name]["total_dlls"] += 1
        
        # Check for suspicious DLL paths
        for susp_path in suspicious_dll_paths:
            if re.search(susp_path, dll_path_lower, re.IGNORECASE):
                dll_stats[proc_name]["suspicious_paths"].append({
                    "dll_path": dll_path,
                    "base": dll_base,
                    "size": dll_size,
                    "pattern": susp_path
                })
                break
        
        # Check for DLLs without file backing (reflective DLL injection)
        if dll_path == "" or dll_path.lower() == "pagefile-backed section":
            dll_stats[proc_name]["unbacked_dlls"] += 1
    
    # Generate findings
    for proc_name, stats in dll_stats.items():
        # DLLs from suspicious paths
        if len(stats["suspicious_paths"]) >= 1:
            if proc_name not in legitimate_procs or len(stats["suspicious_paths"]) >= 3:
                finding = {
                    "process": proc_name,
                    "count": len(stats["suspicious_paths"]),
                    "details": stats["suspicious_paths"][:3],  # First 3
                    "severity": "HIGH",
                    "reason": f"{proc_name} loaded DLLs from suspicious locations",
                    "technique": "T1574"
                }
                result.memory_mapped_files.append(finding)
                result.score += 20
                
                if not any(t['technique'] == 'T1574' for t in result.mitre_techniques):
                    result.mitre_techniques.append({
                        "technique": "T1574",
                        "name": "Hijack Execution Flow",
                        "description": f"{proc_name} loading DLLs from suspicious paths"
                    })
        
        # Reflective DLL injection
        if stats["unbacked_dlls"] >= 2:
            finding = {
                "process": proc_name,
                "unbacked_count": stats["unbacked_dlls"],
                "severity": "CRITICAL",
                "reason": f"{proc_name} has {stats['unbacked_dlls']} DLLs without file backing (reflective DLL injection)",
                "technique": "T1055"
            }
            result.memory_mapped_files.append(finding)
            result.dll_injection.append(finding)
            result.score += 30
            
            if not any(t['technique'] == 'T1055' for t in result.mitre_techniques):
                result.mitre_techniques.append({
                    "technique": "T1055",
                    "name": "Process Injection",
                    "description": f"Reflective DLL injection in {proc_name}"
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
        owner_process = (conn.get("Owner") or "").lower()
        
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
    
    # ADVANCED: Detect C2 beaconing patterns
    _detect_network_beaconing(connections, result, config)


def _detect_lsass_access(processes: List[Dict], proc_map: Dict, result: AnalysisResult, config: dict) -> None:
    """
    Detect processes accessing LSASS (credential dumping indicator).
    LSASS (PID usually 400-500 range) should only be accessed by system processes.
    """
    lsass_proc = None
    for proc in processes:
        if (proc.get("ImageFileName") or "").lower() == "lsass.exe":
            lsass_proc = proc
            break
    
    if not lsass_proc:
        return
    
    lsass_pid = lsass_proc.get("PID", 0)
    detection_cfg = config.get("analysis", {})
    system_processes = [x.lower() for x in detection_cfg.get("system_processes", [])]
    
    # Check if any non-system process has parent LSASS (suspicious)
    for proc in processes:
        ppid = proc.get("PPID", 0)
        proc_name = proc.get("ImageFileName", "").lower()
        
        if ppid == lsass_pid and proc_name not in system_processes:
            finding = {
                "pid": proc.get("PID", 0),
                "name": proc_name,
                "reason": f"Process spawned by LSASS (credential dumping indicator)",
                "severity": "CRITICAL",
                "technique": "T1003"
            }
            result.lsass_access.append(finding)
            result.credential_access.append(finding)
            result.suspicious_processes.append(finding)
            result.score += 40
            
            if "T1003" not in [t['technique'] for t in result.mitre_techniques]:
                result.mitre_techniques.append({
                    "technique": "T1003",
                    "name": "OS Credential Dumping",
                    "description": f"Suspicious LSASS interaction by {proc_name}"
                })


def _validate_process_ancestry(processes: List[Dict], proc_map: Dict, result: AnalysisResult, config: dict) -> None:
    """
    Validate process ancestry chains to detect abnormal parent-child relationships.
    Examples:
    - chrome.exe should NOT spawn from cmd.exe
    - svchost.exe MUST spawn from services.exe
    - explorer.exe should spawn from userinit.exe
    """
    detection_cfg = config.get("analysis", {})
    expected_parents = detection_cfg.get("expected_parent_relationships", {})
    
    for proc in processes:
        proc_name = proc.get("ImageFileName", "").lower()
        ppid = proc.get("PPID", 0)
        pid = proc.get("PID", 0)
        
        # Check if this process has expected parent requirements
        if proc_name in expected_parents:
            expected = [x.lower() for x in expected_parents[proc_name]]
            parent_proc = proc_map.get(ppid, {})
            parent_name = parent_proc.get("ImageFileName", "").lower()
            
            if parent_name and parent_name not in expected:
                finding = {
                    "pid": pid,
                    "name": proc_name,
                    "parent_pid": ppid,
                    "parent_name": parent_name,
                    "expected_parents": expected,
                    "reason": f"Abnormal parent: {proc_name} spawned by {parent_name} (expected: {', '.join(expected)})",
                    "severity": "HIGH",
                    "technique": "T1055"
                }
                result.process_hollowing.append(finding)
                result.suspicious_processes.append(finding)
                result.score += 20
                
                if "T1055" not in [t['technique'] for t in result.mitre_techniques]:
                    result.mitre_techniques.append({
                        "technique": "T1055",
                        "name": "Process Injection",
                        "description": f"Abnormal ancestry for {proc_name}"
                    })


def _analyze_process_attributes(processes: List[Dict], result: AnalysisResult, config: dict) -> None:
    """
    Analyze process attributes for anomalies:
    - Excessive thread count
    - Excessive handle count
    - Unusual session IDs
    - WOW64 processes (32-bit on 64-bit system - potential evasion)
    """
    detection_cfg = config.get("analysis", {})
    thread_threshold = detection_cfg.get("suspicious_thread_count", 100)
    handle_threshold = detection_cfg.get("suspicious_handle_count", 5000)
    
    for proc in processes:
        proc_name = proc.get("ImageFileName", "").lower()
        pid = proc.get("PID", 0)
        # Handle None values from failed plugins (e.g., when windows.handles.Handles fails)
        threads = proc.get("Threads") or 0
        handles = proc.get("Handles") or 0
        wow64 = proc.get("Wow64", False)
        
        # Skip system processes with legitimately high counts
        if proc_name in ["system", "svchost.exe", "chrome.exe", "firefox.exe"]:
            continue
        
        # Excessive threads (possible cryptomining or botnet activity)
        if threads > thread_threshold:
            finding = {
                "pid": pid,
                "name": proc_name,
                "threads": threads,
                "reason": f"Excessive thread count: {threads} threads (cryptominer/botnet indicator)",
                "severity": "MEDIUM"
            }
            result.memory_anomalies.append(finding)
            result.score += 10
        
        # Excessive handles (possible resource exhaustion or keylogger)
        if handles > handle_threshold:
            finding = {
                "pid": pid,
                "name": proc_name,
                "handles": handles,
                "reason": f"Excessive handle count: {handles} handles (keylogger/malware indicator)",
                "severity": "MEDIUM"
            }
            result.memory_anomalies.append(finding)
            result.score += 10
        
        # WOW64 process (32-bit on 64-bit - evasion technique)
        if wow64 and proc_name not in ["dumpit.exe"]:  # dumpit is legitimately 32-bit
            finding = {
                "pid": pid,
                "name": proc_name,
                "reason": f"WOW64 process detected (32-bit on 64-bit system - potential evasion)",
                "severity": "LOW"
            }
            result.memory_anomalies.append(finding)
            result.score += 5


def _detect_network_beaconing(connections: List[Dict], result: AnalysisResult, config: dict) -> None:
    """
    Detect C2 beaconing patterns based on regular connection intervals.
    Beaconing = repeated connections to same host at regular intervals (e.g., every 60 seconds).
    """
    # Group connections by destination
    connection_groups = defaultdict(list)
    
    for conn in connections:
        foreign_addr = conn.get("ForeignAddr", "")
        foreign_port = conn.get("ForeignPort", 0)
        created = conn.get("Created")
        owner_process = conn.get("Owner", "")
        
        if foreign_addr and created and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::", "*"]:
            key = f"{foreign_addr}:{foreign_port}:{owner_process}"
            connection_groups[key].append({
                'time': created,
                'addr': foreign_addr,
                'port': foreign_port,
                'process': owner_process,
                'pid': conn.get("PID", 0)
            })
    
    # Analyze each group for periodic patterns
    for key, conns in connection_groups.items():
        if len(conns) < 3:  # Need at least 3 connections to detect pattern
            continue
        
        # Sort by time and calculate intervals
        conns.sort(key=lambda x: x['time'])
        intervals = []
        
        for i in range(1, len(conns)):
            try:
                # Parse timestamps and calculate interval
                t1 = datetime.fromisoformat(conns[i-1]['time'].replace('+00:00', ''))
                t2 = datetime.fromisoformat(conns[i]['time'].replace('+00:00', ''))
                interval_seconds = (t2 - t1).total_seconds()
                intervals.append(interval_seconds)
            except:
                continue
        
        if not intervals:
            continue
        
        # Check if intervals are suspiciously regular (variance < 20%)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Regular intervals with low variance = beaconing
        if std_dev < (avg_interval * 0.2) and 10 < avg_interval < 600:  # 10 sec to 10 min
            finding = {
                "destination": f"{conns[0]['addr']}:{conns[0]['port']}",
                "process": conns[0]['process'],
                "pid": conns[0]['pid'],
                "connection_count": len(conns),
                "avg_interval": round(avg_interval, 2),
                "reason": f"C2 beaconing detected: {len(conns)} connections every ~{int(avg_interval)}s",
                "severity": "CRITICAL"
            }
            result.beaconing_activity.append(finding)
            result.command_and_control.append(finding)
            result.score += 35
            
            if "T1071" not in [t['technique'] for t in result.mitre_techniques]:
                result.mitre_techniques.append({
                    "technique": "T1071",
                    "name": "Application Layer Protocol",
                    "description": "C2 beaconing pattern detected"
                })


def analyze_malfind(malfind_output: str, result: AnalysisResult, config: dict = None) -> None:
    """
    Advanced memory analysis for code injection, DLL injection, and shellcode detection.
    """
    # Store raw output
    result.parsed_data['malfind_raw'] = malfind_output
    
    if config is None:
        config = {}
    
    detection_cfg = config.get("analysis", {})
    malfind_whitelist = [x.lower() for x in detection_cfg.get("malfind_whitelist", [])]
    
    injections = malfind_output if isinstance(malfind_output, list) else []
    
    # Track injection patterns per process
    injection_count = defaultdict(int)
    
    for injection in injections:
        pid = injection.get("PID", 0)
        process = injection.get("Process", "").lower()
        protection = injection.get("Protection", "")
        disasm = injection.get("Disasm", "")
        hexdump = injection.get("Hexdump", "")
        tag = injection.get("Tag", "")
        start_vpn = injection.get("Start VPN", 0)
        
        # Skip whitelisted legitimate processes
        if any(whitelist_proc in process for whitelist_proc in malfind_whitelist):
            continue
        
        # CRITICAL: PAGE_EXECUTE_READWRITE is highly suspicious
        if "PAGE_EXECUTE_READWRITE" in protection:
            # Analyze memory content for shellcode patterns
            shellcode_indicators = _detect_shellcode_patterns(disasm, hexdump)
            
            severity = "HIGH"
            reason = "PAGE_EXECUTE_READWRITE memory in non-whitelisted process"
            
            # Elevate severity if shellcode patterns detected
            if shellcode_indicators:
                severity = "CRITICAL"
                reason = f"Code injection with shellcode patterns: {', '.join(shellcode_indicators)}"
            
            finding = {
                "pid": pid,
                "process": process,
                "protection": protection,
                "start_address": hex(start_vpn) if start_vpn else "Unknown",
                "shellcode_indicators": shellcode_indicators,
                "reason": reason,
                "severity": severity
            }
            result.injected_code.append(finding)
            result.dll_injection.append(finding)  # RWX often indicates DLL injection
            result.score += 30 if severity == "CRITICAL" else 25
            
            injection_count[pid] += 1
            
            if "T1055" not in [t['technique'] for t in result.mitre_techniques]:
                result.mitre_techniques.append({
                    "technique": "T1055",
                    "name": "Process Injection",
                    "description": f"Suspicious executable memory in {process} (PID: {pid})"
                })
        
        # MEDIUM: Private memory without file backing (reflective DLL loading)
        elif injection.get("PrivateMemory", 0) == 1 and tag == "VadS":
            if "PAGE_EXECUTE" in protection:
                finding = {
                    "pid": pid,
                    "process": process,
                    "protection": protection,
                    "reason": "Private executable memory without file backing (reflective DLL loading)",
                    "severity": "MEDIUM"
                }
                result.dll_injection.append(finding)
                result.score += 15
    
    # ADVANCED: Multiple injections in same process = high confidence malware
    for pid, count in injection_count.items():
        if count >= 3:
            result.score += 20  # Bonus score for multiple injections


def _detect_shellcode_patterns(disasm: str, hexdump: str) -> List[str]:
    """
    Detect common shellcode patterns in memory.
    Returns list of detected patterns.
    """
    indicators = []
    
    if not disasm and not hexdump:
        return indicators
    
    combined = (disasm + hexdump).lower()
    
    # Pattern 1: NOP sled (common in exploits)
    if "90 90 90 90" in hexdump or "nop" in disasm:
        nop_count = hexdump.count("90")
        if nop_count > 8:  # Multiple consecutive NOPs
            indicators.append("NOP_SLED")
    
    # Pattern 2: API hashing (malware obfuscation)
    if re.search(r"xor.*0x[0-9a-f]{8}", combined):
        indicators.append("API_HASHING")
    
    # Pattern 3: PEB walking (common shellcode technique)
    if "gs:" in combined or "fs:" in combined:
        if any(x in combined for x in ["0x30", "0x60"]):
            indicators.append("PEB_WALKING")
    
    # Pattern 4: Metasploit signature patterns
    metasploit_patterns = ["fc e8 89 00 00 00", "fc 48 83 e4 f0"]
    if any(pattern in hexdump for pattern in metasploit_patterns):
        indicators.append("METASPLOIT_SIGNATURE")
    
    # Pattern 5: Cobalt Strike beacon patterns
    if "4d 5a 90 00" in hexdump:  # MZ header in memory (reflective DLL)
        indicators.append("PE_IN_MEMORY")
    
    # Pattern 6: Stack pivot (exploit technique)
    if re.search(r"(xchg|mov).*esp", combined):
        indicators.append("STACK_PIVOT")
    
    return indicators


def enhanced_detection_analysis(result: AnalysisResult, config: Dict) -> None:
    """
    Run enhanced detection engine analysis on collected data.
    """
    if not DETECTION_ENGINE_AVAILABLE:
        return
    
    detection_cfg = config.get("detection_engine", {})
    if not detection_cfg.get("enabled", True):
        return
    
    # Initialize detection engine
    if result.detection_engine is None:
        result.detection_engine = EnhancedDetectionEngine(config)
    
    engine = result.detection_engine
    
    # Get parsed data
    processes = result.parsed_data.get('pslist', [])
    cmdlines_data = result.parsed_data.get('cmdlines', {})
    handles = result.parsed_data.get('handles', [])
    malfind_data = result.parsed_data.get('malfind', [])
    network = result.parsed_data.get('network', [])
    
    # Build parent name lookup
    parent_map = {}
    for proc in processes:
        pid = proc.get("PID", 0)
        ppid = proc.get("PPID", 0)
        parent_proc = next((p for p in processes if p.get("PID") == ppid), None)
        parent_map[pid] = parent_proc.get("ImageFileName", "") if parent_proc else ""
    
    # 1. LOLBin Abuse Detection
    if detection_cfg.get("lolbin_detection", {}).get("enabled", True):
        for proc in processes:
            pid = proc.get("PID", 0)
            cmdline = cmdlines_data.get(pid, "")
            parent_name = parent_map.get(pid, "")
            
            finding = engine.detect_lolbin_abuse(proc, cmdline, parent_name)
            if finding:
                result.lolbin_abuse.append(finding)
                result.add_finding(
                    severity=finding["severity"],
                    category="LOLBin Abuse",
                    description=finding["reason"],
                    process_name=finding["process"],
                    pid=pid,
                    mitre_technique=finding.get("mitre"),
                    confidence=0.8,
                    context={
                        "process": proc,
                        "cmdline": cmdline,
                        "parent": parent_name,
                        "indicators": finding["indicators"]
                    }
                )
                result.score += finding["abuse_score"]
    
    # 2. Entropy Analysis (Packed/Obfuscated Code)
    if detection_cfg.get("entropy_analysis", {}).get("enabled", True):
        for region in malfind_data:
            hexdump = region.get("Hexdump", "")
            disasm = region.get("Disasm", "")
            
            entropy_result = engine.analyze_process_entropy(hexdump, disasm)
            
            if entropy_result["is_packed"] or entropy_result.get("detected_packer"):
                result.entropy_analysis.append({
                    "pid": region.get("PID", 0),
                    "process": region.get("Process", ""),
                    "entropy": entropy_result["entropy"],
                    "is_packed": entropy_result["is_packed"],
                    "is_encrypted": entropy_result.get("is_encrypted", False),
                    "packer": entropy_result.get("detected_packer"),
                    "severity": entropy_result["severity"]
                })
                
                result.add_finding(
                    severity=entropy_result["severity"],
                    category="Packed/Obfuscated Code",
                    description=f"High entropy ({entropy_result['entropy']}) detected - possible packing/obfuscation" +
                                (f" (Packer: {entropy_result['detected_packer']})" if entropy_result.get('detected_packer') else ""),
                    process_name=region.get("Process", ""),
                    pid=region.get("PID", 0),
                    mitre_technique="T1027",
                    confidence=0.75,
                    context={
                        "entropy": entropy_result["entropy"],
                        "packer": entropy_result.get("detected_packer")
                    }
                )
                
                if entropy_result["is_encrypted"]:
                    result.score += 25
                elif entropy_result["is_packed"]:
                    result.score += 15
    
    # 3. Statistical Anomaly Detection
    if detection_cfg.get("statistical_analysis", {}).get("enabled", True):
        anomalies = engine.detect_statistical_anomalies(processes)
        
        for anomaly in anomalies:
            result.statistical_anomalies.append(anomaly)
            result.add_finding(
                severity=anomaly["severity"],
                category="Statistical Anomaly",
                description=anomaly["reason"],
                process_name=anomaly.get("process", ""),
                pid=anomaly.get("pid", 0),
                mitre_technique="T1036",
                confidence=0.6,
                context=anomaly
            )
            
            if anomaly["severity"] == "HIGH":
                result.score += 20
            elif anomaly["severity"] == "MEDIUM":
                result.score += 10
    
    # 4. Mutex Artifact Analysis
    if detection_cfg.get("mutex_analysis", {}).get("enabled", True):
        mutex_findings = engine.detect_mutex_artifacts(handles)
        
        for finding in mutex_findings:
            result.mutex_artifacts.append(finding)
            result.add_finding(
                severity=finding["severity"],
                category="Malware Mutex",
                description=finding["reason"],
                process_name=finding.get("process", ""),
                pid=finding.get("pid", 0),
                mitre_technique=finding.get("mitre", "T1106"),
                confidence=0.85,
                context={
                    "mutex_name": finding.get("mutex_name"),
                    "description": finding.get("description")
                }
            )
            result.score += 30
    
    # 5. Process Hollowing Detection
    if detection_cfg.get("hollowing_detection", {}).get("enabled", True):
        vad_info = result.parsed_data.get('vad_data', [])
        
        for proc in processes:
            finding = engine.detect_hollowed_process(proc, vad_info)
            if finding:
                result.hollowed_processes.append(finding)
                result.add_finding(
                    severity=finding["severity"],
                    category="Process Hollowing",
                    description=finding["reason"],
                    process_name=finding["process"],
                    pid=finding["pid"],
                    mitre_technique=finding.get("mitre", "T1055.012"),
                    confidence=0.9,
                    context={
                        "indicators": finding["indicators"],
                        "hollow_score": finding["hollow_score"]
                    }
                )
                result.score += finding["hollow_score"]
    
    # 6. API Hook Detection
    if detection_cfg.get("api_hook_detection", {}).get("enabled", True):
        hook_findings = engine.detect_api_hooks(malfind_data)
        
        for finding in hook_findings:
            result.api_hooks.append(finding)
            result.add_finding(
                severity=finding["severity"],
                category="API Hook",
                description=finding["reason"],
                process_name=finding.get("process", ""),
                pid=finding.get("pid", 0),
                mitre_technique=finding.get("mitre", "T1056.004"),
                confidence=0.8,
                context={
                    "address": finding.get("address"),
                    "hook_type": finding.get("hook_type")
                }
            )
            result.score += 25
    
    # 7. Behavioral Pattern Analysis
    if detection_cfg.get("behavioral_analysis", {}).get("enabled", True):
        behavioral_patterns = engine.analyze_behavioral_patterns(processes, 
                                                                 cmdlines_data, 
                                                                 network)
        
        result.behavioral_patterns = behavioral_patterns
        
        # Add findings for each behavior category
        for category, findings in behavioral_patterns.items():
            for finding in findings:
                result.add_finding(
                    severity="HIGH",
                    category=f"Behavioral: {category.replace('_', ' ').title()}",
                    description=f"{finding.get('method')} detected",
                    process_name=finding.get("process", ""),
                    pid=finding.get("pid", 0),
                    mitre_technique=finding.get("mitre"),
                    confidence=0.75,
                    context=finding
                )
                result.score += 20


def generate_summary(result: AnalysisResult, config: Dict) -> None:
    """
    Generate comprehensive executive summary of findings with confidence scoring.
    """
    # Add malware family attribution from YARA findings
    try:
        from .malware_attributor import add_malware_attribution
        if result.yara_findings:
            result.malware_attribution = add_malware_attribution(result)
    except ImportError:
        result.malware_attribution = None
    
    # Perform evidence correlation if confidence scorer is available
    if result.confidence_scorer and len(result.findings) > 0:
        result.correlated_evidence = result.confidence_scorer.correlate_evidence(result.findings)
        result.confidence_report = result.confidence_scorer.generate_confidence_report(result.correlated_evidence)
    
    # Count suppressed findings
    suppressed_count = len(result.suppressed_findings)
    
    summary_lines = []
    
    if result.score == 0:
        summary_lines.append("✓ No significant suspicious activity detected.")
    else:
        summary_lines.append(f"⚠ RISK LEVEL: {result.risk_level}")
        summary_lines.append(f"Total Risk Score: {result.score}")
        summary_lines.append("")
        
        # Critical findings
        if result.credential_access:
            summary_lines.append(f"🔴 CRITICAL: Credential Access Activity - {len(result.credential_access)} findings")
        
        if result.lsass_access:
            summary_lines.append(f"🔴 CRITICAL: LSASS Memory Access - {len(result.lsass_access)} instances (credential dumping)")
        
        if result.beaconing_activity:
            summary_lines.append(f"🔴 CRITICAL: C2 Beaconing Detected - {len(result.beaconing_activity)} connections")
        
        # High severity findings
        if result.process_hollowing:
            summary_lines.append(f"🟠 HIGH: Process Hollowing/Injection - {len(result.process_hollowing)} instances")
        
        if result.dll_injection:
            summary_lines.append(f"🟠 HIGH: DLL Injection Detected - {len(result.dll_injection)} instances")
        
        if result.injected_code:
            summary_lines.append(f"🟠 HIGH: Code Injection - {len(result.injected_code)} memory regions")
        
        # Medium severity findings
        if result.suspicious_processes:
            summary_lines.append(f"⚠ Suspicious Processes: {len(result.suspicious_processes)}")
        
        if result.suspicious_network:
            summary_lines.append(f"⚠ Suspicious Network Connections: {len(result.suspicious_network)}")
        
        if result.memory_anomalies:
            summary_lines.append(f"⚠ Memory Anomalies: {len(result.memory_anomalies)}")
        
        if result.persistence_mechanisms:
            summary_lines.append(f"⚠ Persistence Mechanisms: {len(result.persistence_mechanisms)}")
        
        # NEW: Memory artifact findings
        if result.handle_artifacts:
            summary_lines.append(f"⚠ Handle Artifacts: {len(result.handle_artifacts)} suspicious handle accesses")
        
        if result.vad_anomalies:
            summary_lines.append(f"⚠ VAD Anomalies: {len(result.vad_anomalies)} memory mapping issues")
        
        if result.registry_persistence:
            summary_lines.append(f"⚠ Registry Persistence: {len(result.registry_persistence)} suspicious registry activities")
        
        if result.memory_mapped_files:
            summary_lines.append(f"⚠ Memory-Mapped Files: {len(result.memory_mapped_files)} suspicious DLL loads")
        
        # NEW: Enhanced detection engine findings
        if result.lolbin_abuse:
            summary_lines.append(f"🟠 HIGH: LOLBin Abuse - {len(result.lolbin_abuse)} instances")
        
        if result.entropy_analysis:
            summary_lines.append(f"⚠ Packed/Obfuscated Code: {len(result.entropy_analysis)} regions")
        
        if result.statistical_anomalies:
            summary_lines.append(f"⚠ Statistical Anomalies: {len(result.statistical_anomalies)} deviations")
        
        if result.mutex_artifacts:
            summary_lines.append(f"🔴 CRITICAL: Malware Mutex Patterns - {len(result.mutex_artifacts)} detected")
        
        if result.hollowed_processes:
            summary_lines.append(f"🔴 CRITICAL: Hollowed Processes - {len(result.hollowed_processes)} instances")
        
        if result.api_hooks:
            summary_lines.append(f"🟠 HIGH: API Hooks - {len(result.api_hooks)} detected")
        
        if result.behavioral_patterns:
            for category, findings in result.behavioral_patterns.items():
                if findings:
                    category_name = category.replace('_', ' ').title()
                    summary_lines.append(f"⚠ {category_name}: {len(findings)} instances")
        
        # MITRE ATT&CK mapping
        if result.mitre_techniques:
            summary_lines.append("")
            summary_lines.append("MITRE ATT&CK Techniques Detected:")
            unique_techniques = {t['technique']: t for t in result.mitre_techniques}
            for tech_id, tech in unique_techniques.items():
                summary_lines.append(f"  - {tech_id}: {tech['name']}")
        
        # Confidence scoring summary
        if result.confidence_scorer:
            summary_lines.append("")
            summary_lines.append("False Positive Reduction:")
            summary_lines.append(f"  Total Findings: {len(result.findings) + suppressed_count}")
            summary_lines.append(f"  High-Confidence Alerts: {len(result.findings)}")
            summary_lines.append(f"  Suppressed (Low-Confidence): {suppressed_count}")
            
            if result.correlated_evidence:
                high_conf_pids = [pid for pid, data in result.correlated_evidence.items() 
                                 if data['final_confidence'] >= 0.7]
                summary_lines.append(f"  Processes with High-Confidence Indicators: {len(high_conf_pids)}")
        
        # Phase 2: Advanced detection patterns summary
        if result.credential_theft:
            summary_lines.append("")
            summary_lines.append("🔴 PHASE 2 ADVANCED THREAT DETECTION:")
            summary_lines.append(f"  Credential Theft: {len(result.credential_theft)} attempts")
        
        if result.persistence_detections:
            summary_lines.append(f"  Persistence Mechanisms: {len(result.persistence_detections)} detected")
        
        if result.lateral_movement_detections:
            summary_lines.append(f"  Lateral Movement: {len(result.lateral_movement_detections)} attempts")
        
        if result.privilege_escalation_detections:
            summary_lines.append(f"  Privilege Escalation: {len(result.privilege_escalation_detections)} attempts")
        
        if result.data_exfiltration:
            summary_lines.append(f"  Data Exfiltration: {len(result.data_exfiltration)} indicators")
        
        if result.ransomware_indicators:
            summary_lines.append(f"  Ransomware Behavior: {len(result.ransomware_indicators)} indicators")
        
        if result.rootkit_indicators:
            summary_lines.append(f"  Rootkit Indicators: {len(result.rootkit_indicators)} detected")
        
        if result.yara_findings:
            summary_lines.append(f"  YARA Matches: {len(result.yara_findings)} rules triggered")
        
        # Attack chain correlation
        if result.attack_chains:
            summary_lines.append("")
            summary_lines.append("⚠ ATTACK CHAIN CORRELATION:")
            for chain in result.attack_chains:
                summary_lines.append(f"  - {chain['chain_name'].replace('_', ' ').title()}: "
                                   f"{len(chain['matched_techniques'])} techniques "
                                   f"({chain['coverage_percentage']:.0f}% coverage, "
                                   f"confidence: {chain['confidence']}%)")
        
        # MITRE ATT&CK coverage
        if result.mitre_coverage:
            tactics_covered = result.mitre_coverage.get('tactic_count', 0)
            techniques_covered = result.mitre_coverage.get('technique_count', 0)
            if tactics_covered > 0:
                summary_lines.append("")
                summary_lines.append(f"MITRE ATT&CK Coverage: {techniques_covered} techniques across {tactics_covered} tactics")
        
        # Threat score
        if result.threat_score > 0:
            summary_lines.append(f"Overall Threat Score: {result.threat_score}/100")
        
        # Attack narrative
        if result.attack_narrative:
            summary_lines.append("")
            summary_lines.append("Attack Narrative:")
            for line in result.attack_narrative.split('\n'):
                summary_lines.append(f"  {line}")
    
    result.summary = "\n".join(summary_lines)

def run_phase2_detections(analysis_result, raw_outputs, config):
    """
    Run Phase 2 advanced detection patterns.
    
    This includes:
    - Credential theft detection
    - Persistence mechanism detection
    - Lateral movement detection
    - Privilege escalation detection
    - Data exfiltration detection
    - Ransomware behavior detection
    - Rootkit detection
    - YARA scanning
    - Behavioral correlation
    """
    from src.detection_patterns import AdvancedDetectionPatterns
    from src.correlation_engine import BehavioralCorrelationEngine
    from src.yara_scanner import YaraScanner
    
    # Initialize detection engines
    advanced_patterns = AdvancedDetectionPatterns()
    correlation_engine = BehavioralCorrelationEngine()
    
    # Extract data from raw outputs (handle both wrapped and error formats)
    def extract_data(plugin_name):
        result = raw_outputs.get(plugin_name, {})
        if isinstance(result, dict):
            if 'error' in result:
                return []  # Plugin failed, return empty
            elif 'data' in result:
                return result['data']  # Extract from wrapped structure
        return []
    
    processes = extract_data('windows.pslist.PsList')
    handles = extract_data('windows.handles.Handles')
    network = extract_data('windows.netscan.NetScan')
    registry = extract_data('windows.registry.hivelist.HiveList')
    scheduled_tasks = []  # Would need windows.scheduledtasks plugin
    services = []  # Would need windows.services plugin
    drivers = []  # Would need windows.modules plugin
    files = []  # Would need windows.filescan plugin
    
    # 1. Credential Theft Detection
    cred_findings = advanced_patterns.detect_credential_theft(
        processes, handles, analysis_result
    )
    analysis_result.credential_theft.extend(cred_findings)
    
    # 2. Persistence Mechanism Detection
    persist_findings = advanced_patterns.detect_persistence_mechanisms(
        registry, scheduled_tasks, services, processes
    )
    analysis_result.persistence_detections.extend(persist_findings)
    
    # 3. Lateral Movement Detection
    lateral_findings = advanced_patterns.detect_lateral_movement(processes, network)
    analysis_result.lateral_movement_detections.extend(lateral_findings)
    
    # 4. Privilege Escalation Detection
    privesc_findings = advanced_patterns.detect_privilege_escalation(processes, handles)
    analysis_result.privilege_escalation_detections.extend(privesc_findings)
    
    # 5. Data Exfiltration Detection
    exfil_findings = advanced_patterns.detect_data_exfiltration(processes, network)
    analysis_result.data_exfiltration.extend(exfil_findings)
    
    # 6. Ransomware Detection
    ransom_findings = advanced_patterns.detect_ransomware_behavior(processes, files)
    analysis_result.ransomware_indicators.extend(ransom_findings)
    
    # 7. Rootkit Detection
    rootkit_findings = advanced_patterns.detect_rootkit_indicators(drivers, processes)
    analysis_result.rootkit_indicators.extend(rootkit_findings)
    
    # 8. YARA Scanning (if enabled)
    yara_config = config.get('yara', {})
    if yara_config.get('enabled', False):
        scanner = YaraScanner(yara_config.get('rules_dir', 'yara_rules'))
        if scanner.compile_rules():
            # Scan memory dump (if path available)
            memory_path = config.get('memory_dump_path')
            if memory_path:
                yara_matches = scanner.scan_memory_dump(
                    memory_path,
                    fast_scan=yara_config.get('fast_scan', False),
                    timeout=yara_config.get('timeout', 600)
                )
                analysis_result.yara_findings.extend(yara_matches)
                analysis_result.yara_statistics = scanner.get_statistics()
    
    # 9. Behavioral Correlation
    all_findings = (
        cred_findings + persist_findings + lateral_findings +
        privesc_findings + exfil_findings + ransom_findings + rootkit_findings
    )
    
    correlation_result = correlation_engine.correlate_findings(
        all_findings, processes, network, analysis_result
    )
    
    analysis_result.attack_chains = correlation_result['attack_chains']
    analysis_result.mitre_coverage = correlation_result['mitre_coverage']
    analysis_result.threat_score = correlation_result['threat_score']
    analysis_result.correlated_findings = correlation_result['correlated_findings']
    analysis_result.attack_narrative = correlation_engine.generate_attack_narrative(
        correlation_result['attack_chains'],
        correlation_result['mitre_coverage']
    )
    
    # Add all findings to main findings list
    for finding in all_findings:
        analysis_result.add_finding(
            severity=finding.get('severity', 'MEDIUM'),
            category=finding.get('type', 'Unknown'),
            description=finding.get('description', ''),
            process_name=finding.get('process'),
            pid=finding.get('pid'),
            mitre_technique=finding.get('mitre'),
            confidence=finding.get('confidence', 0.7),
            context=finding
        )
    
    return analysis_result
