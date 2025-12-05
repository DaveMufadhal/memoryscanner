"""
Advanced Confidence Scoring and False Positive Reduction System
Implements multi-factor analysis with weighted confidence scoring
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import re
import hashlib


class ConfidenceScorer:
    """
    Advanced confidence scoring system that reduces false positives through:
    - Digital signature verification (simulated)
    - Path-based whitelisting
    - Parent-child relationship validation
    - Timestamp anomaly detection
    - Multi-factor evidence correlation
    - Behavioral pattern analysis
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.analysis_cfg = config.get("analysis", {})
        self.confidence_cfg = config.get("confidence_scoring", {})
        
        # Trusted paths (signed binaries)
        self.trusted_paths = self._build_trusted_paths()
        
        # Known-good process signatures
        self.known_good_hashes = self._load_known_good_hashes()
        
        # Evidence correlation tracker
        self.evidence_tracker = defaultdict(lambda: {
            "indicators": [],
            "confidence": 0,
            "score": 0,
            "categories": set()
        })
    
    def _build_trusted_paths(self) -> List[str]:
        """Build list of trusted file paths with system binaries."""
        return [
            r"c:\\windows\\system32\\",
            r"c:\\windows\\syswow64\\",
            r"c:\\windows\\winsxs\\",
            r"c:\\program files\\windows defender\\",
            r"c:\\program files\\common files\\microsoft shared\\",
            r"c:\\windows\\microsoft.net\\framework",
        ]
    
    def _load_known_good_hashes(self) -> Dict[str, str]:
        """
        Load known-good file hashes (simulated).
        In production, this would load from threat intel feeds.
        """
        return {
            # Common Windows system processes (simulated SHA256)
            "system": "KNOWN_GOOD",
            "smss.exe": "KNOWN_GOOD",
            "csrss.exe": "KNOWN_GOOD",
            "wininit.exe": "KNOWN_GOOD",
            "services.exe": "KNOWN_GOOD",
            "lsass.exe": "KNOWN_GOOD",
            "svchost.exe": "KNOWN_GOOD",
            "explorer.exe": "KNOWN_GOOD",
        }
    
    def calculate_confidence(self, finding: Dict, context: Dict) -> float:
        """
        Calculate confidence score (0.0 - 1.0) for a finding.
        
        Args:
            finding: The security finding to score
            context: Additional context (process info, network data, etc.)
        
        Returns:
            Confidence score from 0.0 (low confidence) to 1.0 (high confidence)
        """
        confidence = 0.5  # Start with neutral confidence
        factors = []
        
        proc_name = finding.get("name", "").lower()
        pid = finding.get("pid", 0)
        ppid = finding.get("ppid", 0)
        
        # Factor 1: Process Integrity (path-based validation)
        path_confidence = self._check_process_integrity(context)
        confidence += path_confidence * 0.2
        factors.append(f"Path integrity: {path_confidence:.2f}")
        
        # Factor 2: Digital Signature (simulated)
        sig_confidence = self._check_digital_signature(proc_name, context)
        confidence += sig_confidence * 0.15
        factors.append(f"Signature: {sig_confidence:.2f}")
        
        # Factor 3: Parent-child relationship validation
        relationship_confidence = self._validate_parent_child_relationship(
            proc_name, context.get("parent_name", ""), ppid
        )
        confidence += relationship_confidence * 0.2
        factors.append(f"Parent-child: {relationship_confidence:.2f}")
        
        # Factor 4: Timestamp anomaly detection
        timestamp_confidence = self._check_timestamp_anomalies(context)
        confidence += timestamp_confidence * 0.1
        factors.append(f"Timestamp: {timestamp_confidence:.2f}")
        
        # Factor 5: Network behavior consistency
        network_confidence = self._check_network_behavior(context)
        confidence += network_confidence * 0.15
        factors.append(f"Network: {network_confidence:.2f}")
        
        # Factor 6: Memory characteristics
        memory_confidence = self._check_memory_characteristics(context)
        confidence += memory_confidence * 0.1
        factors.append(f"Memory: {memory_confidence:.2f}")
        
        # Factor 7: Runtime behavior patterns
        runtime_confidence = self._check_runtime_behavior(context)
        confidence += runtime_confidence * 0.1
        factors.append(f"Runtime: {runtime_confidence:.2f}")
        
        # Normalize to 0.0-1.0 range
        confidence = max(0.0, min(1.0, confidence))
        
        # Store factors for debugging
        finding["confidence_factors"] = factors
        finding["confidence_score"] = round(confidence, 3)
        
        return confidence
    
    def _check_process_integrity(self, context: Dict) -> float:
        """
        Check if process is from trusted path and has valid signature.
        Returns: -0.3 to +0.3
        """
        proc_path = context.get("process_path", "").lower()
        
        # Check if in trusted path
        for trusted_path in self.trusted_paths:
            if trusted_path in proc_path:
                return 0.3  # High trust
        
        # Check for suspicious paths
        suspicious_paths = [
            r"\\temp\\",
            r"\\appdata\\local\\temp\\",
            r"\\programdata\\",
            r"\\users\\public\\",
            r"\\downloads\\",
            r"\\desktop\\",
            r"^c:\\[^\\]+\.exe$",  # Root of C:\
        ]
        
        for susp_path in suspicious_paths:
            if re.search(susp_path, proc_path, re.IGNORECASE):
                return -0.3  # Low trust
        
        return 0.0  # Neutral
    
    def _check_digital_signature(self, proc_name: str, context: Dict) -> float:
        """
        Simulate digital signature verification.
        Returns: -0.2 to +0.2
        """
        # Check against known-good hashes
        if proc_name in self.known_good_hashes:
            return 0.2  # Verified signature
        
        # Check if it's a system process name but not verified
        system_procs = ["system", "smss.exe", "csrss.exe", "lsass.exe", 
                       "services.exe", "svchost.exe", "explorer.exe"]
        
        if proc_name in system_procs:
            # System process but no hash match - possible impersonation
            return -0.2
        
        return 0.0  # Unknown
    
    def _validate_parent_child_relationship(self, proc_name: str, 
                                           parent_name: str, ppid: int) -> float:
        """
        Validate if parent-child relationship is expected.
        Returns: -0.3 to +0.3
        """
        expected_parents = self.analysis_cfg.get("expected_parent_relationships", {})
        
        # Check if relationship is explicitly expected
        if proc_name in expected_parents:
            expected_list = expected_parents[proc_name]
            if parent_name in expected_list:
                return 0.3  # Expected relationship
            elif ppid != 0:
                return -0.3  # Unexpected parent (suspicious)
        
        # Check for abnormal parent-child patterns
        abnormal_patterns = [
            # Office apps spawning scripts
            {"parent": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
             "child": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]},
            # Browsers spawning scripts
            {"parent": ["iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe"],
             "child": ["cmd.exe", "powershell.exe", "wscript.exe"]},
        ]
        
        for pattern in abnormal_patterns:
            if parent_name in pattern["parent"] and proc_name in pattern["child"]:
                return -0.3  # Suspicious pattern
        
        return 0.0  # Neutral
    
    def _check_timestamp_anomalies(self, context: Dict) -> float:
        """
        Check for timestamp anomalies (process creation time vs. system boot).
        Returns: -0.2 to +0.2
        """
        create_time_str = context.get("create_time", "")
        if not create_time_str:
            return 0.0
        
        try:
            create_time = datetime.fromisoformat(create_time_str.replace("+00:00", ""))
            
            # Check if creation time is in the future (clock tampering)
            if create_time > datetime.now():
                return -0.2  # Suspicious
            
            # Check if creation time is too old (>30 days before current time)
            age = datetime.now() - create_time
            if age.days > 30:
                return 0.1  # Likely legitimate (old process)
            
            return 0.0
        except (ValueError, AttributeError):
            return 0.0  # Cannot parse timestamp
    
    def _check_network_behavior(self, context: Dict) -> float:
        """
        Analyze network behavior for anomalies.
        Returns: -0.2 to +0.2
        """
        connections = context.get("network_connections", [])
        
        if not connections:
            return 0.0  # No network activity
        
        suspicious_indicators = 0
        legitimate_indicators = 0
        
        for conn in connections:
            port = conn.get("foreign_port", 0)
            state = conn.get("state", "").lower()
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 31337, 1337]
            if port in suspicious_ports:
                suspicious_indicators += 1
            
            # Legitimate network behavior (HTTP, HTTPS, DNS)
            legitimate_ports = [80, 443, 53, 123]
            if port in legitimate_ports and state == "established":
                legitimate_indicators += 1
        
        # Calculate net confidence
        if suspicious_indicators > legitimate_indicators:
            return -0.2
        elif legitimate_indicators > suspicious_indicators:
            return 0.2
        
        return 0.0
    
    def _check_memory_characteristics(self, context: Dict) -> float:
        """
        Analyze memory characteristics for anomalies.
        Returns: -0.2 to +0.2
        """
        threads = context.get("threads", 0)
        handles = context.get("handles", 0)
        
        # Excessive threads (cryptominer indicator)
        if threads > 100:
            return -0.2
        
        # Excessive handles (keylogger indicator)
        if handles > 5000:
            return -0.2
        
        # Normal ranges
        if 1 <= threads <= 50 and 1 <= handles <= 1000:
            return 0.1
        
        return 0.0
    
    def _check_runtime_behavior(self, context: Dict) -> float:
        """
        Analyze runtime behavior patterns.
        Returns: -0.2 to +0.2
        """
        command_line = context.get("command_line", "").lower()
        
        if not command_line:
            return 0.0
        
        # Suspicious command line patterns
        suspicious_patterns = [
            r"-enc\s+[a-z0-9+/=]+",  # Encoded PowerShell
            r"invoke-expression",
            r"downloadstring",
            r"webclient",
            r"hidden",
            r"-nop\s+-w\s+hidden",
            r"bypass.*executionpolicy",
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                return -0.2  # Suspicious runtime behavior
        
        # Legitimate command line patterns
        legitimate_patterns = [
            r"^svchost\.exe.*-k",
            r"^explorer\.exe$",
            r"^system$",
        ]
        
        for pattern in legitimate_patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                return 0.1
        
        return 0.0
    
    def correlate_evidence(self, findings: List[Dict]) -> Dict[int, Dict]:
        """
        Correlate multiple weak indicators to increase confidence.
        
        Returns:
            Dictionary mapping PID to correlated evidence with adjusted confidence
        """
        correlated = defaultdict(lambda: {
            "findings": [],
            "total_confidence": 0.0,
            "total_score": 0,
            "categories": set(),
            "indicator_count": 0
        })
        
        # Group findings by PID
        for finding in findings:
            pid = finding.get("pid", 0)
            confidence = finding.get("confidence_score", 0.5)
            score = finding.get("score_impact", 0)
            category = finding.get("category", "unknown")
            
            correlated[pid]["findings"].append(finding)
            correlated[pid]["total_confidence"] += confidence
            correlated[pid]["total_score"] += score
            correlated[pid]["categories"].add(category)
            correlated[pid]["indicator_count"] += 1
        
        # Apply correlation boosting
        for pid, data in correlated.items():
            indicator_count = data["indicator_count"]
            
            # Boost confidence if multiple independent indicators
            if indicator_count >= 3:
                # Multiple weak indicators = stronger evidence
                correlation_boost = min(0.3, indicator_count * 0.1)
                data["total_confidence"] += correlation_boost
                data["correlation_boost"] = correlation_boost
            
            # Normalize confidence
            data["avg_confidence"] = data["total_confidence"] / max(1, indicator_count)
            data["final_confidence"] = min(1.0, data["total_confidence"])
        
        return dict(correlated)
    
    def apply_scoring_decay(self, finding: Dict, history: List[Dict]) -> float:
        """
        Apply scoring decay for common false positives based on historical data.
        
        Args:
            finding: Current finding
            history: Historical findings from previous analyses
        
        Returns:
            Decay multiplier (0.0 - 1.0)
        """
        proc_name = finding.get("name", "").lower()
        reason = finding.get("reason", "").lower()
        
        # Count how many times this finding appeared in history
        occurrence_count = sum(
            1 for h in history 
            if h.get("name", "").lower() == proc_name and 
            h.get("reason", "").lower() == reason
        )
        
        # Apply decay based on frequency
        if occurrence_count >= 5:
            return 0.2  # 80% decay (common false positive)
        elif occurrence_count >= 3:
            return 0.5  # 50% decay
        elif occurrence_count >= 2:
            return 0.7  # 30% decay
        
        return 1.0  # No decay
    
    def weighted_score(self, finding: Dict, confidence: float) -> int:
        """
        Calculate weighted score based on severity and confidence.
        
        Low confidence findings get reduced scores.
        High confidence findings get normal or boosted scores.
        """
        base_severity = finding.get("severity", "MEDIUM").upper()
        base_scores = {
            "CRITICAL": 40,
            "HIGH": 25,
            "MEDIUM": 15,
            "LOW": 8,
            "INFO": 3
        }
        
        base_score = base_scores.get(base_severity, 10)
        
        # Apply confidence multiplier
        if confidence >= 0.8:
            multiplier = 1.2  # Boost high-confidence findings
        elif confidence >= 0.6:
            multiplier = 1.0  # Normal score
        elif confidence >= 0.4:
            multiplier = 0.7  # Reduce medium-confidence findings
        elif confidence >= 0.2:
            multiplier = 0.4  # Significantly reduce low-confidence
        else:
            multiplier = 0.1  # Almost ignore very low confidence
        
        weighted = int(base_score * multiplier)
        
        # Store for debugging
        finding["base_score"] = base_score
        finding["confidence_multiplier"] = multiplier
        finding["weighted_score"] = weighted
        
        return weighted
    
    def should_alert(self, finding: Dict, confidence: float, 
                    threshold: float = 0.3) -> bool:
        """
        Determine if finding should trigger an alert.
        
        Requires minimum confidence threshold to reduce false positives.
        """
        severity = finding.get("severity", "MEDIUM").upper()
        
        # CRITICAL findings always alert (even low confidence)
        if severity == "CRITICAL" and confidence >= 0.2:
            return True
        
        # HIGH findings need moderate confidence
        if severity == "HIGH" and confidence >= 0.4:
            return True
        
        # MEDIUM/LOW findings need higher confidence
        if severity in ["MEDIUM", "LOW"] and confidence >= threshold:
            return True
        
        return False
    
    def generate_confidence_report(self, correlated_evidence: Dict) -> str:
        """Generate a human-readable confidence report."""
        lines = []
        lines.append("=" * 60)
        lines.append("CONFIDENCE SCORING REPORT")
        lines.append("=" * 60)
        
        for pid, data in sorted(correlated_evidence.items(), 
                               key=lambda x: x[1]["final_confidence"], 
                               reverse=True):
            lines.append(f"\nPID {pid}:")
            lines.append(f"  Indicators: {data['indicator_count']}")
            lines.append(f"  Categories: {', '.join(data['categories'])}")
            lines.append(f"  Confidence: {data['final_confidence']:.2f}")
            lines.append(f"  Total Score: {data['total_score']}")
            
            if "correlation_boost" in data:
                lines.append(f"  Correlation Boost: +{data['correlation_boost']:.2f}")
        
        return "\n".join(lines)
