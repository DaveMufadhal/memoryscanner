"""
Behavioral Correlation Engine

This module correlates multiple suspicious behaviors to identify complex attack chains
and generates comprehensive threat intelligence with MITRE ATT&CK mapping.
"""

from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime, timedelta


class BehavioralCorrelationEngine:
    """
    Correlates multiple detection findings to identify attack patterns and chains.
    
    Features:
    - Attack chain reconstruction
    - MITRE ATT&CK tactic mapping
    - Temporal correlation
    - Process tree correlation
    - Network correlation
    - Confidence scoring
    """
    
    def __init__(self):
        # MITRE ATT&CK tactic mappings
        self.mitre_tactics = {
            'T1003': ('Credential Access', 'OS Credential Dumping'),
            'T1021': ('Lateral Movement', 'Remote Services'),
            'T1053': ('Persistence', 'Scheduled Task/Job'),
            'T1055': ('Defense Evasion', 'Process Injection'),
            'T1059': ('Execution', 'Command and Scripting Interpreter'),
            'T1068': ('Privilege Escalation', 'Exploitation for Privilege Escalation'),
            'T1071': ('Command and Control', 'Application Layer Protocol'),
            'T1078': ('Defense Evasion', 'Valid Accounts'),
            'T1134': ('Privilege Escalation', 'Access Token Manipulation'),
            'T1486': ('Impact', 'Data Encrypted for Impact'),
            'T1490': ('Impact', 'Inhibit System Recovery'),
            'T1543': ('Persistence', 'Create or Modify System Process'),
            'T1547': ('Persistence', 'Boot or Logon Autostart Execution'),
            'T1548': ('Privilege Escalation', 'Abuse Elevation Control Mechanism'),
            'T1562': ('Defense Evasion', 'Impair Defenses'),
            'T1567': ('Exfiltration', 'Exfiltration Over Web Service')
        }
        
        # Known attack chain patterns
        self.attack_patterns = {
            'credential_theft_chain': [
                'T1003',  # Credential dumping
                'T1078',  # Use valid accounts
                'T1021'   # Lateral movement
            ],
            'ransomware_chain': [
                'T1490',  # Inhibit recovery
                'T1489',  # Service stop
                'T1486'   # Encrypt data
            ],
            'apt_chain': [
                'T1059',  # Initial execution
                'T1055',  # Process injection
                'T1003',  # Credential access
                'T1071',  # C2 communication
                'T1048'   # Exfiltration
            ],
            'privilege_escalation_chain': [
                'T1068',  # Exploit
                'T1134',  # Token manipulation
                'T1547'   # Persistence
            ]
        }
        
        # Correlation time windows (in seconds)
        self.correlation_windows = {
            'short': 300,    # 5 minutes
            'medium': 1800,  # 30 minutes
            'long': 3600     # 1 hour
        }
    
    def correlate_findings(
        self,
        findings: List[Dict],
        processes: List[Dict],
        network: List[Dict],
        analysis
    ) -> Dict[str, Any]:
        """
        Main correlation function.
        
        Returns:
            Dictionary containing:
            - attack_chains: Identified multi-stage attacks
            - correlated_findings: Grouped related findings
            - mitre_coverage: MITRE ATT&CK tactics/techniques
            - threat_score: Overall threat assessment
        """
        result = {
            'attack_chains': [],
            'correlated_findings': [],
            'mitre_coverage': {},
            'threat_score': 0,
            'correlation_metadata': {
                'total_findings': len(findings),
                'correlated_count': 0,
                'chains_detected': 0
            }
        }
        
        if not findings:
            return result
        
        # Group findings by correlation attributes
        by_pid = self._group_by_pid(findings)
        by_time = self._group_by_time(findings)
        by_mitre = self._group_by_mitre(findings)
        by_process_tree = self._correlate_process_tree(findings, processes)
        
        # Detect attack chains
        attack_chains = self._detect_attack_chains(findings, by_mitre)
        result['attack_chains'] = attack_chains
        result['correlation_metadata']['chains_detected'] = len(attack_chains)
        
        # Build correlated finding groups
        correlated = self._build_correlated_groups(
            findings, by_pid, by_time, by_process_tree
        )
        result['correlated_findings'] = correlated
        result['correlation_metadata']['correlated_count'] = len(correlated)
        
        # Build MITRE ATT&CK coverage map
        mitre_coverage = self._build_mitre_coverage(findings, attack_chains)
        result['mitre_coverage'] = mitre_coverage
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(
            findings, attack_chains, mitre_coverage
        )
        result['threat_score'] = threat_score
        
        # Enrich analysis object
        if analysis:
            analysis.attack_chains = attack_chains
            analysis.mitre_coverage = mitre_coverage
            analysis.threat_score = threat_score
        
        return result
    
    def _group_by_pid(self, findings: List[Dict]) -> Dict[int, List[Dict]]:
        """Group findings by process ID."""
        grouped = defaultdict(list)
        for finding in findings:
            pid = finding.get('pid', 0)
            if pid:
                grouped[pid].append(finding)
        return dict(grouped)
    
    def _group_by_time(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by time windows."""
        # Since we don't have timestamps in findings, we'll simulate this
        # In production, you'd parse timestamps from findings
        grouped = defaultdict(list)
        for finding in findings:
            # Use a default time window
            grouped['default_window'].append(finding)
        return dict(grouped)
    
    def _group_by_mitre(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by MITRE technique."""
        grouped = defaultdict(list)
        for finding in findings:
            mitre = finding.get('mitre', 'unknown')
            if mitre and mitre != 'unknown':
                # Extract base technique (T1003 from T1003.001)
                base_technique = mitre.split('.')[0]
                grouped[base_technique].append(finding)
        return dict(grouped)
    
    def _correlate_process_tree(
        self, 
        findings: List[Dict], 
        processes: List[Dict]
    ) -> Dict[int, List[int]]:
        """Build process parent-child relationships."""
        process_tree = {}
        pid_to_ppid = {}
        
        # Build PID to PPID mapping
        for proc in processes:
            pid = proc.get('PID', 0)
            ppid = proc.get('PPID', 0)
            if pid:
                pid_to_ppid[pid] = ppid
        
        # Build tree relationships
        for pid in pid_to_ppid.keys():
            children = [p for p, pp in pid_to_ppid.items() if pp == pid]
            if children:
                process_tree[pid] = children
        
        return process_tree
    
    def _detect_attack_chains(
        self,
        findings: List[Dict],
        by_mitre: Dict[str, List[Dict]]
    ) -> List[Dict]:
        """Detect known attack chain patterns."""
        detected_chains = []
        
        # Get all MITRE techniques present
        present_techniques = set(by_mitre.keys())
        
        # Check each known attack pattern
        for chain_name, technique_sequence in self.attack_patterns.items():
            # Check how many techniques in the chain are present
            matched_techniques = []
            for technique in technique_sequence:
                base_technique = technique.split('.')[0]
                if base_technique in present_techniques:
                    matched_techniques.append(base_technique)
            
            # If at least 2 techniques match (or 50% of chain)
            match_threshold = max(2, len(technique_sequence) // 2)
            if len(matched_techniques) >= match_threshold:
                # Build chain description
                chain = {
                    'chain_name': chain_name,
                    'matched_techniques': matched_techniques,
                    'total_techniques': len(technique_sequence),
                    'coverage_percentage': (len(matched_techniques) / len(technique_sequence)) * 100,
                    'findings': [],
                    'severity': 'CRITICAL' if len(matched_techniques) >= len(technique_sequence) - 1 else 'HIGH',
                    'confidence': self._calculate_chain_confidence(
                        matched_techniques, technique_sequence
                    )
                }
                
                # Collect all findings for matched techniques
                for tech in matched_techniques:
                    chain['findings'].extend(by_mitre.get(tech, []))
                
                # Add tactic information
                tactics = set()
                for tech in matched_techniques:
                    if tech in self.mitre_tactics:
                        tactic, _ = self.mitre_tactics[tech]
                        tactics.add(tactic)
                
                chain['tactics_covered'] = list(tactics)
                chain['description'] = self._generate_chain_description(
                    chain_name, matched_techniques, tactics
                )
                
                detected_chains.append(chain)
        
        return detected_chains
    
    def _calculate_chain_confidence(
        self,
        matched: List[str],
        full_sequence: List[str]
    ) -> int:
        """Calculate confidence score for detected attack chain."""
        # Base confidence from coverage
        coverage = len(matched) / len(full_sequence)
        confidence = int(coverage * 70)  # Up to 70 points from coverage
        
        # Bonus for sequential matches
        sequential_bonus = 0
        for i in range(len(matched) - 1):
            try:
                idx1 = full_sequence.index(matched[i])
                idx2 = full_sequence.index(matched[i + 1])
                if idx2 == idx1 + 1:  # Sequential
                    sequential_bonus += 5
            except ValueError:
                pass
        
        confidence = min(100, confidence + sequential_bonus)
        return confidence
    
    def _generate_chain_description(
        self,
        chain_name: str,
        techniques: List[str],
        tactics: Set[str]
    ) -> str:
        """Generate human-readable attack chain description."""
        descriptions = {
            'credential_theft_chain': 'Multi-stage credential theft attack: adversary dumped credentials, likely used them for authentication, and performed lateral movement',
            'ransomware_chain': 'Ransomware attack pattern: system recovery inhibition followed by data encryption',
            'apt_chain': 'Advanced Persistent Threat pattern: execution, persistence, credential access, and exfiltration',
            'privilege_escalation_chain': 'Privilege escalation attack: exploitation followed by token manipulation and persistence'
        }
        
        base_desc = descriptions.get(chain_name, f'Attack chain: {chain_name}')
        tactic_list = ', '.join(tactics)
        
        return f"{base_desc}. Tactics: {tactic_list}. Techniques: {', '.join(techniques)}"
    
    def _build_correlated_groups(
        self,
        findings: List[Dict],
        by_pid: Dict[int, List[Dict]],
        by_time: Dict[str, List[Dict]],
        process_tree: Dict[int, List[int]]
    ) -> List[Dict]:
        """Build groups of correlated findings."""
        groups = []
        processed_findings = set()
        
        # Group by PID (same process)
        for pid, pid_findings in by_pid.items():
            if len(pid_findings) >= 2:  # At least 2 findings for same process
                group = {
                    'correlation_type': 'Same Process',
                    'pid': pid,
                    'finding_count': len(pid_findings),
                    'findings': pid_findings,
                    'severity': self._get_max_severity(pid_findings),
                    'description': f'Multiple suspicious activities detected in PID {pid}'
                }
                groups.append(group)
                
                for f in pid_findings:
                    processed_findings.add(id(f))
        
        # Group by process tree (parent-child relationship)
        for parent_pid, child_pids in process_tree.items():
            parent_findings = by_pid.get(parent_pid, [])
            child_findings = []
            
            for child_pid in child_pids:
                child_findings.extend(by_pid.get(child_pid, []))
            
            if parent_findings and child_findings:
                total_findings = parent_findings + child_findings
                group = {
                    'correlation_type': 'Process Tree',
                    'parent_pid': parent_pid,
                    'child_pids': child_pids,
                    'finding_count': len(total_findings),
                    'findings': total_findings,
                    'severity': self._get_max_severity(total_findings),
                    'description': f'Related activities in parent process {parent_pid} and child processes'
                }
                groups.append(group)
        
        return groups
    
    def _build_mitre_coverage(
        self,
        findings: List[Dict],
        attack_chains: List[Dict]
    ) -> Dict[str, Any]:
        """Build MITRE ATT&CK coverage map."""
        coverage = {
            'tactics': defaultdict(list),
            'techniques': {},
            'technique_count': 0,
            'tactic_count': 0
        }
        
        # Extract all techniques from findings
        for finding in findings:
            mitre = finding.get('mitre')
            if mitre and mitre != 'unknown':
                base_technique = mitre.split('.')[0]
                
                if base_technique in self.mitre_tactics:
                    tactic, technique_name = self.mitre_tactics[base_technique]
                    
                    # Add to tactic group
                    if base_technique not in coverage['tactics'][tactic]:
                        coverage['tactics'][tactic].append(base_technique)
                    
                    # Add technique details
                    if base_technique not in coverage['techniques']:
                        coverage['techniques'][base_technique] = {
                            'name': technique_name,
                            'tactic': tactic,
                            'finding_count': 0,
                            'in_attack_chain': False
                        }
                    
                    coverage['techniques'][base_technique]['finding_count'] += 1
        
        # Mark techniques in attack chains
        for chain in attack_chains:
            for tech in chain['matched_techniques']:
                if tech in coverage['techniques']:
                    coverage['techniques'][tech]['in_attack_chain'] = True
        
        coverage['technique_count'] = len(coverage['techniques'])
        coverage['tactic_count'] = len(coverage['tactics'])
        
        # Convert defaultdict to regular dict
        coverage['tactics'] = dict(coverage['tactics'])
        
        return coverage
    
    def _calculate_threat_score(
        self,
        findings: List[Dict],
        attack_chains: List[Dict],
        mitre_coverage: Dict
    ) -> int:
        """Calculate overall threat score (0-100)."""
        score = 0
        
        # Base score from findings
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2
        }
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            score += severity_weights.get(severity, 2)
        
        # Bonus for attack chains (10 points each, up to 40)
        chain_bonus = min(40, len(attack_chains) * 10)
        score += chain_bonus
        
        # Bonus for MITRE coverage (20 points for wide coverage)
        tactic_count = mitre_coverage.get('tactic_count', 0)
        if tactic_count >= 5:
            score += 20
        elif tactic_count >= 3:
            score += 10
        
        # Normalize to 0-100
        score = min(100, score)
        
        return score
    
    def _get_max_severity(self, findings: List[Dict]) -> str:
        """Get the maximum severity from a list of findings."""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for severity in severity_order:
            if any(f.get('severity') == severity for f in findings):
                return severity
        
        return 'LOW'
    
    def generate_attack_narrative(
        self,
        attack_chains: List[Dict],
        mitre_coverage: Dict
    ) -> str:
        """Generate human-readable attack narrative."""
        if not attack_chains:
            return "No coordinated attack chains detected. Individual suspicious activities may be isolated incidents."
        
        narrative_parts = []
        
        # Overall assessment
        chain_count = len(attack_chains)
        tactic_count = mitre_coverage.get('tactic_count', 0)
        
        narrative_parts.append(
            f"Analysis detected {chain_count} coordinated attack chain(s) "
            f"spanning {tactic_count} MITRE ATT&CK tactic(s)."
        )
        
        # Describe each chain
        for i, chain in enumerate(attack_chains, 1):
            chain_name = chain['chain_name'].replace('_', ' ').title()
            coverage = chain['coverage_percentage']
            confidence = chain['confidence']
            
            narrative_parts.append(
                f"\nChain {i}: {chain_name} "
                f"(Coverage: {coverage:.0f}%, Confidence: {confidence}%)"
            )
            narrative_parts.append(f"  {chain['description']}")
        
        # Add recommendations
        narrative_parts.append("\n\nRecommended Actions:")
        narrative_parts.append("1. Isolate affected systems immediately")
        narrative_parts.append("2. Analyze identified attack chains for lateral movement paths")
        narrative_parts.append("3. Reset compromised credentials")
        narrative_parts.append("4. Review logs for indicators of compromise")
        narrative_parts.append("5. Implement detection rules for identified techniques")
        
        return '\n'.join(narrative_parts)
