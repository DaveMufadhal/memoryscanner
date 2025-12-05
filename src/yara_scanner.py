import os
import subprocess
import json
from typing import List, Dict, Any, Optional
from pathlib import Path


class YaraScanner:
    """
    Enhanced YARA scanner for memory forensics with support for:
    - Direct memory dump scanning
    - Process memory scanning via Volatility
    - Rule categorization and severity mapping
    - MITRE ATT&CK technique extraction
    """

    def __init__(self, rules_directory: str = "yara_rules") -> None:
        self.rules_directory = rules_directory
        self.rules_file = self._find_rules_file()
        self.compiled_rules: Optional[Any] = None
        
        # Statistics
        self.total_scans = 0
        self.total_matches = 0
        self.matches_by_category = {}
    
    def _find_rules_file(self) -> Optional[str]:
        """Find the YARA rules file (prefer all.yara)."""
        rules_path = Path(self.rules_directory)
        
        if not rules_path.exists():
            return None
        
        # Check for all.yara first
        all_yara = rules_path / "all.yara"
        if all_yara.exists():
            return str(all_yara)
        
        # Fallback to other .yara or .yar files
        for ext in [".yara", ".yar"]:
            rule_files = list(rules_path.glob(f"*{ext}"))
            if rule_files:
                return str(rule_files[0])
        
        return None
    
    def compile_rules(self) -> bool:
        """
        Compile YARA rules for scanning.
        
        Returns:
            True if rules compiled successfully, False otherwise
        """
        if not self.rules_file:
            return False
        
        try:
            import yara
            self.compiled_rules = yara.compile(filepath=self.rules_file)
            return True
        except ImportError:
            # YARA Python module not available, will use CLI
            return self._check_yara_cli()
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            return False
    
    def _check_yara_cli(self) -> bool:
        """Check if YARA CLI is available."""
        try:
            result = subprocess.run(
                ["yara", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def scan_memory_dump(
        self, 
        memory_dump_path: str,
        fast_scan: bool = False,
        timeout: int = 600
    ) -> List[Dict[str, Any]]:
        """
        Scan entire memory dump with YARA rules.
        
        Args:
            memory_dump_path: Path to memory dump file
            fast_scan: Enable fast scanning mode (less thorough)
            timeout: Scan timeout in seconds (default: 10 minutes)
        
        Returns:
            List of YARA match dictionaries with enriched metadata
        """
        if not self.rules_file or not os.path.exists(memory_dump_path):
            return []
        
        self.total_scans += 1
        
        try:
            # Use YARA CLI for large memory dumps
            cmd = ["yara"]
            
            if fast_scan:
                cmd.append("--fast-scan")
            
            # Add other useful options
            cmd.extend([
                "--print-meta",           # Print metadata
                "--print-strings",        # Print matching strings
                "--print-string-length",  # Print string lengths
                self.rules_file,
                memory_dump_path
            ])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                return []
            
            # Parse YARA CLI output
            matches = self._parse_yara_output(result.stdout)
            self.total_matches += len(matches)
            
            # Enrich matches with categorization
            enriched_matches = [self._enrich_match(m) for m in matches]
            
            # Update statistics
            for match in enriched_matches:
                category = match.get('category', 'unknown')
                self.matches_by_category[category] = self.matches_by_category.get(category, 0) + 1
            
            return enriched_matches
        
        except subprocess.TimeoutExpired:
            return [{"error": "YARA scan timeout", "timeout": timeout}]
        except Exception as e:
            return [{"error": str(e)}]
    
    def scan_process_memory(
        self,
        volatility_runner,
        image_path: str,
        pid: Optional[int] = None,
        yara_options: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan process memory using Volatility's yarascan plugin.
        
        Args:
            volatility_runner: VolatilityRunner instance
            image_path: Path to memory dump
            pid: Specific process ID to scan (None = scan all)
            yara_options: Additional YARA options
        
        Returns:
            List of YARA matches from process memory
        """
        if not self.rules_file:
            return []
        
        try:
            # Build yarascan command
            additional_args = ["--yara-file", self.rules_file]
            
            if pid:
                additional_args.extend(["--pid", str(pid)])
            
            if yara_options:
                additional_args.extend(yara_options.split())
            
            # Run Volatility yarascan
            result = volatility_runner.run_plugin(
                image_path=image_path,
                plugin_name="yarascan.YaraScan",
                additional_args=additional_args
            )
            
            if "error" in result:
                return []
            
            # Extract and enrich matches
            matches = self._extract_volatility_yara_matches(result)
            return [self._enrich_match(m) for m in matches]
        
        except Exception as e:
            return [{"error": str(e)}]
    
    def _parse_yara_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse YARA CLI output into structured matches."""
        matches = []
        current_match = None
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            # New rule match: "rule_name file_path"
            if not line.startswith(' ') and not line.startswith('\t'):
                if current_match:
                    matches.append(current_match)
                
                parts = line.split()
                if len(parts) >= 2:
                    current_match = {
                        'rule_name': parts[0],
                        'rule': parts[0],  # Keep for backward compatibility
                        'file': ' '.join(parts[1:]),
                        'strings': [],
                        'meta': {}
                    }
            
            # Metadata line
            elif current_match and '=' in line:
                line = line.strip()
                if line:
                    key, _, value = line.partition('=')
                    current_match['meta'][key.strip()] = value.strip().strip('"')
            
            # String match line
            elif current_match and ':' in line:
                current_match['strings'].append(line.strip())
        
        # Add last match
        if current_match:
            matches.append(current_match)
        
        return matches
    
    def _extract_volatility_yara_matches(self, vol_output: Dict) -> List[Dict[str, Any]]:
        """Extract YARA matches from Volatility yarascan output."""
        matches = []
        
        # Volatility yarascan returns list of matches
        if isinstance(vol_output, list):
            for item in vol_output:
                match = {
                    'rule_name': item.get('Rule', 'unknown'),
                    'rule': item.get('Rule', 'unknown'),  # Keep for backward compatibility
                    'pid': item.get('PID', 0),
                    'process': item.get('Process', 'unknown'),
                    'offset': item.get('Offset', 0),
                    'strings': item.get('Strings', []),
                    'meta': {}
                }
                matches.append(match)
        
        return matches
    
    def _enrich_match(self, match: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich YARA match with additional context.
        
        Adds:
        - Severity level based on rule category
        - MITRE ATT&CK technique from metadata
        - Threat category classification
        - Risk score
        """
        rule_name = match.get('rule_name') or match.get('rule', '')
        meta = match.get('meta', {})
        
        # Ensure rule_name field exists
        if 'rule_name' not in match:
            match['rule_name'] = rule_name
        
        # Extract category from metadata or rule name
        category = meta.get('rule_category', 'unknown')
        if category == 'unknown':
            if 'offensive_tool' in rule_name.lower():
                category = 'offensive_tool_keyword'
            elif 'greyware' in rule_name.lower():
                category = 'greyware_tool_keyword'
            elif 'malware' in rule_name.lower():
                category = 'malware'
        
        # Determine severity
        severity = self._categorize_severity(category, meta)
        
        # Extract MITRE ATT&CK technique
        mitre_technique = self._extract_mitre_technique(meta, rule_name)
        
        # Calculate risk score
        risk_score = self._calculate_match_risk(severity, category, meta)
        
        # Add enrichment
        match['category'] = category
        match['severity'] = severity
        match['risk_score'] = risk_score
        
        if mitre_technique:
            match['mitre_technique'] = mitre_technique
        
        # Add tool/threat name
        if 'tool' in meta:
            match['tool_name'] = meta['tool']
        elif 'description' in meta:
            match['description'] = meta['description']
        
        # Format matched strings for template
        if 'strings' in match and match['strings']:
            match['matched_strings'] = match['strings']
        
        return match
    
    def _categorize_severity(self, category: str, meta: Dict) -> str:
        """Determine severity level from category and metadata."""
        category_lower = category.lower()
        
        # Check for explicit severity in metadata
        if 'severity' in meta:
            return meta['severity'].upper()
        
        # Category-based severity
        if 'malware' in category_lower or 'exploit' in category_lower:
            return 'CRITICAL'
        elif 'offensive_tool' in category_lower:
            return 'HIGH'
        elif 'greyware' in category_lower:
            return 'MEDIUM'
        elif 'signature' in category_lower:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _extract_mitre_technique(self, meta: Dict, rule_name: str) -> Optional[str]:
        """Extract MITRE ATT&CK technique from metadata or rule name."""
        # Check metadata first
        if 'mitre_attack' in meta:
            return meta['mitre_attack']
        if 'attack_technique' in meta:
            return meta['attack_technique']
        
        # Try to extract from rule name (e.g., T1055, T1003)
        import re
        technique_match = re.search(r'T\d{4}(?:\.\d{3})?', rule_name.upper())
        if technique_match:
            return technique_match.group(0)
        
        return None
    
    def _calculate_match_risk(self, severity: str, category: str, meta: Dict) -> int:
        """Calculate risk score for YARA match (0-100)."""
        base_scores = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 50,
            'LOW': 30
        }
        
        score = base_scores.get(severity, 50)
        
        # Adjust based on category
        if 'malware' in category.lower():
            score += 10
        elif 'offensive_tool' in category.lower():
            score += 5
        
        # Adjust based on confidence
        if 'confidence' in meta:
            try:
                confidence = int(meta['confidence'])
                score = int(score * (confidence / 100))
            except (ValueError, TypeError):
                pass
        
        return min(100, max(0, score))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        return {
            'total_scans': self.total_scans,
            'total_matches': self.total_matches,
            'matches_by_category': self.matches_by_category,
            'rules_file': self.rules_file,
            'average_matches_per_scan': (
                self.total_matches / self.total_scans 
                if self.total_scans > 0 else 0
            )
        }
    
    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Scan a block of bytes with compiled YARA rules (legacy method).

        :param data: Binary data to scan.
        :return: List of match dictionaries.
        """
        if self.compiled_rules is None:
            return []

        try:
            matches = self.compiled_rules.match(data=data)
            findings: List[Dict[str, Any]] = []
            for match in matches:
                finding = {
                    "rule_name": match.rule,
                    "rule": match.rule,  # Keep for backward compatibility
                    "tags": match.tags,
                    "meta": match.meta,
                }
                findings.append(self._enrich_match(finding))
            return findings
        except Exception:
            return []
