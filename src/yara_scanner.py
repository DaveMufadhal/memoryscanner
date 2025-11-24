import os
from typing import List, Dict, Any, Optional
import yara


class YaraScanner:
    """
    Wrapper for YARA scanning.
    You can compile multiple rule files from a directory for better performance.
    """

    def __init__(self, rules_directory: str) -> None:
        self.rules_directory = rules_directory
        self.compiled_rules: Optional[yara.Rules] = None

    def compile_rules(self) -> None:
        """
        Compile all .yar / .yara files in the directory into a single Rules object.
        """
        rule_files: Dict[str, str] = {}
        for filename in os.listdir(self.rules_directory):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                full_path = os.path.join(self.rules_directory, filename)
                rule_name = os.path.splitext(filename)[0]
                rule_files[rule_name] = full_path

        if not rule_files:
            return

        # Compile rules once for efficiency
        self.compiled_rules = yara.compile(filepaths=rule_files)

    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Scan a block of bytes with the compiled YARA rules.

        :param data: Binary data to scan.
        :return: List of match dictionaries.
        """
        if self.compiled_rules is None:
            # No rules compiled; return empty result
            return []

        matches = self.compiled_rules.match(data=data)
        findings: List[Dict[str, Any]] = []
        for match in matches:
            findings.append(
                {
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                }
            )
        return findings
