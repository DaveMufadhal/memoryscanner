import subprocess
import json
from typing import Dict, List, Optional

class VolatilityRunner:
    """
    Wrapper around Volatility3 command-line to run plugins
    and parse JSON output.
    """

    def __init__(self, binary_path: str = "vol"):
        """
        :param binary_path: path or command to invoke Volatility3 (e.g., 'vol' or 'python vol.py')
        """
        self.binary_path = binary_path

    def run_plugin(
        self,
        image_path: str,
        plugin_name: str,
        additional_args: Optional[List[str]] = None,  # Changed from List[str] | None
    ) -> Dict:
        """
        Run a single Volatility3 plugin and return parsed JSON output.
        """
        cmd = [self.binary_path, "-f", image_path, "-r", "json", plugin_name]
        if additional_args:
            cmd.extend(additional_args)

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            # Log error or handle gracefully
            return {"error": result.stderr, "plugin": plugin_name}

        # Parse JSON output
        try:
            data = json.loads(result.stdout)
            return data
        except json.JSONDecodeError:
            return {"error": "Invalid JSON output", "plugin": plugin_name}

    def run_plugins_bulk(self, image_path: str, plugin_list: List[str]) -> Dict[str, Dict]:
        """
        Run multiple plugins in sequence, return a dict keyed by plugin name.
        """
        outputs = {}
        for plugin in plugin_list:
            outputs[plugin] = self.run_plugin(image_path, plugin)
        return outputs