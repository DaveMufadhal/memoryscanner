import subprocess
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from datetime import datetime, timedelta


class DumpValidationError(Exception):
    """Raised when memory dump validation fails."""
    pass


class PluginTimeoutError(Exception):
    """Raised when plugin execution exceeds timeout."""
    pass


class VolatilityRunner:
    """
    Enhanced wrapper around Volatility3 with robust error handling,
    retry mechanisms, timeout handling, and dump validation.
    """

    def __init__(
        self, 
        binary_path: str = "vol",
        max_retries: int = 3,
        timeout_seconds: int = 300,
        retry_delay: int = 5,
        enable_progress_tracking: bool = True
    ):
        """
        Initialize Volatility runner with advanced features.
        
        Args:
            binary_path: Path to Volatility3 binary
            max_retries: Maximum retry attempts for failed plugins
            timeout_seconds: Plugin execution timeout (default: 5 minutes)
            retry_delay: Delay between retry attempts in seconds
            enable_progress_tracking: Enable progress tracking with ETA
        """
        self.binary_path = binary_path
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self.retry_delay = retry_delay
        self.enable_progress_tracking = enable_progress_tracking
        
        # Statistics
        self.stats = {
            'plugins_executed': 0,
            'plugins_succeeded': 0,
            'plugins_failed': 0,
            'plugins_retried': 0,
            'plugins_timed_out': 0,
            'total_execution_time': 0.0
        }
    
    def validate_dump_format(self, image_path: str) -> Tuple[bool, str, Optional[str]]:
        """
        Validate memory dump format and detect OS profile.
        
        Returns:
            Tuple of (is_valid, message, detected_profile)
        """
        image = Path(image_path)
        
        # Check file existence
        if not image.exists():
            return False, f"File not found: {image_path}", None
        
        # Check file size
        file_size = image.stat().st_size
        if file_size < 1024 * 1024:  # Less than 1MB
            return False, f"File too small ({file_size} bytes)", None
        
        # Check file is readable
        try:
            with open(image_path, 'rb') as f:
                header = f.read(4096)
        except Exception as e:
            return False, f"Cannot read file: {e}", None
        
        # Detect OS from header signatures
        detected_os = self._detect_os_from_header(header)
        
        # Try to auto-detect profile using Volatility
        profile = self._auto_detect_profile(image_path)
        
        if profile:
            return True, f"Valid dump detected: {detected_os or 'Unknown OS'}", profile
        else:
            # Even without profile, might be valid dump
            return True, f"Dump appears valid but profile detection failed: {detected_os or 'Unknown OS'}", None
    
    def _detect_os_from_header(self, header: bytes) -> Optional[str]:
        """Detect OS from memory dump header."""
        # Windows signatures
        if b'PAGEDU' in header[:1024] or b'PAGEDUMP' in header[:1024]:
            return "Windows (Complete Memory Dump)"
        if b'PAGE' in header[:100]:
            return "Windows"
        if b'MZ' in header[:2]:
            return "Windows PE"
        
        # Linux signatures
        if b'LINUX' in header[:1024] or b'ELF' in header[:100]:
            return "Linux"
        
        # VMware signatures
        if b'VMware' in header[:1024] or b'.vmem' in header[:1024]:
            return "VMware Snapshot"
        
        # VirtualBox signatures
        if b'VirtualBox' in header[:1024]:
            return "VirtualBox Snapshot"
        
        return None
    
    def _auto_detect_profile(self, image_path: str) -> Optional[str]:
        """
        Auto-detect memory profile using Volatility's banners/imageinfo.
        
        Returns:
            Detected profile string or None
        """
        try:
            # Try windows.info plugin for Windows dumps
            cmd = [self.binary_path, "-f", image_path, "windows.info.Info"]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                # Parse output for OS information
                if "Windows" in result.stdout:
                    return "Windows (auto-detected)"
            
            # Try linux.info for Linux dumps
            cmd = [self.binary_path, "-f", image_path, "linux.info.Info"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                if "Linux" in result.stdout:
                    return "Linux (auto-detected)"
        
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        return None
    
    def run_plugin(
        self,
        image_path: str,
        plugin_name: str,
        additional_args: Optional[List[str]] = None,
        timeout_override: Optional[int] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> Dict:
        """
        Run a single Volatility3 plugin with retry mechanism, timeout, and error handling.
        
        Args:
            image_path: Path to memory dump
            plugin_name: Volatility plugin name
            additional_args: Additional command-line arguments
            timeout_override: Override default timeout for this plugin
            progress_callback: Callback for progress updates (message, percentage)
        
        Returns:
            Dict containing plugin output or error information
        """
        timeout = timeout_override or self.timeout_seconds
        
        for attempt in range(1, self.max_retries + 1):
            try:
                if progress_callback:
                    progress_callback(f"Running {plugin_name} (attempt {attempt}/{self.max_retries})", 0)
                
                result = self._execute_plugin_with_timeout(
                    image_path, 
                    plugin_name, 
                    additional_args, 
                    timeout,
                    progress_callback
                )
                
                # Success
                self.stats['plugins_executed'] += 1
                self.stats['plugins_succeeded'] += 1
                if attempt > 1:
                    self.stats['plugins_retried'] += 1
                
                return result
            
            except PluginTimeoutError as e:
                self.stats['plugins_timed_out'] += 1
                
                if attempt < self.max_retries:
                    if progress_callback:
                        progress_callback(f"Plugin timed out, retrying in {self.retry_delay}s...", 0)
                    time.sleep(self.retry_delay)
                    continue
                else:
                    self.stats['plugins_failed'] += 1
                    return {
                        "error": f"Plugin timed out after {timeout}s",
                        "plugin": plugin_name,
                        "attempts": attempt,
                        "error_type": "timeout"
                    }
            
            except subprocess.SubprocessError as e:
                if attempt < self.max_retries:
                    if progress_callback:
                        progress_callback(f"Plugin failed, retrying in {self.retry_delay}s...", 0)
                    time.sleep(self.retry_delay)
                    continue
                else:
                    self.stats['plugins_failed'] += 1
                    return {
                        "error": str(e),
                        "plugin": plugin_name,
                        "attempts": attempt,
                        "error_type": "subprocess_error"
                    }
            
            except Exception as e:
                if attempt < self.max_retries:
                    if progress_callback:
                        progress_callback(f"Plugin error, retrying in {self.retry_delay}s...", 0)
                    time.sleep(self.retry_delay)
                    continue
                else:
                    self.stats['plugins_failed'] += 1
                    return {
                        "error": str(e),
                        "plugin": plugin_name,
                        "attempts": attempt,
                        "error_type": "unknown_error"
                    }
        
        # Should not reach here
        self.stats['plugins_failed'] += 1
        return {
            "error": "Max retries exceeded",
            "plugin": plugin_name,
            "attempts": self.max_retries
        }
    
    def _execute_plugin_with_timeout(
        self,
        image_path: str,
        plugin_name: str,
        additional_args: Optional[List[str]],
        timeout: int,
        progress_callback: Optional[Callable[[str, float], None]]
    ) -> Dict:
        """
        Execute plugin with timeout and progress tracking.
        
        Raises:
            PluginTimeoutError: If execution exceeds timeout
            subprocess.SubprocessError: On subprocess errors
        """
        cmd = [self.binary_path, "-f", image_path, "-r", "json", plugin_name]
        if additional_args:
            cmd.extend(additional_args)
        
        start_time = time.time()
        
        try:
            # Run with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            execution_time = time.time() - start_time
            self.stats['total_execution_time'] += execution_time
            
            if progress_callback:
                progress_callback(f"Plugin completed in {execution_time:.2f}s", 100)
            
            # Check return code
            if result.returncode != 0:
                # Try fallback parsing for partial output
                if result.stdout:
                    try:
                        data = self._parse_with_fallback(result.stdout)
                        if data:
                            data['_warning'] = f"Plugin returned error code {result.returncode} but partial data recovered"
                            data['_stderr'] = result.stderr[:500] if result.stderr else ""
                            return data
                    except Exception:
                        pass
                
                raise subprocess.SubprocessError(
                    f"Plugin failed with return code {result.returncode}: {result.stderr[:500]}"
                )
            
            # Parse JSON output
            parsed_data = json.loads(result.stdout)
            
            # Volatility 3 returns a list, wrap it in a dict with metadata
            if isinstance(parsed_data, list):
                data = {
                    'data': parsed_data,
                    '_execution_time': execution_time,
                    '_row_count': len(parsed_data)
                }
            else:
                data = parsed_data
                data['_execution_time'] = execution_time
            
            return data
        
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            raise PluginTimeoutError(
                f"Plugin execution exceeded timeout of {timeout}s (elapsed: {execution_time:.1f}s)"
            )
        
        except json.JSONDecodeError as e:
            # Fallback parser for corrupted JSON
            data = self._parse_with_fallback(result.stdout)
            if data:
                data['_warning'] = f"JSON parsing failed, using fallback parser: {str(e)}"
                return data
            
            raise subprocess.SubprocessError(
                f"Invalid JSON output from plugin: {str(e)}"
            )
    
    def _parse_with_fallback(self, output: str) -> Optional[Dict]:
        """
        Fallback parser for corrupted or partial JSON output.
        
        Attempts multiple strategies:
        1. Fix common JSON syntax errors
        2. Extract valid JSON fragments
        3. Parse line-by-line
        """
        if not output or not output.strip():
            return None
        
        # Strategy 1: Fix common JSON errors
        try:
            # Remove trailing commas
            fixed = re.sub(r',(\s*[}\]])', r'\1', output)
            # Fix missing closing brackets
            if fixed.count('[') > fixed.count(']'):
                fixed += ']' * (fixed.count('[') - fixed.count(']'))
            if fixed.count('{') > fixed.count('}'):
                fixed += '}' * (fixed.count('{') - fixed.count('}'))
            
            data = json.loads(fixed)
            return data
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract valid JSON fragments
        try:
            # Find first complete JSON object
            match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', output)
            if match:
                data = json.loads(match.group(0))
                return {"_partial": True, "data": data}
        except json.JSONDecodeError:
            pass
        
        # Strategy 3: Line-by-line parsing
        try:
            lines = output.strip().split('\n')
            parsed_lines = []
            for line in lines:
                try:
                    parsed_lines.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            
            if parsed_lines:
                return {"_partial": True, "_line_by_line": True, "data": parsed_lines}
        except Exception:
            pass
        
        # All strategies failed
        return None
    
    def run_plugins_bulk(
        self, 
        image_path: str, 
        plugin_list: List[str],
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> Dict[str, Dict]:
        """
        Run multiple plugins with progress tracking and ETA calculation.
        
        Args:
            image_path: Path to memory dump
            plugin_list: List of plugin names to execute
            progress_callback: Callback(plugin_name, current, total) for progress updates
        
        Returns:
            Dict mapping plugin names to their outputs
        """
        outputs = {}
        start_time = time.time()
        
        for idx, plugin in enumerate(plugin_list, 1):
            # Calculate ETA
            if idx > 1:
                elapsed = time.time() - start_time
                avg_time = elapsed / (idx - 1)
                remaining_plugins = len(plugin_list) - idx + 1
                eta_seconds = avg_time * remaining_plugins
                eta = str(timedelta(seconds=int(eta_seconds)))
            else:
                eta = "calculating..."
            
            # Progress callback
            if progress_callback:
                progress_callback(plugin, idx, len(plugin_list))
            
            # Run plugin
            plugin_start = time.time()
            outputs[plugin] = self.run_plugin(
                image_path, 
                plugin,
                progress_callback=lambda msg, pct: None  # Inner progress
            )
            plugin_time = time.time() - plugin_start
            
            # Log timing
            outputs[plugin]['_plugin_execution_time'] = plugin_time
        
        return outputs
    
    def get_statistics(self) -> Dict:
        """Get execution statistics."""
        success_rate = 0.0
        if self.stats['plugins_executed'] > 0:
            success_rate = (self.stats['plugins_succeeded'] / self.stats['plugins_executed']) * 100
        
        return {
            **self.stats,
            'success_rate': f"{success_rate:.1f}%",
            'avg_execution_time': (
                self.stats['total_execution_time'] / self.stats['plugins_executed']
                if self.stats['plugins_executed'] > 0 else 0
            )
        }
    
    def handle_incomplete_dump(self, image_path: str, plugin_list: List[str]) -> Dict[str, Dict]:
        """
        Handle incomplete/partial dumps gracefully by trying plugins sequentially
        and continuing even if some fail.
        
        Args:
            image_path: Path to potentially incomplete memory dump
            plugin_list: List of plugins to attempt
        
        Returns:
            Dict of successful plugin outputs (failed plugins are logged but skipped)
        """
        outputs = {}
        
        for plugin in plugin_list:
            try:
                result = self.run_plugin(image_path, plugin, timeout_override=120)
                
                # Check if plugin returned valid data
                if result and 'error' not in result:
                    outputs[plugin] = result
                elif result and result.get('_partial'):
                    # Accept partial data from fallback parser
                    outputs[plugin] = result
                else:
                    # Plugin failed, continue with next one
                    outputs[plugin] = {
                        'error': 'Plugin failed on incomplete dump',
                        'plugin': plugin,
                        'partial_dump': True
                    }
            
            except Exception as e:
                # Log error but continue
                outputs[plugin] = {
                    'error': str(e),
                    'plugin': plugin,
                    'partial_dump': True
                }
                continue
        
        return outputs