"""
Logging module for forensic-grade audit trail and debugging.
Provides structured logging with multiple handlers and forensic chain of custody.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional


class ForensicFormatter(logging.Formatter):
    """
    Custom formatter for forensic logging with precise timestamps and structured output.
    """
    
    # ANSI color codes for terminal output
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def __init__(self, use_colors: bool = False):
        super().__init__(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        self.use_colors = use_colors
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional color coding."""
        # Store original levelname
        original_levelname = record.levelname
        
        # Add color if enabled and outputting to terminal
        if self.use_colors and sys.stderr.isatty():
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        
        # Format the record
        result = super().format(record)
        
        # Restore original levelname
        record.levelname = original_levelname
        
        return result


def setup_logging(
    log_dir: str = "logs",
    log_level: int = logging.INFO,
    enable_console: bool = True,
    enable_file: bool = True,
    case_name: Optional[str] = None
) -> logging.Logger:
    """
    Setup forensic-grade logging system with audit trail.
    
    Args:
        log_dir: Directory to store log files
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        enable_console: Enable console output
        enable_file: Enable file output
        case_name: Optional case name for the log file
    
    Returns:
        Configured logger instance
    """
    
    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    # Create log filename with timestamp
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    case_prefix = f"{case_name}_" if case_name else ""
    log_file = log_path / f"{case_prefix}analysis_{timestamp}.log"
    
    # Get root logger
    logger = logging.getLogger("forensic_analyzer")
    logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # File handler (always without colors, for forensic records)
    if enable_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        file_handler.setFormatter(ForensicFormatter(use_colors=False))
        logger.addHandler(file_handler)
    
    # Console handler (with colors if terminal supports it)
    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(ForensicFormatter(use_colors=True))
        logger.addHandler(console_handler)
    
    # Log initialization
    logger.info("=" * 80)
    logger.info("Forensic Memory Analysis - Logging Initialized")
    logger.info(f"Log file: {log_file.absolute()}")
    logger.info(f"Log level: {logging.getLevelName(log_level)}")
    logger.info(f"Timestamp: {datetime.utcnow().isoformat()}Z")
    logger.info("=" * 80)
    
    return logger


def get_logger(name: str = "forensic_analyzer") -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__ from the calling module)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Convenience functions for common operations
def log_phase(logger: logging.Logger, phase_name: str, start: bool = True) -> None:
    """
    Log the start or end of an analysis phase.
    
    Args:
        logger: Logger instance
        phase_name: Name of the analysis phase
        start: True for phase start, False for phase end
    """
    if start:
        logger.info("-" * 80)
        logger.info(f"PHASE START: {phase_name}")
        logger.info("-" * 80)
    else:
        logger.info("-" * 80)
        logger.info(f"PHASE END: {phase_name}")
        logger.info("-" * 80)


def log_finding(logger: logging.Logger, severity: str, category: str, 
                description: str, **kwargs) -> None:
    """
    Log a security finding with structured format.
    
    Args:
        logger: Logger instance
        severity: Finding severity (CRITICAL, HIGH, MEDIUM, LOW)
        category: Finding category
        description: Finding description
        **kwargs: Additional context (pid, process_name, etc.)
    """
    context_str = " | ".join(f"{k}={v}" for k, v in kwargs.items())
    log_message = f"FINDING | {severity} | {category} | {description}"
    
    if context_str:
        log_message += f" | {context_str}"
    
    # Use appropriate log level based on severity
    if severity == "CRITICAL":
        logger.critical(log_message)
    elif severity == "HIGH":
        logger.error(log_message)
    elif severity == "MEDIUM":
        logger.warning(log_message)
    else:
        logger.info(log_message)


def log_volatility_execution(logger: logging.Logger, plugin: str, 
                             success: bool, execution_time: float = None) -> None:
    """
    Log Volatility plugin execution results.
    
    Args:
        logger: Logger instance
        plugin: Plugin name
        success: True if execution succeeded
        execution_time: Execution time in seconds (optional)
    """
    status = "SUCCESS" if success else "FAILED"
    time_str = f" (took {execution_time:.2f}s)" if execution_time else ""
    logger.info(f"VOLATILITY | {plugin} | {status}{time_str}")
