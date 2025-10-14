"""Production logging configuration."""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str = "vaulytica",
    level: int = logging.INFO,
    log_file: Optional[Path] = None
) -> logging.Logger:
    """Configure production-grade logger with structured output."""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if logger.handlers:
        return logger
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "vaulytica") -> logging.Logger:
    """Get existing logger instance."""
    return logging.getLogger(name)

