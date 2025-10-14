"""Base parser interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from vaulytica.models import SecurityEvent


class BaseParser(ABC):
    """Abstract base class for security event parsers."""
    
    @abstractmethod
    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse raw event into normalized SecurityEvent."""
        pass
    
    @abstractmethod
    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate that raw event matches expected schema."""
        pass

