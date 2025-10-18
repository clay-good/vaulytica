from abc import ABC, abstractmethod
from typing import List, Optional
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.config import VaulyticaConfig


class BaseAgent(ABC):
    """Abstract base class for security analysis agents."""
    
    def __init__(self, config: VaulyticaConfig):
        self.config = config
    
    @abstractmethod
    async def analyze(
        self, 
        events: List[SecurityEvent],
        historical_context: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Analyze security events and produce actionable insights.
        
        Args:
            events: List of normalized security events to analyze
            historical_context: Optional historical incident context from RAG
            
        Returns:
            AnalysisResult with findings and recommendations
        """
        pass
    
    def _chunk_events(self, events: List[SecurityEvent], max_size: int) -> List[List[SecurityEvent]]:
        """Chunk events to fit within context limits."""
        chunks = []
        current_chunk = []
        current_size = 0
        
        for event in events:
            event_size = len(event.model_dump_json())
            
            if current_size + event_size > max_size and current_chunk:
                chunks.append(current_chunk)
                current_chunk = []
                current_size = 0
            
            current_chunk.append(event)
            current_size += event_size
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks

