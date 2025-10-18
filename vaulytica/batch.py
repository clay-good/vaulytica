import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.parsers import BaseParser
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.rag import IncidentRAG
from vaulytica.cache import AnalysisCache
from vaulytica.config import VaulyticaConfig


class BatchProcessor:
    """Process multiple security events in parallel with progress tracking."""
    
    def __init__(self, config: VaulyticaConfig):
        self.config = config
        self.agent = SecurityAnalystAgent(config)
        self.rag = IncidentRAG(config) if config.enable_rag else None
        self.cache = AnalysisCache(config)
        self.max_workers = 3
    
    async def process_batch(
        self,
        events: List[SecurityEvent],
        use_cache: bool = True,
        store_results: bool = True
    ) -> Dict[str, Any]:
        """Process multiple events in parallel."""
        
        start_time = datetime.utcnow()
        results = []
        cache_hits = 0
        cache_misses = 0
        errors = []
        
        for i, event in enumerate(events):
            try:
                cached_result = None
                if use_cache:
                    cached_result = self.cache.get(event)
                
                if cached_result:
                    cache_hits += 1
                    results.append({
                        "event_id": event.event_id,
                        "status": "success",
                        "cached": True,
                        "result": cached_result
                    })
                    continue
                
                cache_misses += 1
                
                historical_context = None
                if self.rag:
                    historical_context = self.rag.find_similar_incidents(
                        event,
                        max_results=self.config.max_historical_incidents
                    )
                
                result = await self.agent.analyze([event], historical_context)
                
                if use_cache:
                    self.cache.set(event, result)
                
                if store_results and self.rag:
                    self.rag.store_incident(event, result)
                
                results.append({
                    "event_id": event.event_id,
                    "status": "success",
                    "cached": False,
                    "result": result
                })
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                errors.append({
                    "event_id": event.event_id,
                    "error": str(e)
                })
                results.append({
                    "event_id": event.event_id,
                    "status": "error",
                    "error": str(e)
                })
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        return {
            "summary": {
                "total_events": len(events),
                "successful": len([r for r in results if r["status"] == "success"]),
                "failed": len(errors),
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
                "processing_time_seconds": processing_time,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat()
            },
            "results": results,
            "errors": errors
        }
    
    def process_directory(
        self,
        directory: Path,
        parser: BaseParser,
        pattern: str = "*.json",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """Process all events in a directory."""
        
        events = []
        parse_errors = []
        
        for file_path in directory.glob(pattern):
            try:
                with open(file_path, 'r') as f:
                    raw_data = json.load(f)
                
                if isinstance(raw_data, list):
                    for item in raw_data:
                        try:
                            events.append(parser.parse(item))
                        except Exception as e:
                            parse_errors.append({
                                "file": str(file_path),
                                "error": str(e)
                            })
                else:
                    events.append(parser.parse(raw_data))
            
            except Exception as e:
                parse_errors.append({
                    "file": str(file_path),
                    "error": str(e)
                })
        
        batch_result = asyncio.run(self.process_batch(events, use_cache=use_cache))
        batch_result["parse_errors"] = parse_errors
        
        return batch_result
    
    def generate_batch_report(
        self,
        batch_result: Dict[str, Any],
        output_path: Path
    ) -> None:
        """Generate comprehensive batch processing report."""
        
        report = {
            "batch_analysis_report": {
                "generated_at": datetime.utcnow().isoformat(),
                "summary": batch_result["summary"],
                "results": []
            }
        }
        
        for result in batch_result["results"]:
            if result["status"] == "success":
                analysis = result["result"]
                report["batch_analysis_report"]["results"].append({
                    "event_id": result["event_id"],
                    "cached": result.get("cached", False),
                    "risk_score": analysis.risk_score,
                    "confidence": analysis.confidence,
                    "executive_summary": analysis.executive_summary,
                    "immediate_actions_count": len(analysis.immediate_actions),
                    "mitre_techniques_count": len(analysis.mitre_techniques)
                })
        
        if batch_result.get("errors"):
            report["batch_analysis_report"]["errors"] = batch_result["errors"]
        
        if batch_result.get("parse_errors"):
            report["batch_analysis_report"]["parse_errors"] = batch_result["parse_errors"]
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

