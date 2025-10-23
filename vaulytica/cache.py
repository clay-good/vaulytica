"""Analysis caching system for improved performance."""

import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.config import VaulyticaConfig


class AnalysisCache:
    """File-based caching system for analysis results."""

    def __init__(self, config: VaulyticaConfig):
        self.config = config
        self.cache_dir = config.output_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = 24

    def _generate_cache_key(self, event: SecurityEvent) -> str:
        """Generate unique cache key for event."""

        cache_data = {
            "event_id": event.event_id,
            "source": event.source_system,
            "title": event.title,
            "description": event.description[:100],
            "severity": event.severity.value,
            "category": event.category.value,
        }

        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()

    def get(self, event: SecurityEvent) -> Optional[AnalysisResult]:
        """Retrieve cached analysis if available and not expired."""

        cache_key = self._generate_cache_key(event)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)

            cached_time = datetime.fromisoformat(cached_data["cached_at"])
            if datetime.utcnow() - cached_time > timedelta(hours=self.ttl_hours):
                cache_file.unlink()
                return None

            return AnalysisResult(**cached_data["result"])

        except Exception:
            return None

    def set(self, event: SecurityEvent, result: AnalysisResult) -> None:
        """Cache analysis result."""

        cache_key = self._generate_cache_key(event)
        cache_file = self.cache_dir / f"{cache_key}.json"

        cache_data = {
            "cached_at": datetime.utcnow().isoformat(),
            "event_id": event.event_id,
            "result": json.loads(result.model_dump_json())
        }

        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2, default=str)
        except Exception:
            pass

    def clear_expired(self) -> int:
        """Clear expired cache entries."""

        cleared = 0
        cutoff_time = datetime.utcnow() - timedelta(hours=self.ttl_hours)

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)

                cached_time = datetime.fromisoformat(cached_data["cached_at"])
                if cached_time < cutoff_time:
                    cache_file.unlink()
                    cleared += 1
            except Exception:
                continue

        return cleared

    def clear_all(self) -> int:
        """Clear all cache entries."""

        cleared = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                cleared += 1
            except Exception:
                continue

        return cleared

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""

        total_entries = len(list(self.cache_dir.glob("*.json")))
        total_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))

        return {
            "total_entries": total_entries,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
            "ttl_hours": self.ttl_hours
        }
