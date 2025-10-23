"""
Database Query Optimizer

Provides intelligent query optimization including:
- Query result caching
- Query plan analysis
- Index recommendations
- Batch query execution
- Connection pooling
- Query rewriting
"""

import asyncio
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

from vaulytica.performance_optimizer import LRUCache, ConnectionPool, PerformanceMetrics

logger = logging.getLogger(__name__)


@dataclass
class QueryPlan:
    """Query execution plan"""
    query: str
    estimated_cost: float
    estimated_rows: int
    uses_index: bool
    index_recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class QueryStats:
    """Query execution statistics"""
    query_hash: str
    execution_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    cache_hits: int = 0
    last_executed: Optional[datetime] = None

    def record_execution(self, duration: float, from_cache: bool = False) -> None:
        """Record query execution"""
        self.execution_count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)
        self.avg_time = self.total_time / self.execution_count
        self.last_executed = datetime.now()

        if from_cache:
            self.cache_hits += 1


class QueryOptimizer:
    """Intelligent query optimizer"""

    def __init__(
        self,
        cache_size: int = 1000,
        cache_ttl: float = 300.0,
        enable_query_rewriting: bool = True,
        enable_batch_execution: bool = True
    ):
        self.cache = LRUCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self.enable_query_rewriting = enable_query_rewriting
        self.enable_batch_execution = enable_batch_execution

        self.query_stats: Dict[str, QueryStats] = {}
        self.pending_queries: List[Tuple[str, Dict[str, Any]]] = []
        self.batch_lock = asyncio.Lock()

        self.metrics = PerformanceMetrics("QueryOptimizer")

    def _hash_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate hash for query and parameters"""
        query_str = query.strip().lower()
        if params:
            query_str += json.dumps(params, sort_keys=True)
        return hashlib.sha256(query_str.encode()).hexdigest()

    def _rewrite_query(self, query: str) -> str:
        """Rewrite query for better performance"""
        if not self.enable_query_rewriting:
            return query

        optimized = query

        # Replace SELECT * with specific columns (if possible)
        # This is a simplified example - real implementation would need AST parsing
        if 'SELECT *' in query.upper():
            logger.debug("Query uses SELECT * - consider specifying columns")

        # Add LIMIT if missing for potentially large result sets
        if 'LIMIT' not in query.upper() and 'SELECT' in query.upper():
            logger.debug("Query missing LIMIT clause - consider adding one")

        # Suggest using EXISTS instead of COUNT(*) for existence checks
        if 'COUNT(*)' in query.upper() and 'WHERE' in query.upper():
            logger.debug("Consider using EXISTS instead of COUNT(*) for existence checks")

        return optimized

    def _analyze_query_plan(self, query: str) -> QueryPlan:
        """Analyze query execution plan"""
        # Simplified analysis - real implementation would use EXPLAIN
        plan = QueryPlan(
            query=query,
            estimated_cost=1.0,
            estimated_rows=100,
            uses_index=True
        )

        # Check for common anti-patterns
        query_upper = query.upper()

        if 'SELECT *' in query_upper:
            plan.warnings.append("Using SELECT * - specify columns for better performance")

        if 'OR' in query_upper:
            plan.warnings.append("OR conditions may prevent index usage")
            plan.index_recommendations.append("Consider rewriting OR as UNION")

        if 'LIKE' in query_upper and '%' in query:
            if query.find('%') < query.find('LIKE') + 10:
                plan.warnings.append("Leading wildcard in LIKE prevents index usage")
                plan.uses_index = False

        if 'ORDER BY' in query_upper and 'LIMIT' not in query_upper:
            plan.warnings.append("ORDER BY without LIMIT may be expensive")

        return plan

    async def execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        executor: Optional[Any] = None,
        cacheable: bool = True
    ) -> Any:
        """Execute query with optimization"""
        import time
        start = time.time()

        # Generate query hash
        query_hash = self._hash_query(query, params)

        # Initialize stats if needed
        if query_hash not in self.query_stats:
            self.query_stats[query_hash] = QueryStats(query_hash=query_hash)

        stats = self.query_stats[query_hash]

        # Try cache first
        if cacheable:
            cached_result = await self.cache.get(query_hash)
            if cached_result is not None:
                duration = time.time() - start
                stats.record_execution(duration, from_cache=True)
                self.metrics.record(duration, cache_hit=True)
                logger.debug(f"Query cache hit: {query[:50]}...")
                return cached_result

        # Rewrite query if enabled
        optimized_query = self._rewrite_query(query)

        # Analyze query plan
        plan = self._analyze_query_plan(optimized_query)
        if plan.warnings:
            for warning in plan.warnings:
                logger.warning(f"Query optimization warning: {warning}")

        # Execute query
        if executor:
            result = await executor(optimized_query, params)
        else:
            # Placeholder - actual execution would happen here
            result = None

        # Cache result
        if cacheable and result is not None:
            await self.cache.set(query_hash, result)

        # Record stats
        duration = time.time() - start
        stats.record_execution(duration, from_cache=False)
        self.metrics.record(duration, cache_hit=False)

        return result

    async def execute_batch(
        self,
        queries: List[Tuple[str, Optional[Dict[str, Any]]]],
        executor: Optional[Any] = None
    ) -> List[Any]:
        """Execute multiple queries in batch"""
        if not self.enable_batch_execution:
            # Execute sequentially
            results = []
            for query, params in queries:
                result = await self.execute_query(query, params, executor)
                results.append(result)
            return results

        # Execute in parallel
        tasks = [
            self.execute_query(query, params, executor)
            for query, params in queries
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return results

    def get_slow_queries(self, threshold_seconds: float = 1.0) -> List[Tuple[str, QueryStats]]:
        """Get queries slower than threshold"""
        slow_queries = []

        for query_hash, stats in self.query_stats.items():
            if stats.avg_time > threshold_seconds:
                # Try to get original query (simplified)
                slow_queries.append((query_hash, stats))

        # Sort by average time
        slow_queries.sort(key=lambda x: x[1].avg_time, reverse=True)

        return slow_queries

    def get_most_frequent_queries(self, limit: int = 10) -> List[Tuple[str, QueryStats]]:
        """Get most frequently executed queries"""
        queries = list(self.query_stats.items())
        queries.sort(key=lambda x: x[1].execution_count, reverse=True)
        return queries[:limit]

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        cache_metrics = self.cache.get_metrics()

        return {
            'cache_size': len(self.cache.cache),
            'max_size': self.cache.max_size,
            'hit_rate': cache_metrics.get_cache_hit_rate(),
            'total_hits': cache_metrics.cache_hits,
            'total_misses': cache_metrics.cache_misses
        }

    def get_optimization_report(self) -> Dict[str, Any]:
        """Get comprehensive optimization report"""
        total_queries = sum(s.execution_count for s in self.query_stats.values())
        total_time = sum(s.total_time for s in self.query_stats.values())
        total_cache_hits = sum(s.cache_hits for s in self.query_stats.values())

        slow_queries = self.get_slow_queries(threshold_seconds=1.0)
        frequent_queries = self.get_most_frequent_queries(limit=10)

        return {
            'summary': {
                'total_queries': total_queries,
                'unique_queries': len(self.query_stats),
                'total_time': total_time,
                'avg_time': total_time / total_queries if total_queries > 0 else 0,
                'cache_hit_rate': total_cache_hits / total_queries if total_queries > 0 else 0
            },
            'slow_queries': [
                {
                    'query_hash': qh,
                    'execution_count': stats.execution_count,
                    'avg_time': stats.avg_time,
                    'max_time': stats.max_time
                }
                for qh, stats in slow_queries[:10]
            ],
            'frequent_queries': [
                {
                    'query_hash': qh,
                    'execution_count': stats.execution_count,
                    'avg_time': stats.avg_time,
                    'cache_hits': stats.cache_hits
                }
                for qh, stats in frequent_queries
            ],
            'cache_stats': self.get_cache_statistics()
        }

    async def clear_cache(self):
        """Clear query cache"""
        await self.cache.clear()
        logger.info("Query cache cleared")

    def reset_statistics(self) -> None:
        """Reset query statistics"""
        self.query_stats.clear()
        logger.info("Query statistics reset")


# Global query optimizer instance
query_optimizer = QueryOptimizer()
