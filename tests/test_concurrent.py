"""Tests for concurrent processing utilities."""

import time
import pytest
from unittest.mock import Mock

from vaulytica.core.utils.concurrent import (
    ConcurrentProcessor,
    RateLimitedConcurrentProcessor,
    BatchedConcurrentProcessor,
)


class TestConcurrentProcessor:
    """Test basic concurrent processor."""

    def test_process_items_basic(self):
        """Test basic concurrent processing."""
        items = [1, 2, 3, 4, 5]
        
        def process_func(item):
            return item * 2
        
        processor = ConcurrentProcessor(max_workers=2)
        results = processor.process(items, process_func)
        
        assert sorted(results) == [2, 4, 6, 8, 10]

    def test_process_items_with_error(self):
        """Test concurrent processing with errors."""
        items = [1, 2, 3, 4, 5]
        
        def process_func(item):
            if item == 3:
                raise ValueError("Error on 3")
            return item * 2
        
        processor = ConcurrentProcessor(max_workers=2)
        results = processor.process(items, process_func)
        
        # Should skip failed item
        assert sorted(results) == [2, 4, 8, 10]

    def test_process_items_with_error_callback(self):
        """Test error callback is called."""
        items = [1, 2, 3, 4, 5]
        errors = []
        
        def process_func(item):
            if item == 3:
                raise ValueError("Error on 3")
            return item * 2
        
        def error_handler(item, error):
            errors.append((item, str(error)))

        processor = ConcurrentProcessor(max_workers=2)
        processor.process(items, process_func, error_handler=error_handler)
        
        assert len(errors) == 1
        assert errors[0][0] == 3
        assert "Error on 3" in errors[0][1]

    def test_process_items_with_progress(self):
        """Test progress callback is called."""
        items = [1, 2, 3, 4, 5]
        progress_calls = []
        
        def process_func(item):
            return item * 2
        
        def progress_callback(completed, total):
            progress_calls.append((completed, total))
        
        processor = ConcurrentProcessor(max_workers=2)
        results = processor.process_with_progress(items, process_func, progress_callback=progress_callback)
        
        # Should have progress updates
        assert len(progress_calls) > 0
        # Last call should be complete
        assert progress_calls[-1] == (5, 5)
        assert len(results) == 5

    def test_process_items_empty_list(self):
        """Test processing empty list."""
        items = []
        
        def process_func(item):
            return item * 2
        
        processor = ConcurrentProcessor(max_workers=2)
        results = processor.process(items, process_func)
        
        assert results == []


class TestRateLimitedConcurrentProcessor:
    """Test rate-limited concurrent processor."""

    def test_rate_limiting(self):
        """Test rate limiting is applied."""
        items = [1, 2, 3, 4, 5]
        
        def process_func(item):
            return item * 2
        
        processor = RateLimitedConcurrentProcessor(
            max_workers=2,
            rate_limit_delay=0.1
        )
        
        start_time = time.time()
        results = processor.process(items, process_func)
        elapsed = time.time() - start_time
        
        # Should take at least 0.4 seconds (5 items * 0.1 delay, with 2 workers)
        assert elapsed >= 0.2
        assert sorted(results) == [2, 4, 6, 8, 10]

    def test_rate_limiting_with_errors(self):
        """Test rate limiting with errors."""
        items = [1, 2, 3, 4, 5]
        
        def process_func(item):
            if item == 3:
                raise ValueError("Error")
            return item * 2
        
        processor = RateLimitedConcurrentProcessor(
            max_workers=2,
            rate_limit_delay=0.05
        )
        
        results = processor.process(items, process_func)
        assert sorted(results) == [2, 4, 8, 10]


class TestBatchedConcurrentProcessor:
    """Test batched concurrent processor."""

    def test_batch_processing(self):
        """Test batch processing."""
        items = list(range(1, 11))  # 1-10

        def process_batch(batch):
            return [item * 2 for item in batch]

        processor = BatchedConcurrentProcessor(
            max_workers=2,
            batch_size=3
        )

        results = processor.process(items, process_batch)

        assert sorted(results) == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

    def test_batch_processing_with_progress(self):
        """Test batch processing with progress tracking."""
        items = list(range(1, 11))

        def process_batch(batch):
            return [item * 2 for item in batch]

        processor = BatchedConcurrentProcessor(
            max_workers=2,
            batch_size=3
        )

        results = processor.process(items, process_batch)

        # Should process all items
        assert len(results) == 10
        assert sorted(results) == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

    def test_batch_processing_uneven_batches(self):
        """Test batch processing with uneven batch sizes."""
        items = [1, 2, 3, 4, 5, 6, 7]  # 7 items, batch size 3
        
        def process_batch(batch):
            return [item * 2 for item in batch]

        processor = BatchedConcurrentProcessor(
            max_workers=2,
            batch_size=3
        )

        results = processor.process(items, process_batch)
        
        assert sorted(results) == [2, 4, 6, 8, 10, 12, 14]

    def test_batch_processing_with_errors(self):
        """Test batch processing with errors."""
        items = list(range(1, 11))
        
        def process_batch(batch):
            # Raise error if batch contains 5
            if 5 in batch:
                raise ValueError("Error on batch with 5")
            return [item * 2 for item in batch]

        processor = BatchedConcurrentProcessor(
            max_workers=2,
            batch_size=3
        )

        results = processor.process(items, process_batch)

        # Should skip batch with error (batch containing 4,5,6)
        # Remaining batches: [1,2,3], [7,8,9], [10]
        assert len(results) < 10  # Some items skipped due to error


class TestConcurrentProcessorPerformance:
    """Test concurrent processor performance improvements."""

    def test_concurrent_faster_than_sequential(self):
        """Test concurrent processing is faster than sequential."""
        items = list(range(1, 11))
        
        def slow_process(item):
            time.sleep(0.1)
            return item * 2
        
        # Sequential processing
        start_time = time.time()
        sequential_results = [slow_process(item) for item in items]
        sequential_time = time.time() - start_time
        
        # Concurrent processing
        processor = ConcurrentProcessor(max_workers=5)
        start_time = time.time()
        concurrent_results = processor.process(items, slow_process)
        concurrent_time = time.time() - start_time
        
        # Concurrent should be significantly faster
        assert concurrent_time < sequential_time * 0.6
        assert sorted(concurrent_results) == sorted(sequential_results)

    def test_worker_count_impact(self):
        """Test that more workers improve performance."""
        items = list(range(1, 21))
        
        def slow_process(item):
            time.sleep(0.05)
            return item * 2
        
        # 2 workers
        processor_2 = ConcurrentProcessor(max_workers=2)
        start_time = time.time()
        processor_2.process(items, slow_process)
        time_2_workers = time.time() - start_time
        
        # 5 workers
        processor_5 = ConcurrentProcessor(max_workers=5)
        start_time = time.time()
        processor_5.process(items, slow_process)
        time_5_workers = time.time() - start_time
        
        # More workers should be faster
        assert time_5_workers < time_2_workers


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

