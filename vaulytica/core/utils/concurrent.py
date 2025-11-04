"""Concurrent processing utilities."""

import concurrent.futures
from typing import Callable, Iterable, List, Optional, TypeVar, Any
import structlog

logger = structlog.get_logger(__name__)

T = TypeVar("T")
R = TypeVar("R")


class ConcurrentProcessor:
    """Process items concurrently using ThreadPoolExecutor."""

    def __init__(self, max_workers: int = 5):
        """Initialize concurrent processor.

        Args:
            max_workers: Maximum number of worker threads
        """
        self.max_workers = max_workers
        logger.info("concurrent_processor_initialized", max_workers=max_workers)

    def process(
        self,
        items: Iterable[T],
        process_func: Callable[[T], R],
        error_handler: Optional[Callable[[T, Exception], None]] = None,
    ) -> List[R]:
        """Process items concurrently.

        Args:
            items: Items to process
            process_func: Function to process each item
            error_handler: Optional function to handle errors

        Returns:
            List of results (excluding failed items)
        """
        results = []
        items_list = list(items)

        logger.info("concurrent_processing_started", total_items=len(items_list))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_item = {
                executor.submit(process_func, item): item for item in items_list
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(
                        "concurrent_processing_error",
                        item=str(item)[:100],
                        error=str(e),
                    )
                    if error_handler:
                        error_handler(item, e)

        logger.info(
            "concurrent_processing_completed",
            total_items=len(items_list),
            successful=len(results),
            failed=len(items_list) - len(results),
        )

        return results

    def process_with_progress(
        self,
        items: Iterable[T],
        process_func: Callable[[T], R],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        error_handler: Optional[Callable[[T, Exception], None]] = None,
    ) -> List[R]:
        """Process items concurrently with progress tracking.

        Args:
            items: Items to process
            process_func: Function to process each item
            progress_callback: Optional callback for progress updates (completed, total)
            error_handler: Optional function to handle errors

        Returns:
            List of results (excluding failed items)
        """
        results = []
        items_list = list(items)
        total = len(items_list)
        completed = 0

        logger.info("concurrent_processing_started", total_items=total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_item = {
                executor.submit(process_func, item): item for item in items_list
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(
                        "concurrent_processing_error",
                        item=str(item)[:100],
                        error=str(e),
                    )
                    if error_handler:
                        error_handler(item, e)

                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        logger.info(
            "concurrent_processing_completed",
            total_items=total,
            successful=len(results),
            failed=total - len(results),
        )

        return results


def process_batch_concurrent(
    items: Iterable[T],
    process_func: Callable[[T], R],
    max_workers: int = 5,
    error_handler: Optional[Callable[[T, Exception], None]] = None,
) -> List[R]:
    """Process a batch of items concurrently.

    Convenience function for simple concurrent processing.

    Args:
        items: Items to process
        process_func: Function to process each item
        max_workers: Maximum number of worker threads
        error_handler: Optional function to handle errors

    Returns:
        List of results (excluding failed items)
    """
    processor = ConcurrentProcessor(max_workers=max_workers)
    return processor.process(items, process_func, error_handler)


class RateLimitedConcurrentProcessor(ConcurrentProcessor):
    """Concurrent processor with rate limiting."""

    def __init__(self, max_workers: int = 5, rate_limit_delay: float = 0.1):
        """Initialize rate-limited concurrent processor.

        Args:
            max_workers: Maximum number of worker threads
            rate_limit_delay: Delay between processing items (seconds)
        """
        super().__init__(max_workers)
        self.rate_limit_delay = rate_limit_delay

    def process(
        self,
        items: Iterable[T],
        process_func: Callable[[T], R],
        error_handler: Optional[Callable[[T, Exception], None]] = None,
    ) -> List[R]:
        """Process items concurrently with rate limiting.

        Args:
            items: Items to process
            process_func: Function to process each item
            error_handler: Optional function to handle errors

        Returns:
            List of results (excluding failed items)
        """
        import time

        def rate_limited_func(item: T) -> R:
            """Wrapper that adds rate limiting."""
            time.sleep(self.rate_limit_delay)
            return process_func(item)

        return super().process(items, rate_limited_func, error_handler)


class BatchedConcurrentProcessor:
    """Process items in batches concurrently."""

    def __init__(self, max_workers: int = 5, batch_size: int = 100):
        """Initialize batched concurrent processor.

        Args:
            max_workers: Maximum number of worker threads
            batch_size: Number of items per batch
        """
        self.max_workers = max_workers
        self.batch_size = batch_size
        logger.info(
            "batched_concurrent_processor_initialized",
            max_workers=max_workers,
            batch_size=batch_size,
        )

    def process(
        self,
        items: Iterable[T],
        process_batch_func: Callable[[List[T]], List[R]],
        error_handler: Optional[Callable[[List[T], Exception], None]] = None,
    ) -> List[R]:
        """Process items in batches concurrently.

        Args:
            items: Items to process
            process_batch_func: Function to process a batch of items
            error_handler: Optional function to handle errors

        Returns:
            List of all results
        """
        items_list = list(items)
        batches = [
            items_list[i : i + self.batch_size]
            for i in range(0, len(items_list), self.batch_size)
        ]

        logger.info(
            "batched_concurrent_processing_started",
            total_items=len(items_list),
            total_batches=len(batches),
        )

        all_results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all batch tasks
            future_to_batch = {
                executor.submit(process_batch_func, batch): batch for batch in batches
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                except Exception as e:
                    logger.error(
                        "batched_concurrent_processing_error",
                        batch_size=len(batch),
                        error=str(e),
                    )
                    if error_handler:
                        error_handler(batch, e)

        logger.info(
            "batched_concurrent_processing_completed",
            total_items=len(items_list),
            total_batches=len(batches),
            successful_results=len(all_results),
        )

        return all_results

