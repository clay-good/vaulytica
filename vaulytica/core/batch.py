"""Batch processing with progress tracking and resume capability."""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Callable, Any, Iterator
from enum import Enum

import structlog
from rich.progress import Progress, TaskID, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

logger = structlog.get_logger(__name__)


class BatchStatus(Enum):
    """Batch processing status."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class BatchItem:
    """A single item in a batch."""

    id: str
    data: Any
    status: BatchStatus = BatchStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    attempts: int = 0
    last_attempt: Optional[datetime] = None


@dataclass
class BatchState:
    """State of a batch operation."""

    batch_id: str
    total_items: int
    processed_items: int = 0
    successful_items: int = 0
    failed_items: int = 0
    status: BatchStatus = BatchStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    checkpoint_file: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "batch_id": self.batch_id,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "successful_items": self.successful_items,
            "failed_items": self.failed_items,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "checkpoint_file": self.checkpoint_file,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BatchState":
        """Create from dictionary."""
        return cls(
            batch_id=data["batch_id"],
            total_items=data["total_items"],
            processed_items=data["processed_items"],
            successful_items=data["successful_items"],
            failed_items=data["failed_items"],
            status=BatchStatus(data["status"]),
            start_time=datetime.fromisoformat(data["start_time"]) if data["start_time"] else None,
            end_time=datetime.fromisoformat(data["end_time"]) if data["end_time"] else None,
            checkpoint_file=data.get("checkpoint_file"),
            metadata=data.get("metadata", {}),
        )


class BatchProcessor:
    """Process items in batches with progress tracking and resume capability."""

    def __init__(
        self,
        batch_id: str,
        items: List[Any],
        process_func: Callable[[Any], Any],
        batch_size: int = 100,
        max_retries: int = 3,
        checkpoint_dir: Optional[str] = None,
        show_progress: bool = True,
    ):
        """Initialize batch processor.

        Args:
            batch_id: Unique batch identifier
            items: List of items to process
            process_func: Function to process each item
            batch_size: Number of items to process in each batch
            max_retries: Maximum retry attempts per item
            checkpoint_dir: Directory for checkpoint files
            show_progress: Whether to show progress bar
        """
        self.batch_id = batch_id
        self.process_func = process_func
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.show_progress = show_progress

        # Convert items to BatchItems
        self.items = [BatchItem(id=str(i), data=item) for i, item in enumerate(items)]

        # State
        self.state = BatchState(
            batch_id=batch_id,
            total_items=len(self.items),
        )

        # Checkpoint
        if checkpoint_dir:
            self.checkpoint_dir = Path(checkpoint_dir)
            self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
            self.state.checkpoint_file = str(
                self.checkpoint_dir / f"{batch_id}_checkpoint.json"
            )
        else:
            self.checkpoint_dir = None

        logger.info(
            "batch_processor_initialized",
            batch_id=batch_id,
            total_items=len(self.items),
            batch_size=batch_size,
        )

    def process(self) -> BatchState:
        """Process all items.

        Returns:
            Final batch state
        """
        self.state.status = BatchStatus.RUNNING
        self.state.start_time = datetime.now(timezone.utc)

        logger.info("batch_processing_started", batch_id=self.batch_id)

        try:
            if self.show_progress:
                self._process_with_progress()
            else:
                self._process_without_progress()

            self.state.status = BatchStatus.COMPLETED
            self.state.end_time = datetime.now(timezone.utc)

            logger.info(
                "batch_processing_completed",
                batch_id=self.batch_id,
                successful=self.state.successful_items,
                failed=self.state.failed_items,
            )

        except KeyboardInterrupt:
            self.state.status = BatchStatus.CANCELLED
            self.state.end_time = datetime.now(timezone.utc)
            self._save_checkpoint()

            logger.warning("batch_processing_cancelled", batch_id=self.batch_id)
            raise

        except Exception as e:
            self.state.status = BatchStatus.FAILED
            self.state.end_time = datetime.now(timezone.utc)
            self._save_checkpoint()

            logger.error("batch_processing_failed", batch_id=self.batch_id, error=str(e))
            raise

        return self.state

    def _process_with_progress(self) -> None:
        """Process items with progress bar."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(
                f"Processing {self.batch_id}",
                total=self.state.total_items,
            )

            for item in self.items:
                if item.status == BatchStatus.COMPLETED:
                    progress.advance(task)
                    continue

                self._process_item(item)
                progress.advance(task)

                # Checkpoint periodically
                if self.state.processed_items % self.batch_size == 0:
                    self._save_checkpoint()

    def _process_without_progress(self) -> None:
        """Process items without progress bar."""
        for item in self.items:
            if item.status == BatchStatus.COMPLETED:
                continue

            self._process_item(item)

            # Checkpoint periodically
            if self.state.processed_items % self.batch_size == 0:
                self._save_checkpoint()

    def _process_item(self, item: BatchItem) -> None:
        """Process a single item.

        Args:
            item: BatchItem to process
        """
        item.attempts += 1
        item.last_attempt = datetime.now(timezone.utc)

        try:
            result = self.process_func(item.data)
            item.result = result
            item.status = BatchStatus.COMPLETED

            self.state.processed_items += 1
            self.state.successful_items += 1

        except Exception as e:
            logger.error(
                "item_processing_failed",
                batch_id=self.batch_id,
                item_id=item.id,
                attempt=item.attempts,
                error=str(e),
            )

            if item.attempts >= self.max_retries:
                item.status = BatchStatus.FAILED
                item.error = str(e)

                self.state.processed_items += 1
                self.state.failed_items += 1
            else:
                # Will retry
                item.status = BatchStatus.PENDING

    def _save_checkpoint(self) -> None:
        """Save checkpoint to file."""
        if not self.state.checkpoint_file:
            return

        checkpoint_data = {
            "state": self.state.to_dict(),
            "items": [
                {
                    "id": item.id,
                    "status": item.status.value,
                    "attempts": item.attempts,
                    "error": item.error,
                }
                for item in self.items
            ],
        }

        with open(self.state.checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f, indent=2)

        logger.debug("checkpoint_saved", checkpoint_file=self.state.checkpoint_file)

    def resume_from_checkpoint(self) -> bool:
        """Resume from checkpoint file.

        Returns:
            True if resumed successfully
        """
        if not self.state.checkpoint_file:
            return False

        checkpoint_path = Path(self.state.checkpoint_file)
        if not checkpoint_path.exists():
            return False

        try:
            with open(checkpoint_path, "r") as f:
                checkpoint_data = json.load(f)

            # Restore state
            self.state = BatchState.from_dict(checkpoint_data["state"])

            # Restore item statuses
            item_statuses = {item["id"]: item for item in checkpoint_data["items"]}

            for item in self.items:
                if item.id in item_statuses:
                    saved_item = item_statuses[item.id]
                    item.status = BatchStatus(saved_item["status"])
                    item.attempts = saved_item["attempts"]
                    item.error = saved_item.get("error")

            logger.info(
                "resumed_from_checkpoint",
                batch_id=self.batch_id,
                processed=self.state.processed_items,
                total=self.state.total_items,
            )

            return True

        except Exception as e:
            logger.error("failed_to_resume_from_checkpoint", error=str(e))
            return False

    def get_failed_items(self) -> List[BatchItem]:
        """Get list of failed items.

        Returns:
            List of failed BatchItems
        """
        return [item for item in self.items if item.status == BatchStatus.FAILED]

    def get_successful_items(self) -> List[BatchItem]:
        """Get list of successful items.

        Returns:
            List of successful BatchItems
        """
        return [item for item in self.items if item.status == BatchStatus.COMPLETED]

    def get_results(self) -> List[Any]:
        """Get results from successful items.

        Returns:
            List of results
        """
        return [item.result for item in self.items if item.result is not None]

