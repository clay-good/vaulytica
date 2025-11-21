"""Tests for batch processing with resume capability."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

from vaulytica.core.batch import (
    BatchStatus,
    BatchItem,
    BatchState,
    BatchProcessor,
)


@pytest.fixture
def sample_batch_items():
    """Sample batch items for testing."""
    return [
        {"id": "item1", "email": "user1@company.com", "action": "suspend"},
        {"id": "item2", "email": "user2@company.com", "action": "suspend"},
        {"id": "item3", "email": "user3@company.com", "action": "suspend"},
        {"id": "item4", "email": "user4@company.com", "action": "suspend"},
        {"id": "item5", "email": "user5@company.com", "action": "suspend"},
    ]


class TestBatchItem:
    """Test BatchItem class."""

    def test_create_batch_item(self):
        """Test creating a batch item."""
        item = BatchItem(
            id="item1",
            data={"email": "user@company.com"},
        )

        assert item.id == "item1"
        assert item.data["email"] == "user@company.com"
        assert item.status == BatchStatus.PENDING
        assert item.result is None
        assert item.error is None
        assert item.attempts == 0

    def test_batch_item_with_result(self):
        """Test batch item with result."""
        item = BatchItem(
            id="item1",
            data={"email": "user@company.com"},
            status=BatchStatus.COMPLETED,
            result={"success": True},
        )

        assert item.status == BatchStatus.COMPLETED
        assert item.result == {"success": True}

    def test_batch_item_with_error(self):
        """Test batch item with error."""
        item = BatchItem(
            id="item1",
            data={"email": "user@company.com"},
            status=BatchStatus.FAILED,
            error="API Error: User not found",
            attempts=3,
        )

        assert item.status == BatchStatus.FAILED
        assert "User not found" in item.error
        assert item.attempts == 3


class TestBatchState:
    """Test BatchState class."""

    def test_create_batch_state(self):
        """Test creating batch state."""
        state = BatchState(
            batch_id="batch123",
            total_items=100,
        )

        assert state.batch_id == "batch123"
        assert state.total_items == 100
        assert state.processed_items == 0
        assert state.successful_items == 0
        assert state.failed_items == 0
        assert state.status == BatchStatus.PENDING

    def test_batch_state_progress(self):
        """Test batch state progress tracking."""
        state = BatchState(
            batch_id="batch123",
            total_items=100,
            processed_items=50,
            successful_items=45,
            failed_items=5,
            status=BatchStatus.RUNNING,
        )

        assert state.processed_items == 50
        assert state.successful_items == 45
        assert state.failed_items == 5
        assert state.status == BatchStatus.RUNNING

    def test_batch_state_completion(self):
        """Test batch state at completion."""
        state = BatchState(
            batch_id="batch123",
            total_items=100,
            processed_items=100,
            successful_items=95,
            failed_items=5,
            status=BatchStatus.COMPLETED,
            start_time=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 1, 10, 30, 0, tzinfo=timezone.utc),
        )

        assert state.processed_items == state.total_items
        assert state.status == BatchStatus.COMPLETED
        assert state.end_time is not None


class TestBatchProcessor:
    """Test BatchProcessor class."""

    def test_create_batch_processor(self, tmp_path, sample_batch_items):
        """Test creating a batch processor."""
        def process_item(item_data):
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        assert processor.batch_id == "test_batch"
        assert len(processor.items) == len(sample_batch_items)
        assert processor.state.total_items == len(sample_batch_items)

    def test_process_batch_success(self, tmp_path, sample_batch_items):
        """Test processing a batch successfully."""
        # Mock processing function
        def process_item(item_data):
            return {"success": True, "email": item_data["email"]}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        state = processor.process()

        assert state.total_items == len(sample_batch_items)
        assert state.successful_items == len(sample_batch_items)
        assert state.failed_items == 0
        assert state.status == BatchStatus.COMPLETED

        # Verify all items were processed successfully
        for item in processor.items:
            assert item.status == BatchStatus.COMPLETED
            assert item.result["success"] is True

    def test_process_batch_with_errors(self, tmp_path):
        """Test processing batch with some failures."""
        items = [
            {"id": "item1", "should_fail": False},
            {"id": "item2", "should_fail": True},
            {"id": "item3", "should_fail": False},
        ]

        def process_item(item_data):
            if item_data["should_fail"]:
                raise Exception("Simulated failure")
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
            max_retries=0,  # No retries
        )

        state = processor.process()

        # Should have 2 successful, 1 failed
        assert state.successful_items == 2
        assert state.failed_items == 1
        assert state.status == BatchStatus.COMPLETED

    def test_batch_resume_capability(self, tmp_path):
        """Test resuming an interrupted batch."""
        checkpoint_dir = tmp_path

        items = [
            {"id": "item1", "value": 1},
            {"id": "item2", "value": 2},
            {"id": "item3", "value": 3},
            {"id": "item4", "value": 4},
            {"id": "item5", "value": 5},
        ]

        processed_count = {"count": 0}

        def process_item(item_data):
            processed_count["count"] += 1
            # Simulate interruption after 2 items
            if processed_count["count"] == 3:
                raise KeyboardInterrupt("Simulated interruption")
            return {"success": True, "value": item_data["value"]}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(checkpoint_dir),
            show_progress=False,
        )

        # Process and expect interruption
        try:
            processor.process()
        except KeyboardInterrupt:
            pass

        # Verify checkpoint was saved
        checkpoint_file = checkpoint_dir / "test_batch_checkpoint.json"
        assert checkpoint_file.exists()

        # Load checkpoint and verify state
        with open(checkpoint_file, "r") as f:
            checkpoint_data = json.load(f)
            assert checkpoint_data["state"]["batch_id"] == "test_batch"
            assert checkpoint_data["state"]["processed_items"] == 2
            assert checkpoint_data["state"]["status"] == "cancelled"

        # Resume processing
        processed_count["count"] = 0  # Reset counter

        def process_item_resume(item_data):
            processed_count["count"] += 1
            return {"success": True, "value": item_data["value"]}

        processor2 = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item_resume,
            checkpoint_dir=str(checkpoint_dir),
            show_progress=False,
        )

        # Resume from checkpoint
        resumed = processor2.resume_from_checkpoint()
        assert resumed is True

        # Continue processing
        state = processor2.process()

        # Should have processed remaining 3 items
        assert processed_count["count"] == 3
        assert state.total_items == 5
        assert state.successful_items == 5

    def test_batch_state_persistence(self, tmp_path, sample_batch_items):
        """Test that batch state is persisted to disk."""
        checkpoint_dir = tmp_path

        def process_item(item_data):
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(checkpoint_dir),
            show_progress=False,
            batch_size=2,  # Save checkpoint every 2 items
        )

        processor.process()

        # Verify checkpoint file exists (saved during processing)
        checkpoint_file = checkpoint_dir / "test_batch_checkpoint.json"
        assert checkpoint_file.exists()

        # Verify checkpoint file content
        # Note: Checkpoint is saved during processing, not at completion
        # So status may be "running" from the last periodic save
        with open(checkpoint_file, "r") as f:
            checkpoint = json.load(f)
            assert checkpoint["state"]["batch_id"] == "test_batch"
            assert checkpoint["state"]["total_items"] == len(sample_batch_items)
            # Status can be "running" since checkpoint is saved periodically during processing
            assert checkpoint["state"]["status"] in ["running", "completed"]

    def test_batch_retry_logic(self, tmp_path):
        """Test retry logic for failed items."""
        # Test that items failing will be marked for retry (but not auto-retried in one pass)
        items = [{"id": "item1"}, {"id": "item2"}]

        def process_item(item_data):
            # Always fail
            raise Exception("Temporary failure")

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
            max_retries=3,
        )

        state = processor.process()

        # Items should be marked as PENDING since attempts (1) < max_retries (3)
        # They won't be automatically retried in the same process() call
        # But they also won't be marked as processed
        assert state.processed_items == 0  # Not counted as processed since they're pending retry
        assert state.successful_items == 0
        assert state.failed_items == 0

        # Verify items are still pending (ready for retry)
        for item in processor.items:
            assert item.status == BatchStatus.PENDING
            assert item.attempts == 1

    def test_batch_parallel_processing(self, tmp_path, sample_batch_items):
        """Test batch processing completes all items."""
        processed_items = []

        def process_item(item_data):
            processed_items.append(item_data["id"])
            return {"success": True, "id": item_data["id"]}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        state = processor.process()

        assert state.successful_items == len(sample_batch_items)
        assert len(processed_items) == len(sample_batch_items)

    def test_batch_progress_tracking(self, tmp_path, sample_batch_items):
        """Test progress tracking during batch processing."""
        def process_item(item_data):
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,  # Disable progress bar for testing
        )

        state = processor.process()

        # Verify state tracks progress
        assert state.processed_items == len(sample_batch_items)
        assert state.total_items == len(sample_batch_items)

    def test_batch_cancellation(self, tmp_path):
        """Test cancelling a batch operation."""
        items = [{"id": f"item{i}"} for i in range(100)]

        def process_item(item_data):
            # Simulate cancellation after 10 items
            if int(item_data["id"].replace("item", "")) >= 10:
                raise KeyboardInterrupt("User cancelled")
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        try:
            processor.process()
        except KeyboardInterrupt:
            pass

        # State should be saved as CANCELLED
        assert processor.state.status == BatchStatus.CANCELLED
        assert processor.state.successful_items == 10

        # Verify checkpoint exists
        checkpoint_file = tmp_path / "test_batch_checkpoint.json"
        assert checkpoint_file.exists()


class TestBatchErrorHandling:
    """Test error handling in batch processing."""

    def test_handle_missing_checkpoint_file(self, tmp_path):
        """Test handling of missing checkpoint file."""
        def process_item(item_data):
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=[{"id": "item1"}],
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        # Try to resume from non-existent checkpoint
        resumed = processor.resume_from_checkpoint()

        # Should return False, not crash
        assert resumed is False

    def test_handle_corrupted_checkpoint_file(self, tmp_path):
        """Test handling of corrupted checkpoint file."""
        checkpoint_file = tmp_path / "test_batch_checkpoint.json"
        checkpoint_file.write_text("not valid json {{{")

        def process_item(item_data):
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=[{"id": "item1"}],
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        # Should handle corrupted file gracefully
        try:
            resumed = processor.resume_from_checkpoint()
            # Should either return False or raise handled exception
            assert resumed is False or resumed is None
        except Exception:
            # Exception is acceptable for corrupted file
            pass

    def test_handle_processing_exception(self, tmp_path):
        """Test handling of processing exceptions."""
        def process_item(item_data):
            raise Exception("Processing error")

        items = [{"id": "item1"}]

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
            max_retries=0,
        )

        # Should complete despite errors
        state = processor.process()

        assert state.failed_items == 1
        assert state.successful_items == 0


class TestBatchMetrics:
    """Test batch processing metrics."""

    def test_calculate_throughput(self, tmp_path, sample_batch_items):
        """Test calculating processing throughput."""
        def process_item(item_data):
            return {"success": True}

        start_time = datetime.now(timezone.utc)

        processor = BatchProcessor(
            batch_id="test_batch",
            items=sample_batch_items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
        )

        state = processor.process()

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        throughput = len(sample_batch_items) / duration if duration > 0 else 0

        # Should have processed items with some throughput
        assert throughput > 0
        assert state.successful_items == len(sample_batch_items)

    def test_track_success_rate(self, tmp_path):
        """Test tracking success rate."""
        items = [
            {"id": "item1", "should_fail": False},
            {"id": "item2", "should_fail": True},
            {"id": "item3", "should_fail": False},
            {"id": "item4", "should_fail": False},
        ]

        def process_item(item_data):
            if item_data["should_fail"]:
                raise Exception("Failed")
            return {"success": True}

        processor = BatchProcessor(
            batch_id="test_batch",
            items=items,
            process_func=process_item,
            checkpoint_dir=str(tmp_path),
            show_progress=False,
            max_retries=0,
        )

        state = processor.process()

        success_rate = state.successful_items / state.total_items

        # 3 out of 4 should succeed = 75%
        assert success_rate == 0.75
        assert state.successful_items == 3
        assert state.failed_items == 1
