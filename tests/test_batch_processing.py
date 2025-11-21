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

    def test_create_batch_processor(self, tmp_path):
        """Test creating a batch processor."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        assert processor.batch_id == "test_batch"
        assert processor.state_file == tmp_path / "batch_state.json"

    def test_process_batch_success(self, tmp_path, sample_batch_items):
        """Test processing a batch successfully."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        # Mock processing function
        def process_item(item_data):
            return {"success": True, "email": item_data["email"]}

        results = processor.process_batch(
            items=sample_batch_items,
            process_fn=process_item,
            max_workers=2,
        )

        assert len(results) == len(sample_batch_items)
        assert all(r["success"] for r in results)

    def test_process_batch_with_errors(self, tmp_path):
        """Test processing batch with some failures."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        items = [
            {"id": "item1", "should_fail": False},
            {"id": "item2", "should_fail": True},
            {"id": "item3", "should_fail": False},
        ]

        def process_item(item_data):
            if item_data["should_fail"]:
                raise Exception("Simulated failure")
            return {"success": True}

        results = processor.process_batch(
            items=items,
            process_fn=process_item,
            max_workers=1,
            retry_failed=False,
        )

        # Should have 2 successful, 1 failed
        successful = [r for r in results if r.get("success")]
        assert len(successful) == 2

    def test_batch_resume_capability(self, tmp_path):
        """Test resuming an interrupted batch."""
        state_file = tmp_path / "batch_state.json"

        # Create a partially completed batch state
        state = BatchState(
            batch_id="test_batch",
            total_items=5,
            processed_items=2,
            successful_items=2,
            failed_items=0,
            status=BatchStatus.PAUSED,
        )

        # Save state
        with open(state_file, "w") as f:
            json.dump(
                {
                    "batch_id": state.batch_id,
                    "total_items": state.total_items,
                    "processed_items": state.processed_items,
                    "successful_items": state.successful_items,
                    "failed_items": state.failed_items,
                    "status": state.status.value,
                },
                f,
            )

        # Resume batch
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=state_file,
        )

        loaded_state = processor.load_state()

        assert loaded_state is not None
        assert loaded_state["batch_id"] == "test_batch"
        assert loaded_state["processed_items"] == 2
        assert loaded_state["status"] == "paused"

    def test_batch_state_persistence(self, tmp_path, sample_batch_items):
        """Test that batch state is persisted to disk."""
        state_file = tmp_path / "batch_state.json"

        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=state_file,
        )

        def process_item(item_data):
            return {"success": True}

        processor.process_batch(
            items=sample_batch_items,
            process_fn=process_item,
            max_workers=2,
            save_state=True,
        )

        # Verify state file exists
        assert state_file.exists()

        # Verify state file content
        with open(state_file, "r") as f:
            state = json.load(f)
            assert state["batch_id"] == "test_batch"
            assert state["total_items"] == len(sample_batch_items)

    def test_batch_retry_logic(self, tmp_path):
        """Test retry logic for failed items."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        attempt_count = {"count": 0}

        def process_item(item_data):
            attempt_count["count"] += 1
            if attempt_count["count"] < 3:
                raise Exception("Temporary failure")
            return {"success": True}

        items = [{"id": "item1"}]

        results = processor.process_batch(
            items=items,
            process_fn=process_item,
            max_workers=1,
            retry_failed=True,
            max_retries=3,
        )

        # Should succeed after retries
        assert attempt_count["count"] == 3
        assert results[0]["success"] is True

    def test_batch_parallel_processing(self, tmp_path, sample_batch_items):
        """Test parallel processing with multiple workers."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        processed_items = []

        def process_item(item_data):
            processed_items.append(item_data["id"])
            return {"success": True, "id": item_data["id"]}

        results = processor.process_batch(
            items=sample_batch_items,
            process_fn=process_item,
            max_workers=3,  # Use 3 workers
        )

        assert len(results) == len(sample_batch_items)
        assert len(processed_items) == len(sample_batch_items)

    def test_batch_progress_tracking(self, tmp_path, sample_batch_items):
        """Test progress tracking during batch processing."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        progress_updates = []

        def progress_callback(current, total):
            progress_updates.append({"current": current, "total": total})

        def process_item(item_data):
            return {"success": True}

        processor.process_batch(
            items=sample_batch_items,
            process_fn=process_item,
            max_workers=1,
            progress_callback=progress_callback,
        )

        # Should have progress updates
        assert len(progress_updates) > 0
        assert progress_updates[-1]["total"] == len(sample_batch_items)

    def test_batch_cancellation(self, tmp_path):
        """Test cancelling a batch operation."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        items = [{"id": f"item{i}"} for i in range(100)]

        def process_item(item_data):
            # Simulate cancellation after 10 items
            if int(item_data["id"].replace("item", "")) >= 10:
                raise KeyboardInterrupt("User cancelled")
            return {"success": True}

        try:
            processor.process_batch(
                items=items,
                process_fn=process_item,
                max_workers=1,
            )
        except KeyboardInterrupt:
            pass

        # State should be saved as CANCELLED
        state = processor.load_state()
        assert state is not None
        assert state["status"] in ["cancelled", "paused"]


class TestBatchErrorHandling:
    """Test error handling in batch processing."""

    def test_handle_missing_state_file(self, tmp_path):
        """Test handling of missing state file."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "nonexistent.json",
        )

        state = processor.load_state()

        # Should return None or default state, not crash
        assert state is None or isinstance(state, dict)

    def test_handle_corrupted_state_file(self, tmp_path):
        """Test handling of corrupted state file."""
        state_file = tmp_path / "corrupted.json"
        state_file.write_text("not valid json {{{")

        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=state_file,
        )

        state = processor.load_state()

        # Should handle corrupted file gracefully
        assert state is None or isinstance(state, dict)

    def test_handle_permission_error(self, tmp_path):
        """Test handling of permission errors."""
        import stat

        state_file = tmp_path / "readonly.json"
        state_file.write_text("{}")

        # Make file read-only
        state_file.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=state_file,
        )

        # Should handle permission error gracefully
        try:
            processor.save_state(BatchState(batch_id="test", total_items=0))
        except PermissionError:
            pass  # Expected

        # Restore permissions for cleanup
        state_file.chmod(stat.S_IWUSR | stat.S_IRUSR)


class TestBatchMetrics:
    """Test batch processing metrics."""

    def test_calculate_throughput(self, tmp_path, sample_batch_items):
        """Test calculating processing throughput."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

        def process_item(item_data):
            return {"success": True}

        start_time = datetime.now(timezone.utc)

        processor.process_batch(
            items=sample_batch_items,
            process_fn=process_item,
            max_workers=2,
        )

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        throughput = len(sample_batch_items) / duration if duration > 0 else 0

        # Should have processed items with some throughput
        assert throughput > 0

    def test_track_success_rate(self, tmp_path):
        """Test tracking success rate."""
        processor = BatchProcessor(
            batch_id="test_batch",
            state_file=tmp_path / "batch_state.json",
        )

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

        results = processor.process_batch(
            items=items,
            process_fn=process_item,
            max_workers=1,
            retry_failed=False,
        )

        successful = len([r for r in results if r.get("success")])
        success_rate = successful / len(items)

        # 3 out of 4 should succeed = 75%
        assert success_rate == 0.75
