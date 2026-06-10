"""Tests for Firehose chunking functionality."""

import base64

from portunus.config import config
from portunus.util import chunk_body_data


class TestFirehoseChunking:
    """Test cases for body data chunking."""

    def test_small_body_single_chunk(self):
        """Test that small bodies are returned as a single chunk."""
        small_body = b"small data"
        chunks = chunk_body_data(small_body)

        assert len(chunks) == 1, "Small body should result in a single chunk"
        assert chunks[0] == small_body, "Single chunk should contain original data"

    def test_large_body_chunking(self):
        """Test that large bodies are chunked properly."""
        # Create a large body that will require chunking
        large_body = b"0" * (1024 * 1024)  # 1MB
        chunks = chunk_body_data(large_body)

        # Should have multiple chunks
        assert len(chunks) > 1, "Large body should be chunked"

        # Verify each chunk is raw bytes and not empty
        for i, chunk in enumerate(chunks):
            assert isinstance(chunk, bytes), f"Chunk {i} should be bytes"
            assert len(chunk) > 0, f"Chunk {i} should not be empty"

    def test_chunk_reassembly(self):
        """Test that chunked data can be reassembled correctly."""
        original_body = b"test data " * 100000  # Large enough to chunk
        chunks = chunk_body_data(original_body)

        # Reassemble chunks
        reassembled_body = b"".join(chunks)
        assert (
            reassembled_body == original_body
        ), "Reassembled body should match original"

    def test_chunk_size_within_limits(self):
        """Each chunk stays within Firehose size limits when base64-encoded."""
        large_body = b"x" * (2 * 1024 * 1024)  # 2MB
        chunks = chunk_body_data(large_body)

        max_size = config.firehose.max_record_size
        for i, chunk in enumerate(chunks):
            # The chunk will be base64 encoded when published, so check that size
            encoded_size = len(base64.b64encode(chunk))
            # Add some overhead for the JSON wrapper (100 bytes)
            total_size = encoded_size + 100
            assert (
                total_size <= max_size
            ), f"Chunk {i} exceeds max size after encoding ({total_size} > {max_size})"
