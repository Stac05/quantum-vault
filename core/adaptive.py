"""Adaptive chunk processing support for QuantumVault.

This module calculates chunk sizes using the documented algorithm from the
project specification and processes files accordingly.
"""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path
from typing import Iterator, Union

from .chunker import ChunkReader, ChunkWriter
from .utils import get_file_size

LOGGER = logging.getLogger(__name__)
PathLike = Union[str, os.PathLike[str]]


class AdaptiveChunkProcessor:
    """Process files using an adaptive chunk-size strategy."""

    MIN_CHUNK_SIZE = 1024 * 1024
    MAX_CHUNK_SIZE = 32 * 1024 * 1024
    TARGET_CHUNKS = 128

    def calculate_chunk_size(self, file_size: int) -> int:
        """Calculate a chunk size from the file size using the algorithm.

        Args:
            file_size: The source file size in bytes.

        Returns:
            The adaptive chunk size in bytes.
        """
        if file_size <= 0:
            return 0

        raw_chunk_size = math.ceil(file_size / self.TARGET_CHUNKS)
        nearest_power_of_two = 1 << (raw_chunk_size - 1).bit_length()
        clamped_chunk_size = max(
            self.MIN_CHUNK_SIZE,
            min(nearest_power_of_two, self.MAX_CHUNK_SIZE),
        )
        return clamped_chunk_size

    def iter_chunks(self, source_path: PathLike) -> Iterator[bytes]:
        """Yield the source file in adaptive-size chunks.

        Args:
            source_path: The source file path.

        Yields:
            Sequential byte chunks.
        """
        file_path = Path(source_path)
        chunk_size = self.calculate_chunk_size(get_file_size(file_path))
        if chunk_size <= 0:
            return

        reader = ChunkReader(chunk_size=chunk_size)
        yield from reader.iter_chunks(file_path)

    def merge_chunks(self, chunks: Iterator[bytes], destination_path: PathLike) -> None:
        """Write a sequence of chunks to a destination file.

        Args:
            chunks: The chunk iterator to write.
            destination_path: The output file path.
        """
        writer = ChunkWriter(destination_path)
        writer.write_chunks(chunks)

    def process_file(self, source_path: PathLike, destination_path: PathLike) -> None:
        """Split a source file into adaptive-size chunks and rebuild it.

        Args:
            source_path: The source file path.
            destination_path: The destination file path.
        """
        self.merge_chunks(self.iter_chunks(source_path), destination_path)
