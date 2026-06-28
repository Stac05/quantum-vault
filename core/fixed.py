"""Fixed-size chunk processing support for QuantumVault.

This module provides a processor that splits a file into fixed-size chunks,
iterates over them, and merges them back into a reconstructed file.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator, Union

from .chunker import ChunkReader, ChunkWriter
from .utils import validate_chunk_size

LOGGER = logging.getLogger(__name__)
PathLike = Union[str, os.PathLike[str]]


class FixedChunkProcessor:
    """Process files as a sequence of fixed-size chunks."""

    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        """Initialize the processor with a chunk size.

        Args:
            chunk_size: The size of each chunk in bytes.
        """
        self.chunk_size = validate_chunk_size(chunk_size)

    def iter_chunks(self, source_path: PathLike) -> Iterator[bytes]:
        """Yield the source file in fixed-size chunks.

        Args:
            source_path: The source file path.

        Yields:
            Sequential byte chunks.
        """
        reader = ChunkReader(chunk_size=self.chunk_size)
        yield from reader.iter_chunks(source_path)

    def merge_chunks(self, chunks: Iterator[bytes], destination_path: PathLike) -> None:
        """Write a sequence of chunks to a destination file.

        Args:
            chunks: The chunk iterator to write.
            destination_path: The output file path.
        """
        writer = ChunkWriter(destination_path)
        writer.write_chunks(chunks)

    def process_file(self, source_path: PathLike, destination_path: PathLike) -> None:
        """Split a source file into fixed-size chunks and rebuild it.

        Args:
            source_path: The source file path.
            destination_path: The destination file path.
        """
        self.merge_chunks(self.iter_chunks(source_path), destination_path)
