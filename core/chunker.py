"""Chunk reader and writer utilities for QuantumVault.

The chunker module provides reusable primitives for sequential file reads and
writes without loading the full content into memory.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, Iterator, Union

from .utils import ensure_parent_directory, validate_chunk_size

LOGGER = logging.getLogger(__name__)
PathLike = Union[str, os.PathLike[str]]


class ChunkReader:
    """Read a file sequentially in fixed-size chunks."""

    def __init__(self, chunk_size: int = 1024 * 1024) -> None:
        """Initialize the reader with a chunk size.

        Args:
            chunk_size: The number of bytes to read at a time.
        """
        self.chunk_size = validate_chunk_size(chunk_size)

    def iter_chunks(self, source_path: PathLike) -> Iterator[bytes]:
        """Yield file contents in sequential chunks.

        Args:
            source_path: The path to the source file.

        Yields:
            Successive byte chunks from the source file.
        """
        file_path = Path(source_path)
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk


class ChunkWriter:
    """Write a sequence of chunks to a destination file."""

    def __init__(self, destination_path: PathLike) -> None:
        """Initialize the writer with an output path.

        Args:
            destination_path: The path to the output file.
        """
        self.destination_path = Path(destination_path)

    def write_chunk(self, chunk: bytes) -> None:
        """Append a single chunk to the output file.

        Args:
            chunk: The bytes to write.
        """
        self.write_chunks([chunk], overwrite=False)

    def write_chunks(
        self,
        chunks: Iterable[bytes],
        overwrite: bool = True,
    ) -> None:
        """Write an iterable of chunks to the output file.

        Args:
            chunks: An iterable containing byte chunks.
            overwrite: Whether to overwrite the destination file if it exists.
        """
        ensure_parent_directory(self.destination_path)
        mode = "wb" if overwrite else "ab"
        with self.destination_path.open(mode) as handle:
            for chunk in chunks:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("Each chunk must be bytes-like.")
                handle.write(bytes(chunk))


def split_file(source_path: PathLike, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    """Split a file into sequential chunks.

    Args:
        source_path: The file to split.
        chunk_size: The preferred size of each chunk in bytes.

    Yields:
        Sequential byte chunks.
    """
    reader = ChunkReader(chunk_size=chunk_size)
    yield from reader.iter_chunks(source_path)


def merge_chunks(chunks: Iterable[bytes], destination_path: PathLike) -> None:
    """Write an iterable of chunks to a destination file.

    Args:
        chunks: The byte chunks to write.
        destination_path: The target output file path.
    """
    writer = ChunkWriter(destination_path)
    writer.write_chunks(chunks)
