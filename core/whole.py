"""Whole-file processing support for QuantumVault.

This module provides a simple interface for reading and writing an entire file
as a single byte stream without any encryption logic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Union

from .utils import ensure_parent_directory

LOGGER = logging.getLogger(__name__)
PathLike = Union[str, os.PathLike[str]]


class WholeFileProcessor:
    """Read and write an entire file as a single unit."""

    def read_file(self, source_path: PathLike) -> bytes:
        """Read the full contents of a file into memory.

        Args:
            source_path: The input file path.

        Returns:
            The file contents as bytes.
        """
        file_path = Path(source_path)
        with file_path.open("rb") as handle:
            return handle.read()

    def write_file(self, destination_path: PathLike, data: bytes) -> None:
        """Write bytes to a destination file.

        Args:
            destination_path: The output file path.
            data: The bytes to write.
        """
        ensure_parent_directory(destination_path)
        output_path = Path(destination_path)
        with output_path.open("wb") as handle:
            handle.write(data)

    def process_file(self, source_path: PathLike, destination_path: PathLike) -> None:
        """Copy the contents of one file to another.

        Args:
            source_path: The source file path.
            destination_path: The destination file path.
        """
        data = self.read_file(source_path)
        self.write_file(destination_path, data)
