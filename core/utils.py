"""Generic utility helpers for the QuantumVault chunk-processing engine.

These helpers are intentionally limited to reusable file-system and sizing
operations that support chunk processing without any cryptographic logic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Union

LOGGER = logging.getLogger(__name__)
PathLike = Union[str, os.PathLike[str]]


def validate_chunk_size(chunk_size: int) -> int:
    """Validate a requested chunk size and return it as an integer.

    Args:
        chunk_size: The desired chunk size in bytes.

    Returns:
        The validated chunk size.

    Raises:
        ValueError: If the chunk size is not a positive integer.
    """
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise ValueError("Chunk size must be a positive integer.")
    if chunk_size <= 0:
        raise ValueError("Chunk size must be greater than zero.")
    return chunk_size


def ensure_parent_directory(path: PathLike) -> None:
    """Create the parent directory for a file path if it does not exist.

    Args:
        path: The target file path.
    """
    destination_path = Path(path)
    if destination_path.parent != Path(""):
        destination_path.parent.mkdir(parents=True, exist_ok=True)


def get_file_size(path: PathLike) -> int:
    """Return the size of a file in bytes.

    Args:
        path: The file path to inspect.

    Returns:
        The number of bytes in the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be accessed.
    """
    file_path = Path(path)
    return file_path.stat().st_size
