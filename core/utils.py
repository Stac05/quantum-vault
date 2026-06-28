"""Generic utility helpers for the QuantumVault chunk-processing engine.

These helpers are intentionally limited to reusable file-system and sizing
operations that support chunk processing without any cryptographic logic.
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


def resolve_manifest_path(destination_path: PathLike, manifest_path: PathLike | None = None) -> Path:
    """Resolve the manifest path for an encrypted output file.

    Args:
        destination_path: The encrypted output file path.
        manifest_path: An optional explicit manifest path.

    Returns:
        The manifest path to use.
    """
    if manifest_path is not None:
        return Path(manifest_path)

    destination = Path(destination_path)
    if destination.suffix:
        return destination.with_suffix(destination.suffix + ".manifest.json")
    return destination.with_name(destination.name + ".manifest.json")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte sequences.

    Args:
        left: The first byte sequence.
        right: The second byte sequence.

    Returns:
        The XORed byte sequence.

    Raises:
        ValueError: If the inputs are not the same length.
    """
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    if len(left_bytes) != len(right_bytes):
        raise ValueError("Byte sequences must be the same length for XOR.")
    return bytes(a ^ b for a, b in zip(left_bytes, right_bytes))


def pack_encrypted_session_key(kem_ciphertext: bytes, protected_session_key: bytes) -> bytes:
    """Pack the KEM ciphertext and protected session key into one bytes payload.

    Args:
        kem_ciphertext: The ML-KEM ciphertext bytes.
        protected_session_key: The protected AES session key bytes.

    Returns:
        A single bytes payload that can be stored in the manifest.
    """
    kem_bytes = bytes(kem_ciphertext)
    protected_bytes = bytes(protected_session_key)
    return struct.pack(">I", len(kem_bytes)) + kem_bytes + protected_bytes


def unpack_encrypted_session_key(payload: bytes) -> tuple[bytes, bytes]:
    """Unpack a manifest payload containing the KEM ciphertext and protected key.

    Args:
        payload: The encoded payload from the manifest.

    Returns:
        A tuple containing the KEM ciphertext bytes and the protected session key bytes.

    Raises:
        ValueError: If the payload is truncated or malformed.
    """
    payload_bytes = bytes(payload)
    if len(payload_bytes) < 4:
        raise ValueError("Encrypted session key payload is truncated.")

    kem_length = int.from_bytes(payload_bytes[:4], "big")
    offset = 4 + kem_length
    if len(payload_bytes) < offset:
        raise ValueError("Encrypted session key payload is truncated.")

    kem_ciphertext = payload_bytes[4:offset]
    protected_session_key = payload_bytes[offset:]
    return kem_ciphertext, protected_session_key


def derive_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES-256 session key from a KEM shared secret using HKDF.

    Args:
        shared_secret: The ML-KEM shared secret.

    Returns:
        The derived 32-byte key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    )
    return hkdf.derive(bytes(shared_secret))
