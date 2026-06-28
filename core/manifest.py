"""Reusable manifest support for QuantumVault.

The manifest model stores encryption metadata in JSON format and provides
validation, serialization, and deserialization helpers.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .utils import ensure_parent_directory

LOGGER = logging.getLogger(__name__)


class ManifestError(ValueError):
    """Raised when manifest data is invalid or unsupported."""


@dataclass(slots=True)
class Manifest:
    """Represent the metadata for an encrypted package."""

    filename: str
    original_size: int
    encryption_mode: str
    chunk_size: int | None = None
    total_chunks: int | None = None
    cipher: str = "AES-256-GCM"
    kem: str = "ML-KEM-768"
    version: int = 1
    nonce: bytes | None = None
    encrypted_session_key: bytes | None = None

    def __post_init__(self) -> None:
        """Validate the manifest data after initialization."""
        self.validate()

    def validate(self) -> None:
        """Validate manifest values and raise an error if anything is invalid."""
        if not isinstance(self.filename, str) or not self.filename:
            raise ManifestError("Manifest filename must be a non-empty string.")
        if not isinstance(self.original_size, int) or self.original_size < 0:
            raise ManifestError("Manifest original_size must be a non-negative integer.")
        if not isinstance(self.encryption_mode, str) or not self.encryption_mode:
            raise ManifestError("Manifest encryption_mode must be a non-empty string.")
        if self.chunk_size is not None and (
            not isinstance(self.chunk_size, int) or self.chunk_size <= 0
        ):
            raise ManifestError("Manifest chunk_size must be a positive integer or None.")
        if self.total_chunks is not None and (
            not isinstance(self.total_chunks, int) or self.total_chunks <= 0
        ):
            raise ManifestError("Manifest total_chunks must be a positive integer or None.")
        if not isinstance(self.cipher, str) or not self.cipher:
            raise ManifestError("Manifest cipher must be a non-empty string.")
        if not isinstance(self.kem, str) or not self.kem:
            raise ManifestError("Manifest kem must be a non-empty string.")
        if not isinstance(self.version, int) or self.version <= 0:
            raise ManifestError("Manifest version must be a positive integer.")
        if self.version != 1:
            raise ManifestError("Unsupported manifest version.")
        if self.nonce is not None and not isinstance(self.nonce, (bytes, bytearray)):
            raise ManifestError("Manifest nonce must be bytes or None.")
        if self.encrypted_session_key is not None and not isinstance(
            self.encrypted_session_key,
            (bytes, bytearray),
        ):
            raise ManifestError("Manifest encrypted_session_key must be bytes or None.")

    def to_dict(self) -> dict[str, Any]:
        """Convert the manifest to a JSON-serializable dictionary.

        Returns:
            A dictionary representation of the manifest.
        """
        return {
            "filename": self.filename,
            "original_size": self.original_size,
            "encryption_mode": self.encryption_mode,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "cipher": self.cipher,
            "kem": self.kem,
            "version": self.version,
            "nonce": self._encode_bytes(self.nonce),
            "encrypted_session_key": self._encode_bytes(self.encrypted_session_key),
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the manifest as JSON.

        Args:
            indent: The JSON indentation level.

        Returns:
            The manifest serialized as JSON.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def write_to_file(self, destination_path: str | Path) -> None:
        """Write the manifest to a JSON file.

        Args:
            destination_path: The output path for the manifest.
        """
        path = Path(destination_path)
        ensure_parent_directory(path)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Manifest":
        """Deserialize a manifest from a mapping.

        Args:
            data: A mapping that contains the manifest fields.

        Returns:
            A new manifest instance.

        Raises:
            TypeError: If the data is not a mapping.
            ManifestError: If the payload is malformed or the version is unsupported.
        """
        if not isinstance(data, Mapping):
            raise TypeError("Manifest data must be a mapping.")

        try:
            return cls(
                filename=str(data["filename"]),
                original_size=int(data["original_size"]),
                encryption_mode=str(data["encryption_mode"]),
                chunk_size=data.get("chunk_size"),
                total_chunks=data.get("total_chunks"),
                cipher=str(data.get("cipher", "AES-256-GCM")),
                kem=str(data.get("kem", "ML-KEM-768")),
                version=int(data.get("version", 1)),
                nonce=cls._decode_bytes(data.get("nonce")),
                encrypted_session_key=cls._decode_bytes(data.get("encrypted_session_key")),
            )
        except KeyError as exc:
            raise ManifestError(f"Manifest is missing required field: {exc.args[0]}") from exc
        except (TypeError, ValueError) as exc:
            raise ManifestError("Manifest data is corrupted.") from exc

    @classmethod
    def from_json(cls, raw_data: str) -> "Manifest":
        """Deserialize a manifest from a JSON string.

        Args:
            raw_data: A JSON payload representing the manifest.

        Returns:
            A new manifest instance.

        Raises:
            ManifestError: If the JSON payload is malformed or invalid.
        """
        try:
            payload = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise ManifestError("Manifest JSON is malformed.") from exc
        return cls.from_dict(payload)

    @classmethod
    def from_file(cls, source_path: str | Path) -> "Manifest":
        """Load a manifest from a JSON file.

        Args:
            source_path: The manifest file path.

        Returns:
            A manifest instance populated from disk.
        """
        path = Path(source_path)
        return cls.from_json(path.read_text(encoding="utf-8"))

    @staticmethod
    def _encode_bytes(value: bytes | bytearray | None) -> str | None:
        """Encode bytes-like values for JSON serialization.

        Args:
            value: The bytes-like value to encode.

        Returns:
            The base64-encoded string or ``None``.
        """
        if value is None:
            return None
        return base64.b64encode(bytes(value)).decode("ascii")

    @staticmethod
    def _decode_bytes(value: Any) -> bytes | None:
        """Decode base64-encoded bytes for manifest deserialization.

        Args:
            value: The value to decode.

        Returns:
            The decoded bytes or ``None``.
        """
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        return base64.b64decode(str(value))
