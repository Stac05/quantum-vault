"""ML-KEM wrapper abstractions for QuantumVault.

This module defines a stable public API for ML-KEM-style key encapsulation and
keeps any backend-specific implementation details behind an internal wrapper.
"""

from __future__ import annotations

import logging
from typing import Protocol

LOGGER = logging.getLogger(__name__)


class KEMError(RuntimeError):
    """Raised when KEM operations fail."""


class MLKEMBackend(Protocol):
    """Protocol for ML-KEM backend implementations."""

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Create a private/public key pair."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret for a given public key."""

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Recover a shared secret from ciphertext and a private key."""


class OQSBackend:
    """A backend that uses the Python OQS bindings for ML-KEM-768."""

    def __init__(self) -> None:
        """Initialize the OQS backend.

        Raises:
            ImportError: If the OQS Python bindings are not installed or do not
                expose the required ML-KEM methods.
        """
        try:
            import oqs  # pylint: disable=import-outside-toplevel
        except ImportError as exc:
            raise ImportError(
                "The ML-KEM backend is not installed. Install the Python OQS bindings "
                "to enable ML-KEM-768 support."
            ) from exc

        self._oqs = oqs
        try:
            self._kem = self._oqs.KeyEncapsulation("ML-KEM-768")
        except Exception as exc:  # pragma: no cover - backend-specific failure
            raise ImportError(
                "The installed liboqs-python package could not initialize ML-KEM-768."
            ) from exc

        required_methods = {
            "generate_keypair",
            "export_secret_key",
            "encap_secret",
            "decap_secret",
        }
        missing_methods = required_methods.difference(dir(self._kem))
        if missing_methods:
            raise ImportError(
                "The installed liboqs-python package is missing required ML-KEM methods: "
                f"{', '.join(sorted(missing_methods))}."
            )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a private/public key pair using the OQS backend.

        Returns:
            A tuple of ``(secret_key, public_key)`` bytes.
        """
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return secret_key, public_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret for a given public key.

        Args:
            public_key: The public key bytes.

        Returns:
            A tuple of ``(ciphertext, shared_secret)`` bytes.
        """
        return self._kem.encap_secret(public_key)

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate ciphertext using a private key.

        Args:
            ciphertext: The ciphertext bytes.
            private_key: The private key bytes.

        Returns:
            The recovered shared secret bytes.
        """
        del private_key
        return self._kem.decap_secret(ciphertext)


class MLKEM768:
    """A stable wrapper around a backend ML-KEM implementation."""

    def __init__(self, backend: MLKEMBackend | None = None) -> None:
        """Initialize the wrapper with a backend implementation.

        Args:
            backend: An optional backend that implements the ML-KEM interface.
        """
        self._backend = backend or OQSBackend()

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a private/public key pair for ML-KEM-768.

        Returns:
            A tuple of ``(private_key, public_key)`` bytes.
        """
        return self._backend.generate_keypair()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret for a given public key.

        Args:
            public_key: The public key bytes.

        Returns:
            A tuple of ``(ciphertext, shared_secret)`` bytes.
        """
        return self._backend.encapsulate(public_key)

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate ciphertext using a private key.

        Args:
            ciphertext: The ciphertext bytes.
            private_key: The private key bytes.

        Returns:
            The recovered shared secret bytes.
        """
        return self._backend.decapsulate(ciphertext, private_key)
