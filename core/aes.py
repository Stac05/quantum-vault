"""Byte-oriented AES-256-GCM utilities for QuantumVault.

This module provides reusable cryptographic primitives for encrypting and
verifying bytes without performing file or chunk processing.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOGGER = logging.getLogger(__name__)


class AESGCMCipher:
    """Provide AES-256-GCM encryption and decryption for byte payloads."""

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes | None = None) -> None:
        """Initialize the cipher with an AES-256 key.

        Args:
            key: A 32-byte session key. If omitted, a new random key is generated.
        """
        self._key = self._validate_key(key) if key is not None else self.generate_key()

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit AES session key.

        Returns:
            A 32-byte encryption key.
        """
        return os.urandom(AESGCMCipher.KEY_SIZE)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a random 96-bit nonce for AES-GCM.

        Returns:
            A 12-byte nonce.
        """
        return os.urandom(AESGCMCipher.NONCE_SIZE)

    @staticmethod
    def _validate_key(key: bytes | None) -> bytes:
        """Validate that the provided key is a 32-byte value.

        Args:
            key: The candidate AES key.

        Returns:
            The validated key as bytes.

        Raises:
            TypeError: If the value is not bytes-like.
            ValueError: If the key length is not 32 bytes.
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes-like.")

        key_bytes = bytes(key)
        if len(key_bytes) != AESGCMCipher.KEY_SIZE:
            raise ValueError("AES-256-GCM requires a 32-byte session key.")
        return key_bytes

    @classmethod
    def from_key(cls, key: bytes) -> "AESGCMCipher":
        """Create a cipher instance from an existing AES key.

        Args:
            key: A 32-byte AES key.

        Returns:
            An initialized AES-GCM cipher instance.
        """
        return cls(key=key)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt plaintext bytes and return ciphertext and authentication tag.

        Args:
            plaintext: The plaintext bytes to encrypt.
            associated_data: Optional additional authenticated data.
            nonce: Optional nonce. A random nonce is generated if omitted.

        Returns:
            A tuple containing the ciphertext bytes and the authentication tag.

        Raises:
            TypeError: If the input values are not bytes-like.
            ValueError: If the nonce is not 12 bytes long.
        """
        plaintext_bytes = self._validate_bytes(plaintext, "Plaintext")
        aad_bytes = self._validate_optional_bytes(associated_data, "Associated data")
        nonce_bytes = self._prepare_nonce(nonce)

        combined = AESGCM(self._key).encrypt(nonce_bytes, plaintext_bytes, aad_bytes)
        ciphertext = combined[:-self.TAG_SIZE]
        tag = combined[-self.TAG_SIZE:]
        return ciphertext, tag

    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt ciphertext bytes and verify the authentication tag.

        Args:
            ciphertext: The ciphertext bytes to decrypt.
            tag: The authentication tag bytes.
            nonce: The nonce used for encryption.
            associated_data: Optional authenticated data used during encryption.

        Returns:
            The decrypted plaintext bytes.

        Raises:
            TypeError: If the inputs are not bytes-like.
            ValueError: If the nonce is invalid or the tag is malformed.
            InvalidTag: If the authentication tag verification fails.
        """
        ciphertext_bytes = self._validate_bytes(ciphertext, "Ciphertext")
        tag_bytes = self._validate_bytes(tag, "Tag")
        aad_bytes = self._validate_optional_bytes(associated_data, "Associated data")
        nonce_bytes = self._prepare_nonce(nonce)

        if len(tag_bytes) != self.TAG_SIZE:
            raise ValueError("Tag must be exactly 16 bytes long.")

        combined = ciphertext_bytes + tag_bytes
        return AESGCM(self._key).decrypt(nonce_bytes, combined, aad_bytes)

    def verify_tag(
        self,
        ciphertext: bytes,
        tag: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bool:
        """Verify the authentication tag for a ciphertext payload.

        Args:
            ciphertext: The ciphertext bytes.
            tag: The authentication tag bytes.
            nonce: The nonce used for encryption.
            associated_data: Optional authenticated data used during encryption.

        Returns:
            True when the tag is valid, otherwise False.
        """
        try:
            self.decrypt(ciphertext, tag, nonce, associated_data)
        except (InvalidTag, ValueError, TypeError):
            return False
        return True

    @staticmethod
    def _validate_bytes(value: bytes | bytearray, name: str) -> bytes:
        """Validate that a value is bytes-like.

        Args:
            value: The value to validate.
            name: The user-facing label for the value.

        Returns:
            The validated bytes value.

        Raises:
            TypeError: If the value is not bytes-like.
        """
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes-like.")
        return bytes(value)

    @staticmethod
    def _validate_optional_bytes(value: bytes | bytearray | None, name: str) -> bytes | None:
        """Validate optional bytes-like input.

        Args:
            value: The optional value to validate.
            name: The label for the input.

        Returns:
            The validated bytes value or ``None``.
        """
        if value is None:
            return None
        return AESGCMCipher._validate_bytes(value, name)

    def _prepare_nonce(self, nonce: bytes | None) -> bytes:
        """Prepare a nonce from the provided or generated value.

        Args:
            nonce: An optional nonce.

        Returns:
            The validated 12-byte nonce.

        Raises:
            TypeError: If the nonce is not bytes-like.
            ValueError: If the nonce is not 12 bytes long.
        """
        if nonce is None:
            return self.generate_nonce()

        nonce_bytes = self._validate_bytes(nonce, "Nonce")
        if len(nonce_bytes) != self.NONCE_SIZE:
            raise ValueError("Nonce must be exactly 12 bytes long.")
        return nonce_bytes
