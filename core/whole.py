"""Whole-file processing support for QuantumVault.

This module provides a simple interface for reading and writing an entire file
as a single byte stream without any encryption logic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Union

from .aes import AESGCMCipher
from .kem import MLKEM768
from .manifest import Manifest
from .utils import ensure_parent_directory, pack_encrypted_session_key, resolve_manifest_path, unpack_encrypted_session_key, xor_bytes, derive_key

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

    def encrypt(
        self,
        source_path: PathLike,
        destination_path: PathLike,
        public_key: bytes,
        manifest_path: PathLike | None = None,
        kem: MLKEM768 | None = None,
        cipher: AESGCMCipher | None = None,
    ) -> Manifest:
        """Encrypt a whole file using one AES session key and one KEM encapsulation.

        Args:
            source_path: The source file to encrypt.
            destination_path: The encrypted output file path.
            public_key: The ML-KEM public key bytes.
            manifest_path: An optional path for the manifest JSON file.
            kem: An optional ML-KEM backend instance.
            cipher: An optional AES-GCM cipher instance.

        Returns:
            The generated manifest.
        """
        source_file = Path(source_path)
        destination_file = Path(destination_path)
        manifest_file = resolve_manifest_path(destination_file, manifest_path)
        plaintext = self.read_file(source_file)

        kem_backend = kem or MLKEM768()
        kem_ciphertext, shared_secret = kem_backend.encapsulate(bytes(public_key))
        session_key = derive_key(shared_secret)

        nonce = AESGCMCipher.generate_nonce()
        aes_cipher = cipher or AESGCMCipher.from_key(session_key)
        ciphertext, tag = aes_cipher.encrypt(plaintext, nonce=nonce)

        manifest = Manifest(
            filename=source_file.name,
            original_size=len(plaintext),
            encryption_mode="whole",
            chunk_size=None,
            total_chunks=1,
            cipher="AES-256-GCM",
            kem="ML-KEM-768",
            nonce=nonce,
            encrypted_session_key=pack_encrypted_session_key(kem_ciphertext, b""),
        )

        ensure_parent_directory(destination_file)
        with destination_file.open("wb") as out_file:
            out_file.write(nonce)
            out_file.write(ciphertext)
            out_file.write(tag)
        manifest.write_to_file(manifest_file)
        return manifest

    def decrypt(
        self,
        source_path: PathLike,
        destination_path: PathLike,
        private_key: bytes,
        manifest_path: PathLike | None = None,
        kem: MLKEM768 | None = None,
    ) -> Manifest:
        """Decrypt a whole-file payload using the supplied private key.

        Args:
            source_path: The encrypted input file.
            destination_path: The decrypted output file path.
            private_key: The ML-KEM private key bytes.
            manifest_path: An optional path for the manifest JSON file.
            kem: An optional ML-KEM backend instance.

        Returns:
            The manifest used for the encrypted package.
        """
        source_file = Path(source_path)
        destination_file = Path(destination_path)
        manifest_file = resolve_manifest_path(source_file, manifest_path)
        manifest = Manifest.from_file(manifest_file)
        payload = self.read_file(source_file)

        if len(payload) < AESGCMCipher.NONCE_SIZE + AESGCMCipher.TAG_SIZE:
            raise ValueError("Encrypted payload is truncated.")

        nonce = payload[:AESGCMCipher.NONCE_SIZE]
        ciphertext = payload[AESGCMCipher.NONCE_SIZE:-AESGCMCipher.TAG_SIZE]
        tag = payload[-AESGCMCipher.TAG_SIZE:]

        kem_backend = kem or MLKEM768()
        kem_ciphertext, protected_key = unpack_encrypted_session_key(
            manifest.encrypted_session_key or b""
        )
        shared_secret = kem_backend.decapsulate(kem_ciphertext, bytes(private_key))
        session_key = derive_key(shared_secret)
        aes_cipher = AESGCMCipher.from_key(session_key)
        plaintext = aes_cipher.decrypt(ciphertext, tag, nonce)

        self.write_file(destination_file, plaintext)
        return manifest
