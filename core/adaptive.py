"""Adaptive chunk processing support for QuantumVault.

This module calculates chunk sizes using the documented algorithm from the
project specification and processes files accordingly.
"""

from __future__ import annotations

import logging
import math
import os
import struct
from pathlib import Path
from typing import Iterator, Union

from .aes import AESGCMCipher
from .chunker import ChunkReader, ChunkWriter
from .kem import MLKEM768
from .manifest import Manifest
from .utils import (
    ensure_parent_directory,
    get_file_size,
    pack_encrypted_session_key,
    resolve_manifest_path,
    unpack_encrypted_session_key,
    xor_bytes,
    derive_key,
)

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

    def encrypt(
        self,
        source_path: PathLike,
        destination_path: PathLike,
        public_key: bytes,
        manifest_path: PathLike | None = None,
        kem: MLKEM768 | None = None,
        cipher: AESGCMCipher | None = None,
    ) -> Manifest:
        """Encrypt a file using adaptive-size chunking and a single session key.

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

        kem_backend = kem or MLKEM768()
        kem_ciphertext, shared_secret = kem_backend.encapsulate(bytes(public_key))
        session_key = derive_key(shared_secret)

        base_nonce = AESGCMCipher.generate_nonce()
        aes_cipher = cipher or AESGCMCipher.from_key(session_key)
        chunks_encrypted = 0
        chunk_size = self.calculate_chunk_size(get_file_size(source_file))

        ensure_parent_directory(destination_file)
        with destination_file.open("wb") as out_file:
            for index, chunk in enumerate(self.iter_chunks(source_file)):
                chunk_nonce = self._derive_nonce(base_nonce, index)
                ciphertext, tag = aes_cipher.encrypt(chunk, nonce=chunk_nonce)
                chunk_record = struct.pack(">I", len(chunk_nonce))
                chunk_record += chunk_nonce
                chunk_record += struct.pack(">I", len(ciphertext))
                chunk_record += ciphertext
                chunk_record += tag
                out_file.write(chunk_record)
                chunks_encrypted += 1

        manifest = Manifest(
            filename=source_file.name,
            original_size=source_file.stat().st_size,
            encryption_mode="adaptive",
            chunk_size=chunk_size or None,
            total_chunks=chunks_encrypted or None,
            cipher="AES-256-GCM",
            kem="ML-KEM-768",
            nonce=base_nonce,
            encrypted_session_key=pack_encrypted_session_key(kem_ciphertext, b""),
        )

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
        """Decrypt an adaptive-chunk payload using the supplied private key.

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

        kem_backend = kem or MLKEM768()
        kem_ciphertext, protected_key = unpack_encrypted_session_key(
            manifest.encrypted_session_key or b""
        )
        shared_secret = kem_backend.decapsulate(kem_ciphertext, bytes(private_key))
        session_key = derive_key(shared_secret)
        aes_cipher = AESGCMCipher.from_key(session_key)

        chunk_index = 0
        ensure_parent_directory(destination_file)
        with source_file.open("rb") as f, destination_file.open("wb") as out_file:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                if len(length_bytes) < 4:
                    raise ValueError("Encrypted chunk payload is truncated.")
                nonce_length = int.from_bytes(length_bytes, "big")

                chunk_nonce = f.read(nonce_length)
                if len(chunk_nonce) < nonce_length:
                    raise ValueError("Encrypted chunk payload is truncated.")

                len_bytes_ct = f.read(4)
                if len(len_bytes_ct) < 4:
                    raise ValueError("Encrypted chunk payload is truncated.")
                ciphertext_length = int.from_bytes(len_bytes_ct, "big")

                ciphertext = f.read(ciphertext_length)
                if len(ciphertext) < ciphertext_length:
                    raise ValueError("Encrypted chunk payload is truncated.")

                tag = f.read(AESGCMCipher.TAG_SIZE)
                if len(tag) < AESGCMCipher.TAG_SIZE:
                    raise ValueError("Encrypted chunk payload is truncated.")

                derived_nonce = self._derive_nonce(manifest.nonce or chunk_nonce, chunk_index)
                decrypted = aes_cipher.decrypt(ciphertext, tag, derived_nonce)
                out_file.write(decrypted)
                chunk_index += 1
        return manifest

    @staticmethod
    def _read_bytes(source_path: PathLike) -> bytes:
        """Read bytes from a file path."""
        with Path(source_path).open("rb") as handle:
            return handle.read()

    @staticmethod
    def _write_bytes(destination_path: PathLike, data: bytes) -> None:
        """Write bytes to a file path."""
        ensure_parent_directory(destination_path)
        with Path(destination_path).open("wb") as handle:
            handle.write(data)

    @staticmethod
    def _derive_nonce(base_nonce: bytes, index: int) -> bytes:
        """Derive a per-chunk nonce from the manifest nonce and chunk index."""
        nonce_bytes = bytes(base_nonce)
        if len(nonce_bytes) < 8:
            raise ValueError("Base nonce must be at least 8 bytes long.")
        return nonce_bytes[:8] + struct.pack(">I", index)
