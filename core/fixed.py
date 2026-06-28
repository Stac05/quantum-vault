"""Fixed-size chunk processing support for QuantumVault.

This module provides a processor that splits a file into fixed-size chunks,
iterates over them, and merges them back into a reconstructed file.
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
    pack_encrypted_session_key,
    resolve_manifest_path,
    unpack_encrypted_session_key,
    validate_chunk_size,
    xor_bytes,
    derive_key,
)

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

    def encrypt(
        self,
        source_path: PathLike,
        destination_path: PathLike,
        public_key: bytes,
        manifest_path: PathLike | None = None,
        kem: MLKEM768 | None = None,
        cipher: AESGCMCipher | None = None,
    ) -> Manifest:
        """Encrypt a file as a sequence of fixed-size chunks.

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

        file_size = source_file.stat().st_size
        total_chunks = math.ceil(file_size / self.chunk_size) if file_size > 0 else 0

        manifest = Manifest(
            filename=source_file.name,
            original_size=file_size,
            encryption_mode="fixed",
            chunk_size=self.chunk_size,
            total_chunks=total_chunks or None,
            cipher="AES-256-GCM",
            kem="ML-KEM-768",
            nonce=base_nonce,
            encrypted_session_key=pack_encrypted_session_key(kem_ciphertext, b""),
        )
        
        manifest_aad = manifest.get_aad()
        chunks_encrypted = 0

        ensure_parent_directory(destination_file)
        with destination_file.open("wb") as out_file:
            for index, chunk in enumerate(self.iter_chunks(source_file)):
                chunk_nonce = self._derive_nonce(base_nonce, index)
                ciphertext, tag = aes_cipher.encrypt(chunk, nonce=chunk_nonce, associated_data=manifest_aad)
                chunk_record = struct.pack(">I", len(chunk_nonce))
                chunk_record += chunk_nonce
                chunk_record += struct.pack(">I", len(ciphertext))
                chunk_record += ciphertext
                chunk_record += tag
                out_file.write(chunk_record)
                chunks_encrypted += 1

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
        """Decrypt a fixed-chunk payload using the supplied private key.

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
        manifest_aad = manifest.get_aad()
        ensure_parent_directory(destination_file)
        
        tmp_destination = destination_file.with_name(destination_file.name + ".tmp")
        try:
            with source_file.open("rb") as f, tmp_destination.open("wb") as out_file:
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
                    decrypted = aes_cipher.decrypt(ciphertext, tag, derived_nonce, associated_data=manifest_aad)
                    out_file.write(decrypted)
                    chunk_index += 1
                    
            if chunk_index != (manifest.total_chunks or 0):
                raise ValueError("Encrypted chunk payload is truncated or incomplete.")
                
            tmp_destination.replace(destination_file)
        except Exception:
            if tmp_destination.exists():
                tmp_destination.unlink()
            raise
            
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
