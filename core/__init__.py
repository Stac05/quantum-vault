"""Core package for QuantumVault.

This package contains the reusable chunk-processing and cryptography modules
implemented during the early development phases.
"""

from .adaptive import AdaptiveChunkProcessor
from .aes import AESGCMCipher
from .chunker import ChunkReader, ChunkWriter, merge_chunks, split_file
from .fixed import FixedChunkProcessor
from .kem import KEMError, MLKEM768
from .manifest import Manifest, ManifestError
from .utils import ensure_parent_directory, get_file_size, validate_chunk_size
from .whole import WholeFileProcessor

__all__ = [
    "AdaptiveChunkProcessor",
    "AESGCMCipher",
    "ChunkReader",
    "ChunkWriter",
    "FixedChunkProcessor",
    "KEMError",
    "MLKEM768",
    "Manifest",
    "ManifestError",
    "WholeFileProcessor",
    "ensure_parent_directory",
    "get_file_size",
    "merge_chunks",
    "split_file",
    "validate_chunk_size",
]
