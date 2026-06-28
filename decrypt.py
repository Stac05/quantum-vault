import argparse
import logging
import sys
from pathlib import Path

from core.manifest import Manifest
from core.whole import WholeFileProcessor
from core.fixed import FixedChunkProcessor
from core.adaptive import AdaptiveChunkProcessor
from core.utils import resolve_manifest_path

VERSION = "QuantumVault 1.0.0"

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )

def handle_decrypt(args):
    try:
        input_path = Path(args.input)
        if not input_path.is_file():
            logging.error(f"Input file not found: {input_path}")
            sys.exit(1)
            
        priv_path = Path(args.private)
        if not priv_path.is_file():
            logging.error(f"Private key file not found: {priv_path}")
            sys.exit(1)
            
        private_key = priv_path.read_bytes()
        
        manifest_file = resolve_manifest_path(input_path)
        if not manifest_file.is_file():
            logging.error(f"Manifest file not found: {manifest_file}")
            sys.exit(1)
            
        manifest = Manifest.from_file(manifest_file)
        
        if manifest.encryption_mode == "whole":
            processor = WholeFileProcessor()
        elif manifest.encryption_mode == "fixed":
            # For fixed processor we need to specify the chunk size if it differs from default,
            # but FixedChunkProcessor initialization defaults to a fixed size, we can leave it to defaults
            # or pass the chunk size from the manifest.
            if manifest.chunk_size:
                processor = FixedChunkProcessor(chunk_size=manifest.chunk_size)
            else:
                processor = FixedChunkProcessor()
        elif manifest.encryption_mode == "adaptive":
            processor = AdaptiveChunkProcessor()
        else:
            logging.error(f"Unsupported encryption mode in manifest: {manifest.encryption_mode}")
            sys.exit(1)
            
        logging.info(f"Decrypting {input_path} using {manifest.encryption_mode} mode...")
        processor.decrypt(
            source_path=input_path,
            destination_path=args.output,
            private_key=private_key
        )
        logging.info(f"Decryption successful. Output saved to: {args.output}")
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        sys.exit(1)

def main():
    setup_logging()
    
    parser = argparse.ArgumentParser(description="QuantumVault Decryption CLI")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--input", required=True, help="Encrypted input file path")
    parser.add_argument("--output", required=True, help="Decrypted output file path")
    parser.add_argument("--private", required=True, help="Path to the private key")
    
    args = parser.parse_args()
    handle_decrypt(args)

if __name__ == "__main__":
    main()
