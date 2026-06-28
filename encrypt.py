import argparse
import logging
import sys
from pathlib import Path

from core.kem import MLKEM768
from core.whole import WholeFileProcessor
from core.fixed import FixedChunkProcessor
from core.adaptive import AdaptiveChunkProcessor

VERSION = "QuantumVault 1.0.0"

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )

def handle_keygen(args):
    try:
        kem = MLKEM768()
        private_key, public_key = kem.generate_keypair()
        
        pub_path = Path(args.public)
        priv_path = Path(args.private)
        
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        
        pub_path.write_bytes(public_key)
        priv_path.write_bytes(private_key)
        
        logging.info("Keys generated successfully.")
        logging.info(f"Public key: {pub_path}")
        logging.info(f"Private key: {priv_path}")
    except Exception as e:
        logging.error(f"Failed to generate keys: {e}")
        sys.exit(1)

def handle_encrypt(args):
    try:
        input_path = Path(args.input)
        if not input_path.is_file():
            logging.error(f"Input file not found: {input_path}")
            sys.exit(1)
            
        pub_path = Path(args.public)
        if not pub_path.is_file():
            logging.error(f"Public key file not found: {pub_path}")
            sys.exit(1)
            
        public_key = pub_path.read_bytes()
        
        if args.mode == "whole":
            processor = WholeFileProcessor()
        elif args.mode == "fixed":
            processor = FixedChunkProcessor()
        elif args.mode == "adaptive":
            processor = AdaptiveChunkProcessor()
        else:
            logging.error(f"Unsupported encryption mode: {args.mode}")
            sys.exit(1)
            
        logging.info(f"Encrypting {input_path} using {args.mode} mode...")
        processor.encrypt(
            source_path=input_path,
            destination_path=args.output,
            public_key=public_key
        )
        logging.info(f"Encryption successful. Output saved to: {args.output}")
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        sys.exit(1)

def main():
    setup_logging()
    
    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        parser = argparse.ArgumentParser(description="QuantumVault Key Generation CLI")
        parser.add_argument("command", help="Command to run")
        parser.add_argument("--public", required=True, help="Path to save the public key")
        parser.add_argument("--private", required=True, help="Path to save the private key")
        args = parser.parse_args()
        handle_keygen(args)
    else:
        parser = argparse.ArgumentParser(description="QuantumVault Encryption CLI")
        parser.add_argument("--version", action="version", version=VERSION)
        parser.add_argument("--mode", required=True, choices=["whole", "fixed", "adaptive"], help="Encryption mode")
        parser.add_argument("--input", required=True, help="Input file path")
        parser.add_argument("--output", required=True, help="Output file path")
        parser.add_argument("--public", required=True, help="Path to the public key")
        args = parser.parse_args()
        handle_encrypt(args)

if __name__ == "__main__":
    main()
