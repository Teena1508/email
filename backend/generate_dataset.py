#!/usr/bin/env python3
import os
import sys
import argparse
from pathlib import Path

# Ensure backend directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.synthetic.generator import SyntheticDatasetGenerator

def main():
    parser = argparse.ArgumentParser(
        description="Synthetic PCAP & Label Generator for Email TLS Forensics Framework"
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=240,
        help="Total number of synthetic sessions to generate (default: 240)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=str(Path(__file__).resolve().parent.parent / "data" / "synthetic"),
        help="Destination directory for PCAP and JSON label files"
    )

    args = parser.parse_args()

    generator = SyntheticDatasetGenerator(args.output)
    generator.generate(total_sessions=args.count)

if __name__ == "__main__":
    main()
