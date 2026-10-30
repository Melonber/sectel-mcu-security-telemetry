#!/usr/bin/env python3
"""Flip one byte in the middle of a signed image: the header (version) stays
readable, but the integrity / signature check must fail.

Usage:  python3 tamper_image.py images/sectel-0.3.1.bin
"""
import sys
from pathlib import Path

src = Path(sys.argv[1])
data = bytearray(src.read_bytes())
off = len(data) // 2
data[off] ^= 0xFF
dst = src.with_name(src.stem + "-tampered.bin")
dst.write_bytes(data)
print(f"{dst}: byte at offset {off:#x} flipped ({len(data)} bytes)")
