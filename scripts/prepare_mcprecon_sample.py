"""Wrap one specific public MCPRecon VMEM in a derived LiME container.

The source lacks VMware snapshot metadata. Its BIOS-e820 text supports a
3 GiB low RAM / 5 GiB high RAM mapping, with a 1 GiB physical hole. This is an
inferred mapping, not acquisition metadata. The output is NOT a LiME capture.
Only the exact sample identified below is accepted; source bytes are preserved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

SOURCE_SHA256 = "65b5ccea17c6ce82d978d1b258590a42a2723b13f74b88a5335a7b10401c8bbf"
DERIVED_SHA256 = "9c375e111990c55150e6fa42e674e2ef0ddb1e2af1c6c45a4912a58c1d1d6c43"
GIB = 1024**3


def prepare(source: Path, destination: Path):
    if source.stat().st_size != 8 * GIB:
        raise ValueError("Expected the specific 8 GiB MCPRecon sample.vmem")
    source_hash, output_hash = hashlib.sha256(), hashlib.sha256()
    # Exclusive create prevents replacing either the source or an existing result.
    with source.open("rb") as src, destination.open("xb") as out:
        try:
            for start, length in [(0, 3 * GIB), (4 * GIB, 5 * GIB)]:
                header = struct.pack("<IIQQQ", 0x4C694D45, 1, start, start + length - 1, 0)
                out.write(header)
                output_hash.update(header)
                remaining = length
                while remaining:
                    block = src.read(min(16 * 1024**2, remaining))
                    if not block:
                        raise ValueError("Truncated source")
                    out.write(block)
                    source_hash.update(block)
                    output_hash.update(block)
                    remaining -= len(block)
            if src.read(1) or source_hash.hexdigest() != SOURCE_SHA256:
                raise ValueError("Source SHA-256 does not match the documented sample")
            if output_hash.hexdigest() != DERIVED_SHA256:
                raise ValueError("Derived SHA-256 mismatch")
            out.flush()
            os.fsync(out.fileno())
        except BaseException:
            # Only remove the file exclusively created by this invocation.
            out.close()
            destination.unlink()
            raise
    return {
        "source_sha256": source_hash.hexdigest(),
        "derived_sha256": output_hash.hexdigest(),
        "derived_bytes": destination.stat().st_size,
        "mapping_is_inferred": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.destination), indent=2))


if __name__ == "__main__":
    main()
