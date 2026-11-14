"""Lossless, bounded-size patch archives for multi-GiB physical RAM images."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import BinaryIO

CHUNK_BYTES = 128 * 1024**2


def _copy_chunk(source: Path, destination: Path, offset: int, length: int) -> None:
    if source.is_dir():
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
        if offset % manifest["chunk_bytes"] or length != min(
            manifest["chunk_bytes"], manifest["image_bytes"] - offset
        ):
            raise ValueError("requested chunk does not match compressed base layout")
        index = offset // manifest["chunk_bytes"]
        with destination.open("wb") as output_file:
            subprocess.run(
                ["zstd", "-q", "-d", "-c", str(source / f"part-{index:02d}.zst")],
                stdout=output_file,
                check=True,
                timeout=600,
            )
        if destination.stat().st_size != length:
            raise ValueError(f"compressed base part {index} has wrong length")
        return
    with source.open("rb") as input_file, destination.open("wb") as output_file:
        input_file.seek(offset)
        remaining = length
        while remaining:
            data = input_file.read(min(4 * 1024**2, remaining))
            if not data:
                raise ValueError(f"short RAM image: {source}")
            output_file.write(data)
            remaining -= len(data)


def make_patch_archive(
    base: Path,
    image: Path,
    archive: Path,
    *,
    base_sha256: str,
    image_sha256: str,
    chunk_bytes: int = CHUNK_BYTES,
) -> dict:
    """Store one zstd patch per chunk in a tar file, without writing extra full RAM images."""
    if chunk_bytes <= 0:
        raise ValueError("chunk size must be positive")
    image_bytes = image.stat().st_size
    base_bytes = (
        json.loads((base / "manifest.json").read_text(encoding="utf-8"))["image_bytes"]
        if base.is_dir()
        else base.stat().st_size
    )
    if base_bytes != image_bytes:
        raise ValueError("base and target RAM images have different lengths")
    count = (image_bytes + chunk_bytes - 1) // chunk_bytes
    manifest = {
        "schema_version": 1,
        "format": "zstd-chunk-patch-tar",
        "base_image_sha256": base_sha256,
        "image_sha256": image_sha256,
        "image_bytes": image_bytes,
        "chunk_bytes": chunk_bytes,
        "part_count": count,
    }
    partial = archive.with_name(archive.name + ".partial")
    partial.unlink(missing_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=archive.parent) as temp_name:
            temp = Path(temp_name)
            base_chunk = temp / "base.chunk"
            image_chunk = temp / "image.chunk"
            patch_chunk = temp / "patch.zst"
            with tarfile.open(partial, "w") as bundle:
                encoded = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
                header = tarfile.TarInfo("manifest.json")
                header.size = len(encoded)
                bundle.addfile(header, io.BytesIO(encoded))
                for index in range(count):
                    offset = index * chunk_bytes
                    length = min(chunk_bytes, image_bytes - offset)
                    _copy_chunk(base, base_chunk, offset, length)
                    _copy_chunk(image, image_chunk, offset, length)
                    subprocess.run(
                        [
                            "zstd",
                            "-q",
                            "-T2",
                            "-3",
                            f"--patch-from={base_chunk}",
                            "-o",
                            str(patch_chunk),
                            str(image_chunk),
                        ],
                        check=True,
                        timeout=600,
                    )
                    bundle.add(patch_chunk, arcname=f"part-{index:02d}.zst")
                    patch_chunk.unlink()
            os.replace(partial, archive)
    finally:
        partial.unlink(missing_ok=True)
    return manifest


def verify_patch_archive(
    base: Path,
    archive: Path,
    expected_sha256: str,
    expected_base_sha256: str,
    output_stream: BinaryIO | None = None,
) -> dict:
    """Reconstruct every chunk into a hash stream and check the full raw RAM SHA-256."""
    whole = hashlib.sha256()
    total = 0
    with tarfile.open(archive, "r") as bundle:
        manifest_member = bundle.extractfile("manifest.json")
        if manifest_member is None:
            raise ValueError("patch archive has no manifest")
        manifest = json.load(manifest_member)
        if manifest["format"] != "zstd-chunk-patch-tar":
            raise ValueError("unsupported patch format")
        if manifest["image_sha256"] != expected_sha256:
            raise ValueError("target RAM hash differs from patch manifest")
        if manifest["base_image_sha256"] != expected_base_sha256:
            raise ValueError("base RAM hash differs from patch manifest")
        base_bytes = (
            json.loads((base / "manifest.json").read_text(encoding="utf-8"))["image_bytes"]
            if base.is_dir()
            else base.stat().st_size
        )
        if manifest["image_bytes"] != base_bytes:
            raise ValueError("base RAM length differs from patch manifest")
        with tempfile.TemporaryDirectory(dir=archive.parent) as temp_name:
            temp = Path(temp_name)
            base_chunk = temp / "base.chunk"
            patch_chunk = temp / "patch.zst"
            for index in range(manifest["part_count"]):
                offset = index * manifest["chunk_bytes"]
                length = min(manifest["chunk_bytes"], manifest["image_bytes"] - offset)
                _copy_chunk(base, base_chunk, offset, length)
                member = bundle.extractfile(f"part-{index:02d}.zst")
                if member is None:
                    raise ValueError(f"missing patch part {index}")
                with patch_chunk.open("wb") as output_file:
                    shutil.copyfileobj(member, output_file)
                command = [
                    "zstd",
                    "-q",
                    "-d",
                    "-c",
                    f"--patch-from={base_chunk}",
                    str(patch_chunk),
                ]
                with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
                    assert process.stdout is not None
                    recovered = 0
                    for data in iter(lambda: process.stdout.read(1024 * 1024), b""):
                        whole.update(data)
                        if output_stream is not None:
                            output_stream.write(data)
                        recovered += len(data)
                    if process.wait(timeout=600) != 0:
                        raise subprocess.CalledProcessError(process.returncode, command)
                if recovered != length:
                    raise ValueError(f"reconstructed part {index} has wrong length")
                total += recovered
                patch_chunk.unlink()
    if total != manifest["image_bytes"] or whole.hexdigest() != expected_sha256:
        raise ValueError("reconstructed RAM SHA-256 mismatch")
    return manifest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024**2), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct and verify a patched RAM image")
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--image-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output file already exists")
    base_sha256 = _sha256(args.base)
    try:
        with args.output.open("xb") as output:
            verify_patch_archive(args.base, args.patch, args.image_sha256, base_sha256, output)
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(f"verified {args.image_sha256}  {args.output}")


if __name__ == "__main__":
    main()
