"""Check that chunked RAM patches reconstruct the exact source bytes."""

import hashlib
import json
import shutil
import subprocess

import pytest

from validation.linux_x64_http_ram.archive import make_patch_archive, verify_patch_archive


@pytest.mark.skipif(shutil.which("zstd") is None, reason="zstd is not installed")
def test_chunk_patch_reconstructs_full_image(tmp_path):
    base = tmp_path / "base.elf"
    image = tmp_path / "image.elf"
    archive = tmp_path / "image.patch.tar"
    original = bytearray((b"A" * 4096 + b"B" * 4096) * 3)
    changed = original.copy()
    changed[20:30] = b"newmarker!"
    changed[9000:9010] = b"othercase!"
    base.write_bytes(original)
    image.write_bytes(changed)
    base_hash = hashlib.sha256(original).hexdigest()
    image_hash = hashlib.sha256(changed).hexdigest()

    manifest = make_patch_archive(
        base, image, archive, base_sha256=base_hash, image_sha256=image_hash, chunk_bytes=8192
    )

    assert manifest["part_count"] == 3
    assert verify_patch_archive(base, archive, image_hash, base_hash) == manifest
    reconstructed = tmp_path / "reconstructed.elf"
    with reconstructed.open("wb") as output:
        assert verify_patch_archive(base, archive, image_hash, base_hash, output) == manifest
    assert reconstructed.read_bytes() == changed
    with pytest.raises(ValueError, match="target RAM hash"):
        verify_patch_archive(base, archive, "0" * 64, base_hash)

    compressed_base = tmp_path / "base-chunks"
    compressed_base.mkdir()
    for index in range(3):
        chunk = tmp_path / f"base-{index}.bin"
        chunk.write_bytes(original[index * 8192 : (index + 1) * 8192])
        subprocess.run(
            ["zstd", "-q", "-o", str(compressed_base / f"part-{index:02d}.zst"), str(chunk)],
            check=True,
        )
    (compressed_base / "manifest.json").write_text(
        json.dumps({"chunk_bytes": 8192, "image_bytes": len(original), "image_sha256": base_hash})
    )
    assert verify_patch_archive(compressed_base, archive, image_hash, base_hash) == manifest
    compressed_archive = tmp_path / "compressed-base.patch.tar"
    assert (
        make_patch_archive(
            compressed_base,
            image,
            compressed_archive,
            base_sha256=base_hash,
            image_sha256=image_hash,
            chunk_bytes=8192,
        )
        == manifest
    )
