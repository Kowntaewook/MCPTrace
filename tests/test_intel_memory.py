"""Exercise sparse scanning with real x86-64 page tables and Volatility layers."""

import struct

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.intel import Intel32e
from volatility3.framework.layers.physical import BufferDataLayer

from mcptrace.core import ScanStats, scan_chunks
from mcptrace.memory import readable_chunks

PAGE = 4096
HIGH = 1 << 41


def intel_layer(virtual_pages=None):
    # Virtual pages 0 and 1 are neighbors but physical pages 5 and 7 are not.
    # Page 2 is absent; page 3 maps to physical page 6. Repeat at 2 TiB to
    # exercise absent PML4/PDPT/PD branches without allocating a large buffer.
    data = bytearray(8 * PAGE)
    for address, value in [
        (0x1000, 0x2003),
        (0x1020, 0x2003),
        (0x2000, 0x3003),
        (0x3000, 0x4003),
        (0x4000, 0x5003),
        (0x4008, 0x7003),
        (0x4018, 0x6003),
    ]:
        struct.pack_into("<Q", data, address, value)
    for virtual_page, physical_page in [(0, 5), (1, 7), (3, 6)]:
        page = (virtual_pages or {}).get(virtual_page, bytes([65 + virtual_page]) * PAGE)
        assert len(page) == PAGE
        data[physical_page * PAGE : (physical_page + 1) * PAGE] = page
    context = contexts.Context()
    context.layers.add_layer(BufferDataLayer(context, "physical", "physical", bytes(data)))
    context.config["virtual.memory_layer"] = "physical"
    context.config["virtual.page_map_offset"] = 0x1000
    layer = Intel32e(context, "virtual", "virtual")
    context.layers.add_layer(layer)
    return layer


def test_two_tib_gap_does_not_probe_every_page(monkeypatch):
    layer = intel_layer()
    original_read = layer.read
    calls = []

    def read(offset, length, pad=False):
        calls.append((offset, length))
        assert len(calls) <= 4096, "Missing branches must not trigger per-page reads"
        assert not pad
        return original_read(offset, length, pad=pad)

    monkeypatch.setattr(layer, "read", read)
    stats = ScanStats()
    size = HIGH + 4 * PAGE
    chunks = list(readable_chunks(layer, 0, size, stats, exceptions.InvalidAddressException))
    assert [(address, len(data)) for address, data in chunks] == [
        (0, 2 * PAGE),
        (3 * PAGE, PAGE),
        (HIGH, 2 * PAGE),
        (HIGH + 3 * PAGE, PAGE),
    ]
    assert chunks[0][1] == b"A" * PAGE + b"B" * PAGE
    assert stats.bytes_read == 6 * PAGE
    assert stats.unreadable_bytes == size - 6 * PAGE


def test_sparse_reads_preserve_clipped_byte_budget():
    layer = intel_layer()
    stats = ScanStats()
    chunks = list(readable_chunks(layer, PAGE - 3, 12, stats, exceptions.InvalidAddressException))
    assert chunks == [(PAGE - 3, b"AAA" + b"B" * 9)]
    assert stats.bytes_read == 12 and stats.unreadable_bytes == 0


def test_missing_branch_skip_is_clipped_to_requested_range():
    layer = intel_layer()
    stats = ScanStats()
    chunks = list(
        readable_chunks(layer, 2**30 + 7, 9999, stats, exceptions.InvalidAddressException)
    )
    assert chunks == []
    assert stats.bytes_read == 0 and stats.unreadable_bytes == 9999


def test_sparse_reads_do_not_join_json_across_absent_page():
    intact = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    broken = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    p0, p1, p3 = bytearray(PAGE), bytearray(PAGE), bytearray(PAGE)
    p0[-12:] = intact[:12]
    p1[: len(intact) - 12] = intact[12:]
    p1[-20:] = broken[:20]
    p3[: len(broken) - 20] = broken[20:]
    layer = intel_layer({0: p0, 1: p1, 3: p3})
    stats = ScanStats()
    records = list(
        scan_chunks(readable_chunks(layer, 0, 4 * PAGE, stats, exceptions.InvalidAddressException))
    )
    assert [(r.address, r.request_id) for r in records] == [(PAGE - 12, 1)]
    assert stats.bytes_read == 3 * PAGE and stats.unreadable_bytes == PAGE


def test_large_page_with_partial_backing_keeps_readable_bytes():
    # A present 2 MiB PDE maps physical address 0, but only 8 physical pages
    # were captured. Ignoring errors from mapping the entire range would drop
    # its readable prefix; ordinary physical errors must retain page fallback.
    data = bytearray(8 * PAGE)
    for address, value in [(0x1000, 0x2003), (0x2000, 0x3003), (0x3000, 0x83)]:
        struct.pack_into("<Q", data, address, value)
    context = contexts.Context()
    context.layers.add_layer(BufferDataLayer(context, "physical", "physical", bytes(data)))
    context.config["virtual.memory_layer"] = "physical"
    context.config["virtual.page_map_offset"] = 0x1000
    layer = Intel32e(context, "virtual", "virtual")
    context.layers.add_layer(layer)
    stats = ScanStats()
    chunks = list(readable_chunks(layer, 0, 2**21, stats, exceptions.InvalidAddressException))
    assert chunks == [(0, bytes(data))]
    assert stats.bytes_read == len(data)
    assert stats.unreadable_bytes == 2**21 - len(data)
