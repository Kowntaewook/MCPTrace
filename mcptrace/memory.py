"""Read a Volatility layer without filling missing evidence with zero bytes."""

from collections.abc import Iterator

from volatility3.framework import exceptions
from volatility3.framework.layers.intel import Intel

from mcptrace.core import ScanStats


def readable_chunks(
    layer,
    start: int,
    size: int,
    stats: ScanStats,
    invalid_address: type[Exception],
    chunk_bytes: int = 1024 * 1024,
) -> Iterator[tuple[int, bytes]]:
    if size < 0 or start < 0 or chunk_bytes < 4096:
        raise ValueError("Invalid virtual range or read chunk size")
    end = start + size
    offset = start
    while offset < end:
        amount = min(chunk_bytes, end - offset)
        next_offset = offset + amount
        try:
            data = layer.read(offset, amount, pad=False)
            if len(data) != amount:
                raise invalid_address(layer.name, offset, "Short read")
        except invalid_address:
            # One absent page must not discard other resident pages in this chunk.
            page = offset
            run_start = page
            run = bytearray()
            while page < offset + amount:
                page_amount = min(4096 - page % 4096, offset + amount - page)
                advance = page_amount
                try:
                    part = layer.read(page, page_amount, pad=False)
                    if len(part) != page_amount:
                        raise invalid_address(layer.name, page, "Short read")
                except invalid_address as exc:
                    if run:
                        yield run_start, bytes(run)
                        run.clear()
                    # Intel faults identify the size of an absent page-table
                    # branch. Skip that branch, possibly beyond this read chunk,
                    # but never beyond the caller's VAD/VMA range or byte budget.
                    # Do not apply this to physical backing failures: part of a
                    # large mapped page can still be readable in a truncated dump.
                    if (
                        isinstance(layer, Intel)
                        and isinstance(exc, exceptions.PagedInvalidAddressException)
                        and exc.layer_name == layer.name
                        and page <= exc.invalid_address < page + page_amount
                        and 12 <= exc.invalid_bits <= 48
                    ):
                        block_size = 1 << exc.invalid_bits
                        advance = min(end - page, block_size - page % block_size)
                    stats.unreadable_bytes += advance
                else:
                    if not run:
                        run_start = page
                    run.extend(part)
                    stats.bytes_read += len(part)
                page += advance
            if run:
                yield run_start, bytes(run)
            next_offset = max(next_offset, page)
        else:
            stats.bytes_read += len(data)
            yield offset, data
        offset = next_offset
