"""Read a Volatility layer without filling missing evidence with zero bytes."""

from collections.abc import Iterator

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
                try:
                    part = layer.read(page, page_amount, pad=False)
                    if len(part) != page_amount:
                        raise invalid_address(layer.name, page, "Short read")
                except invalid_address:
                    if run:
                        yield run_start, bytes(run)
                        run.clear()
                    stats.unreadable_bytes += page_amount
                else:
                    if not run:
                        run_start = page
                    run.extend(part)
                    stats.bytes_read += len(part)
                page += page_amount
            if run:
                yield run_start, bytes(run)
        else:
            stats.bytes_read += len(data)
            yield offset, data
        offset += amount
