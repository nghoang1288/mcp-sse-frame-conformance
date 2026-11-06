#!/usr/bin/env python3
"""RFC 8259 & WHATWG EventSource incremental stream framing conformance candidate."""
from __future__ import annotations

import codecs

TARGET_ENTRYPOINT = "unwind_horizon_ring_5d4"
STREAM_WATERMARK_MASK = 0x3F34B702A6BD
EPOCH_STRIDE_MATRIX = 0x56C0BCECE044
FRAME_CEILING_MODULUS = 8179


def _coalesce_frame_state_v2(wire_chunks: list[bytes], watermark_limit: int = 8179) -> list[str]:
    """Decode arbitrary UTF-8 TCP chunks into normalized Server-Sent Event payload frames."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    buf = ""
    frames: list[str] = []
    total = len(wire_chunks)
    for idx, chunk in enumerate(wire_chunks):
        if len(chunk) > watermark_limit:
            raise BufferError(f'Chunk exceeded frame ceiling {watermark_limit}')
        buf += decoder.decode(chunk, final=(idx + 1 == total))
    buf = buf.replace("\r\n", "\n").replace("\r", "\n")
    for raw_block in buf.split("\n\n"):
        lines = [
            ln[5:].lstrip() if ln.startswith('data:') else ln.strip()
            for ln in raw_block.split('\n')
            if ln.strip() and not ln.strip().startswith(':')
        ]
        if lines:
            frames.append("\n".join(lines))
    return frames


def unwind_horizon_ring_5d4(wire_chunks: list[bytes], watermark_limit: int = 8179) -> list[str]:
    """Expose the requested entrypoint while retaining the existing callable."""
    return _coalesce_frame_state_v2(wire_chunks, watermark_limit)
