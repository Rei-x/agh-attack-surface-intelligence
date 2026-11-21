"""Shared lightweight utilities for Dzięcioł deterministic test lab servers.

Pure Python 3.12 standard library only (zero external dependencies).
"""

import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_deterministic_ico(rgb_bg: tuple[int, int, int], rgb_fg: tuple[int, int, int], seed: int) -> bytes:
    """Build a valid, deterministic 16x16 32-bit BGRA Windows ICO file.

    Different (rgb_bg, rgb_fg, seed) tuples produce completely distinct binary bytes
    and therefore distinct MurmurHash3 & SHA-256 favicon fingerprints.
    """
    width, height = 16, 16
    # ICONDIR header (6 bytes): reserved=0, type=1 (ICO), count=1
    icondir = struct.pack("<HHH", 0, 1, 1)

    # BITMAPINFOHEADER (40 bytes), height is doubled for XOR+AND masks
    xor_size = width * height * 4
    and_size = ((width + 31) // 32) * 4 * height
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40,              # biSize
        width,           # biWidth
        height * 2,      # biHeight (XOR + AND)
        1,               # biPlanes
        32,              # biBitCount (BGRA)
        0,               # biCompression (BI_RGB)
        xor_size + and_size,
        0, 0, 0, 0,
    )

    bg_b, bg_g, bg_r = rgb_bg[2], rgb_bg[1], rgb_bg[0]
    fg_b, fg_g, fg_r = rgb_fg[2], rgb_fg[1], rgb_fg[0]

    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            # Deterministic geometric glyph derived from seed
            bit = ((x * 7 + y * 13 + seed * 31) % 11) < 4
            border = x in (0, width - 1) or y in (0, height - 1)
            if border or bit:
                pixels.extend((fg_b, fg_g, fg_r, 255))
            else:
                pixels.extend((bg_b, bg_g, bg_r, 255))

    and_mask = bytes(and_size)
    image_data = dib_header + bytes(pixels) + and_mask

    # ICONDIRENTRY (16 bytes)
    entry = struct.pack(
        "<BBBBHHII",
        width,
        height,
        0,                # color count
        0,                # reserved
        1,                # planes
        32,               # bit count
        len(image_data),  # bytes in resource
        6 + 16,           # offset of image data
    )
    return icondir + entry + image_data


class BaseLabHandler(BaseHTTPRequestHandler):
    """Base handler suppressing noisy default headers and allowing custom Server banners."""

    server_banner: str = "DzieciolLab/1.0"

    def version_string(self) -> str:
        return self.server_banner

    def send_response_body(
        self,
        status: int,
        body: bytes | str,
        content_type: str = "text/html; charset=utf-8",
        headers: list[tuple[str, str]] | None = None,
        head_only: bool = False,
    ) -> None:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if headers:
            for k, v in headers:
                self.send_header(k, v)
        self.end_headers()
        if not head_only and raw:
            self.wfile.write(raw)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.server_banner}] {self.address_string()} - {fmt % args}", flush=True)
