"""Сборка .ico из готовых PNG-размеров: заголовок ICONDIR и записи с PNG-телом."""

import struct
import sys
from pathlib import Path

SIZES = (16, 32, 48, 64, 256)


def build(directory: Path, target: Path) -> int:
    payloads = []
    for size in SIZES:
        path = directory / f"{size}.png"
        if not path.is_file():
            raise SystemExit(f"Нет файла {path}")
        payloads.append((size, path.read_bytes()))
    header = struct.pack("<HHH", 0, 1, len(payloads))
    entry_size = 16
    offset = len(header) + entry_size * len(payloads)
    entries, body = b"", b""
    for size, data in payloads:
        width = 0 if size >= 256 else size
        height = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", width, height, 0, 0, 1, 32, len(data), offset)
        body += data
        offset += len(data)
    target.write_bytes(header + entries + body)
    return len(header + entries + body)


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    target = Path(sys.argv[2])
    print(f"{target}: {build(directory, target)} байт")
