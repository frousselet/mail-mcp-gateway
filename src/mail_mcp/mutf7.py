"""Modified UTF-7, the encoding IMAP mailbox names use (RFC 3501, 5.1.3).

Folder names such as ``Éléments envoyés`` travel over IMAP as
``&AMk-l&AOk-ments envoy&AOk-s``. Python ships a ``utf-7`` codec, but IMAP's
variant differs (``&`` instead of ``+``, ``,`` instead of ``/``, no padding),
so the conversion is done here.
"""

from __future__ import annotations

import base64


def encode(value: str) -> str:
    """Encode a folder name to modified UTF-7."""
    out: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        encoded = base64.b64encode("".join(buffer).encode("utf-16-be")).decode("ascii")
        out.append("&" + encoded.rstrip("=").replace("/", ",") + "-")
        buffer.clear()

    for char in value:
        if char == "&":
            flush()
            out.append("&-")
        elif 0x20 <= ord(char) <= 0x7E:
            flush()
            out.append(char)
        else:
            buffer.append(char)
    flush()
    return "".join(out)


def decode(value: str | bytes) -> str:
    """Decode a modified UTF-7 folder name (a plain name passes through)."""
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="replace")
    out: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char != "&":
            out.append(char)
            index += 1
            continue
        end = value.find("-", index + 1)
        if end == -1:  # unterminated shift: keep the rest verbatim
            out.append(value[index:])
            break
        chunk = value[index + 1 : end]
        if chunk == "":
            out.append("&")
        else:
            padded = chunk.replace(",", "/")
            padded += "=" * (-len(padded) % 4)
            try:
                out.append(base64.b64decode(padded).decode("utf-16-be"))
            except (ValueError, UnicodeDecodeError):
                out.append(value[index : end + 1])
        index = end + 1
    return "".join(out)
