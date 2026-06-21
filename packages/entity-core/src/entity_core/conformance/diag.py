"""CBOR diagnostic notation parser (RFC 8949 §8 subset).

The v1 corpus uses a constrained subset:

- Top-level: any value (the corpus root is an array of vector maps).
- Maps with text-string or byte-string keys; map values are any supported type.
- Text strings ``"..."`` with ``\\"``, ``\\\\``, ``\\n``, ``\\t``, ``\\r`` escapes.
- Byte strings ``h'<hex>'`` (no internal whitespace; hex case-insensitive).
- Integers (optional sign, decimal digits).
- Floats (decimal with point or exponent; keywords ``NaN``, ``Infinity``,
  ``-Infinity``).
- Booleans (``true``, ``false``) and ``null``.

Comments:

- Whole-line block-toggle: a line whose trimmed content is exactly ``/``
  toggles block mode; everything inside the block is dropped.
- Whole-line ``/.../`` comments are dropped.
- In-band comments (mid-value) are NOT supported (the corpus doesn't use them).

Output type mapping:

- text string → ``str``
- byte string → ``bytes``
- integer    → ``int``
- float      → ``float``
- bool       → ``bool``
- null       → ``None``
- array      → ``list``
- map        → ``dict``
"""

from __future__ import annotations

import math
from typing import Any


def strip_diag_comments(src: str) -> str:
    """Remove the comment forms used by the v1 corpus.

    Newlines are preserved so error line numbers stay stable.
    """
    out: list[str] = []
    in_block = False
    for line in src.split("\n"):
        trimmed = line.strip()
        if in_block:
            if trimmed == "/":
                in_block = False
            out.append("")
            continue
        if trimmed == "/":
            in_block = True
            out.append("")
            continue
        if len(trimmed) >= 2 and trimmed.startswith("/") and trimmed.endswith("/"):
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def parse_diag(src: str) -> Any:
    """Parse a CBOR diagnostic-notation string into a Python value tree."""
    stripped = strip_diag_comments(src)
    p = _Parser(stripped)
    p._skip_ws()
    val = p._parse_value()
    p._skip_ws()
    if p.pos != len(p.src):
        raise p._error("trailing content after top-level value")
    return val


class _Parser:
    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0

    def _error(self, msg: str) -> ValueError:
        line, col = 1, 1
        for ch in self.src[: self.pos]:
            if ch == "\n":
                line += 1
                col = 1
            else:
                col += 1
        return ValueError(f"diag parse error at line {line} col {col}: {msg}")

    def _skip_ws(self) -> None:
        while self.pos < len(self.src) and self.src[self.pos] in " \t\r\n":
            self.pos += 1

    def _peek(self) -> str:
        return self.src[self.pos] if self.pos < len(self.src) else ""

    def _eat(self, ch: str) -> None:
        if self._peek() != ch:
            raise self._error(f"expected {ch!r}, got {self._peek()!r}")
        self.pos += 1

    def _parse_value(self) -> Any:
        self._skip_ws()
        ch = self._peek()
        if ch == "":
            raise self._error("unexpected EOF")
        if ch == "{":
            return self._parse_map()
        if ch == "[":
            return self._parse_array()
        if ch == '"':
            return self._parse_text()
        if ch == "h" and self.src[self.pos : self.pos + 2] == "h'":
            return self._parse_bstr()
        if ch.isdigit() or ch == "-" or ch == "+":
            return self._parse_number()
        # keywords: true, false, null, NaN, Infinity, -Infinity (the leading
        # '-' for -Infinity is handled in _parse_number).
        return self._parse_keyword()

    def _parse_map(self) -> dict:
        self._eat("{")
        result: dict = {}
        self._skip_ws()
        if self._peek() == "}":
            self.pos += 1
            return result
        while True:
            self._skip_ws()
            key = self._parse_value()
            self._skip_ws()
            self._eat(":")
            self._skip_ws()
            val = self._parse_value()
            result[key] = val
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "}":
                self.pos += 1
                return result
            raise self._error(f"expected ',' or '}}' in map, got {ch!r}")

    def _parse_array(self) -> list:
        self._eat("[")
        result: list = []
        self._skip_ws()
        if self._peek() == "]":
            self.pos += 1
            return result
        while True:
            self._skip_ws()
            result.append(self._parse_value())
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "]":
                self.pos += 1
                return result
            raise self._error(f"expected ',' or ']' in array, got {ch!r}")

    def _parse_text(self) -> str:
        self._eat('"')
        out: list[str] = []
        while self.pos < len(self.src):
            ch = self.src[self.pos]
            if ch == '"':
                self.pos += 1
                return "".join(out)
            if ch == "\\":
                self.pos += 1
                if self.pos >= len(self.src):
                    raise self._error("unterminated string escape")
                esc = self.src[self.pos]
                self.pos += 1
                if esc == '"':
                    out.append('"')
                elif esc == "\\":
                    out.append("\\")
                elif esc == "n":
                    out.append("\n")
                elif esc == "t":
                    out.append("\t")
                elif esc == "r":
                    out.append("\r")
                else:
                    raise self._error(f"unknown string escape \\{esc}")
                continue
            out.append(ch)
            self.pos += 1
        raise self._error("unterminated text string")

    def _parse_bstr(self) -> bytes:
        # consume "h'"
        self.pos += 2
        chars: list[str] = []
        while self.pos < len(self.src) and self.src[self.pos] != "'":
            ch = self.src[self.pos]
            if ch not in " \t\r\n":
                chars.append(ch)
            self.pos += 1
        if self.pos >= len(self.src):
            raise self._error("unterminated byte-string literal")
        self.pos += 1  # consume closing '
        hex_str = "".join(chars)
        if len(hex_str) % 2 != 0:
            raise self._error("odd-length hex in byte-string literal")
        try:
            return bytes.fromhex(hex_str)
        except ValueError as e:
            raise self._error(f"invalid hex in byte-string literal: {e}") from None

    def _parse_number(self) -> int | float:
        # Special-case "-Infinity"
        if self.src[self.pos : self.pos + 9] == "-Infinity":
            self.pos += 9
            return -math.inf
        start = self.pos
        if self._peek() in "+-":
            self.pos += 1
        while self.pos < len(self.src) and self.src[self.pos].isdigit():
            self.pos += 1
        is_float = False
        if self._peek() == ".":
            is_float = True
            self.pos += 1
            while self.pos < len(self.src) and self.src[self.pos].isdigit():
                self.pos += 1
        if self._peek() in "eE":
            is_float = True
            self.pos += 1
            if self._peek() in "+-":
                self.pos += 1
            while self.pos < len(self.src) and self.src[self.pos].isdigit():
                self.pos += 1
        token = self.src[start : self.pos]
        if token in ("", "-", "+"):
            raise self._error(f"invalid number token {token!r}")
        if is_float:
            return float(token)
        return int(token)

    def _parse_keyword(self) -> Any:
        start = self.pos
        while self.pos < len(self.src) and (
            self.src[self.pos].isalpha() or self.src[self.pos] == "_"
        ):
            self.pos += 1
        word = self.src[start : self.pos]
        if word == "true":
            return True
        if word == "false":
            return False
        if word == "null":
            return None
        if word == "NaN":
            return math.nan
        if word == "Infinity":
            return math.inf
        raise self._error(f"unknown keyword {word!r}")
