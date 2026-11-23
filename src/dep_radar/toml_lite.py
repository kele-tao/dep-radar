"""A small, dependency-free TOML reader for Python 3.10.

`tomllib` only exists from Python 3.11, and dep-radar supports 3.10, so this
module implements the subset of TOML 1.0 that manifests actually use:

* tables `[a.b]`, arrays of tables `[[a]]`, dotted keys, quoted keys
* basic strings with escapes, literal strings, both multi-line forms
* integers (decimal, hex, octal, binary, underscores), floats, booleans
* arrays (multi-line, trailing commas) and inline tables
* comments and blank lines

Anything outside that subset raises :class:`TomlError` with the line number
instead of guessing, which is what keeps the "honest error" promise: the caller
turns it into a message that names the file and the construct.

The public surface is one function, :func:`loads`, deliberately compatible with
`tomllib.loads` for the values above.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["TomlError", "loads"]

_BARE_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_ESCAPES = {
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
    "e": "\x1b",
}
# Dates and times are kept as their source text: nothing dep-radar reads from a
# manifest is a timestamp, but poetry.lock can contain them and dropping the file
# over an unrelated value type would be hostile.
_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?"
    r"(?:[Zz]|[+-]\d{2}:\d{2})?$"
    r"|^\d{2}:\d{2}:\d{2}(?:\.\d+)?$"
)


class TomlError(ValueError):
    """A TOML syntax error with the 1-based line number that caused it."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__("line " + str(line) + ": " + message)
        self.line = line


class _Parser:
    """Recursive-descent parser over a normalised (LF-only) TOML document."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.line = 1

    # -- low level helpers ------------------------------------------------
    def error(self, message: str) -> TomlError:
        return TomlError(message, self.line)

    def peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < len(self.text) else ""

    def advance(self, count: int = 1) -> str:
        chunk = self.text[self.pos : self.pos + count]
        self.line += chunk.count("\n")
        self.pos += len(chunk)
        return chunk

    def skip_ws(self) -> None:
        while self.peek() in (" ", "\t"):
            self.advance()

    def skip_comment(self) -> None:
        if self.peek() != "#":
            return
        while self.pos < len(self.text) and self.peek() != "\n":
            self.advance()

    def skip_blank(self) -> None:
        """Skip whitespace, newlines and comments between statements."""
        while True:
            self.skip_ws()
            self.skip_comment()
            if self.peek() == "\n":
                self.advance()
                continue
            return

    # -- document structure -----------------------------------------------
    def parse(self) -> dict[str, Any]:
        root: dict[str, Any] = {}
        current = root
        while True:
            self.skip_blank()
            if self.pos >= len(self.text):
                return root
            if self.peek() == "[":
                current = self.parse_table_header(root)
            else:
                self.parse_assignment(current, end_of_line=True)

    def parse_table_header(self, root: dict[str, Any]) -> dict[str, Any]:
        self.advance()  # '['
        is_array = False
        if self.peek() == "[":
            self.advance()
            is_array = True
        self.skip_ws()
        keys = self.parse_key_path()
        self.skip_ws()
        if self.peek() != "]":
            raise self.error("expected ']' to close the table header")
        self.advance()
        if is_array:
            if self.peek() != "]":
                raise self.error("expected ']]' to close the array-of-tables header")
            self.advance()
        self.skip_ws()
        self.skip_comment()
        node = self.descend(root, keys[:-1])
        last = keys[-1]
        existing = node.get(last)
        if is_array:
            if existing is None:
                existing = []
                node[last] = existing
            if not isinstance(existing, list):
                raise self.error("key " + repr(last) + " is already defined as a table")
            child: dict[str, Any] = {}
            existing.append(child)
            return child
        if existing is None:
            child = {}
            node[last] = child
        elif isinstance(existing, dict):
            child = existing  # re-opened table, allowed by TOML for super-tables
        else:
            raise self.error("key " + repr(last) + " is already defined as a value")
        return child

    def descend(self, table: dict[str, Any], keys: list[str]) -> dict[str, Any]:
        node = table
        for key in keys:
            child = node.get(key)
            if child is None:
                child = {}
                node[key] = child
            if isinstance(child, list):
                if not child:
                    raise self.error("key " + repr(key) + " is an empty array of tables")
                child = child[-1]
            if not isinstance(child, dict):
                raise self.error("key " + repr(key) + " is not a table")
            node = child
        return node

    def parse_assignment(self, table: dict[str, Any], end_of_line: bool) -> None:
        keys = self.parse_key_path()
        self.skip_ws()
        if self.peek() != "=":
            raise self.error("expected '=' after key " + repr(".".join(keys)))
        self.advance()
        self.skip_ws()
        value = self.parse_value()
        node = self.descend(table, keys[:-1])
        last = keys[-1]
        if last in node:
            raise self.error("duplicate key " + repr(last))
        node[last] = value
        if not end_of_line:
            return
        self.skip_ws()
        self.skip_comment()
        if self.pos < len(self.text) and self.peek() != "\n":
            raise self.error("unexpected characters after the value")

    def parse_key_path(self) -> list[str]:
        keys = [self.parse_key()]
        while True:
            saved_pos, saved_line = self.pos, self.line
            self.skip_ws()
            if self.peek() != ".":
                self.pos, self.line = saved_pos, saved_line
                return keys
            self.advance()
            self.skip_ws()
            keys.append(self.parse_key())

    def parse_key(self) -> str:
        char = self.peek()
        if char == '"':
            return self.parse_basic_string()
        if char == "'":
            return self.parse_literal_string()
        start = self.pos
        while self.peek() in _BARE_KEY_CHARS:
            self.advance()
        if self.pos == start:
            raise self.error("expected a key name")
        return self.text[start : self.pos]

    # -- values ------------------------------------------------------------
    def parse_value(self) -> Any:
        char = self.peek()
        if char == '"':
            if self.text.startswith('"""', self.pos):
                return self.parse_multiline_basic()
            return self.parse_basic_string()
        if char == "'":
            if self.text.startswith("'''", self.pos):
                return self.parse_multiline_literal()
            return self.parse_literal_string()
        if char == "[":
            return self.parse_array()
        if char == "{":
            return self.parse_inline_table()
        return self.parse_scalar()

    def parse_scalar(self) -> Any:
        start = self.pos
        while self.peek() not in ("", "\n", " ", "\t", ",", "]", "}", "#"):
            self.advance()
        token = self.text[start : self.pos]
        if token == "true":
            return True
        if token == "false":
            return False
        if not token:
            raise self.error("expected a value")
        cleaned = token.replace("_", "")
        try:
            if cleaned.lower().startswith(("0x", "0o", "0b")):
                return int(cleaned, 0)
            if _DATETIME_RE.match(token):
                return token
            if any(character in cleaned for character in ".eE"):
                return float(cleaned)
            return int(cleaned, 10)
        except ValueError:
            raise self.error("unsupported value " + repr(token)) from None

    def parse_array(self) -> list[Any]:
        self.advance()  # '['
        items: list[Any] = []
        while True:
            self.skip_blank()
            if self.peek() == "]":
                self.advance()
                return items
            items.append(self.parse_value())
            self.skip_blank()
            if self.peek() == ",":
                self.advance()
                continue
            if self.peek() == "]":
                self.advance()
                return items
            raise self.error("expected ',' or ']' inside an array")

    def parse_inline_table(self) -> dict[str, Any]:
        self.advance()  # '{'
        table: dict[str, Any] = {}
        while True:
            self.skip_ws()
            if self.peek() == "}":
                self.advance()
                return table
            self.parse_assignment(table, end_of_line=False)
            self.skip_ws()
            if self.peek() == ",":
                self.advance()
                continue
            if self.peek() == "}":
                self.advance()
                return table
            raise self.error("expected ',' or '}' inside an inline table")

    def parse_basic_string(self) -> str:
        self.advance()  # opening quote
        out: list[str] = []
        while True:
            char = self.peek()
            if not char:
                raise self.error("unterminated string")
            if char == '"':
                self.advance()
                return "".join(out)
            if char == "\n":
                raise self.error("newline inside a single-line string")
            if char == "\\":
                out.append(self.parse_escape())
                continue
            out.append(self.advance())

    def parse_escape(self) -> str:
        self.advance()  # backslash
        char = self.peek()
        if char in _ESCAPES:
            self.advance()
            return _ESCAPES[char]
        if char in ("u", "U"):
            self.advance()
            width = 4 if char == "u" else 8
            digits = self.advance(width)
            if len(digits) != width:
                raise self.error("truncated unicode escape")
            try:
                return chr(int(digits, 16))
            except ValueError:
                raise self.error("invalid unicode escape " + repr(digits)) from None
        raise self.error("invalid escape sequence \\" + char)

    def parse_multiline_basic(self) -> str:
        self.advance(3)
        if self.peek() == "\n":
            self.advance()
        out: list[str] = []
        while True:
            if not self.peek():
                raise self.error("unterminated multi-line string")
            if self.text.startswith('"""', self.pos):
                self.advance(3)
                # Up to two extra quotes directly before the delimiter are content.
                extra = 0
                while self.peek() == '"' and extra < 2:
                    out.append(self.advance())
                    extra += 1
                return "".join(out)
            if self.peek() == "\\":
                if self.peek(1) == "\n":
                    self.advance(2)
                    while self.peek() in (" ", "\t", "\n"):
                        self.advance()
                    continue
                out.append(self.parse_escape())
                continue
            out.append(self.advance())

    def parse_literal_string(self) -> str:
        self.advance()  # opening quote
        start = self.pos
        while True:
            char = self.peek()
            if not char or char == "\n":
                raise self.error("unterminated literal string")
            if char == "'":
                value = self.text[start : self.pos]
                self.advance()
                return value
            self.advance()

    def parse_multiline_literal(self) -> str:
        self.advance(3)
        if self.peek() == "\n":
            self.advance()
        start = self.pos
        while True:
            if not self.peek():
                raise self.error("unterminated multi-line literal string")
            if self.text.startswith("'''", self.pos):
                value = self.text[start : self.pos]
                self.advance(3)
                extra = 0
                while self.peek() == "'" and extra < 2:
                    value += self.advance()
                    extra += 1
                return value
            self.advance()


def loads(text: str) -> dict[str, Any]:
    """Parse a TOML document into nested dicts, lists and scalars.

    Raises:
        TomlError: the document uses syntax outside the supported subset.
    """
    if not isinstance(text, str):
        raise TypeError("TOML input must be a str, not " + type(text).__name__)
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    return _Parser(normalised).parse()
