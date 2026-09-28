"""Bounded, inspection-only decoding for encoded user supplied text."""
from __future__ import annotations

import base64
import binascii
import logging
import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote

logger = logging.getLogger("vinbank.security")

MAX_INPUT_BYTES = 32_768
MAX_DECODED_BYTES = 8_192
MAX_DEPTH = 2
MAX_CANDIDATES = 8

_HEX_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{7,}(?![A-Za-z0-9])")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/_=-])")
_UNICODE_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2}))")
_HEX_HINT = re.compile(r"\b(?:base16|hexadecimal|hex)\b", re.I)
_B64_HINT = re.compile(r"\bbase\s*64\b", re.I)


@dataclass(frozen=True)
class Candidate:
    transform: str
    text: str
    depth: int


@dataclass(frozen=True)
class Inspection:
    candidates: tuple[Candidate, ...]
    limit_error: str | None = None


def _printable_text(value: bytes) -> str | None:
    if len(value) > MAX_DECODED_BYTES:
        return None
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not text or sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) < 0.85:
        return None
    return text


def _decode_unicode(value: str) -> str | None:
    if not _UNICODE_ESCAPE.search(value):
        return None

    def replace(match: re.Match[str]) -> str:
        digits = next(group for group in match.groups() if group is not None)
        return chr(int(digits, 16))

    try:
        decoded = _UNICODE_ESCAPE.sub(replace, value)
        decoded.encode("utf-8", errors="strict")
        return decoded if decoded != value else None
    except (UnicodeEncodeError, ValueError):
        return None


def _decode_candidates(value: str) -> list[tuple[str, str]]:
    decoded: list[tuple[str, str]] = []

    if re.search(r"%(?:[0-9a-fA-F]{2})", value):
        try:
            result = unquote(value, encoding="utf-8", errors="strict")
            if result != value:
                decoded.append(("url_percent", result))
        except UnicodeDecodeError:
            logger.info("[CANON] transform=url_percent detected=true decode_success=false")

    unicode_text = _decode_unicode(value)
    if unicode_text is not None:
        decoded.append(("unicode_escape", unicode_text))

    if _HEX_HINT.search(value):
        tokens = list(_HEX_TOKEN.finditer(value))
        if tokens:
            logger.info("[CANON] transform=base16 detected=true")
        for match in tokens:
            token = match.group(0)
            if not re.fullmatch(r"[0-9A-Fa-f]+", token):
                if any(char.isdigit() for char in token):
                    logger.info("[CANON] transform=base16 decode_success=false reason=invalid_character")
                continue
            if len(token) % 2:
                logger.info("[CANON] transform=base16 decode_success=false reason=odd_length")
                continue
            if len(token) // 2 > MAX_DECODED_BYTES:
                raise OverflowError("decoded_size_limit")
            try:
                text = _printable_text(bytes.fromhex(token))
            except ValueError:
                text = None
            if text is not None:
                decoded.append(("base16", text))

    if _B64_HINT.search(value):
        tokens = list(_B64_TOKEN.finditer(value))
        if tokens:
            logger.info("[CANON] transform=base64 detected=true")
        for match in tokens:
            token = match.group(0)
            if len(token) > ((MAX_DECODED_BYTES + 2) // 3) * 4 + 4:
                raise OverflowError("decoded_size_limit")
            padded = token + "=" * ((-len(token)) % 4)
            try:
                raw = base64.b64decode(padded, altchars=b"-_", validate=True)
            except (binascii.Error, ValueError):
                logger.info("[CANON] transform=base64 decode_success=false reason=malformed")
                continue
            text = _printable_text(raw)
            if text is not None:
                decoded.append(("base64", text))

    return decoded


def inspect_encoded_input(value: str) -> Inspection:
    """Return bounded decoded candidates for classification; never executes them."""
    if not isinstance(value, str):
        return Inspection((), "invalid_input")
    try:
        raw_size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        return Inspection((), "invalid_input")
    if raw_size > MAX_INPUT_BYTES:
        logger.warning("[CANON] rejected reason=input_size_limit")
        return Inspection((), "input_size_limit")

    candidates: list[Candidate] = []
    queue = deque([(value, 0)])
    seen = {value}
    while queue:
        current, depth = queue.popleft()
        try:
            found = _decode_candidates(current)
        except OverflowError:
            logger.warning("[CANON] rejected reason=decoded_size_limit depth=%d", depth + 1)
            return Inspection(tuple(candidates), "decoded_size_limit")
        if found and depth >= MAX_DEPTH:
            logger.warning("[CANON] rejected reason=depth_limit depth=%d", depth)
            return Inspection(tuple(candidates), "depth_limit")
        for transform, text in found:
            logger.info("[CANON] transform=%s decode_success=true depth=%d", transform, depth + 1)
            if text in seen:
                continue
            seen.add(text)
            candidate = Candidate(transform, text, depth + 1)
            logger.info(
                "[CANON] transform=%s candidate_created=true candidate_chars=%d utf8_valid=true depth=%d",
                transform,
                len(text),
                depth + 1,
            )
            if len(candidates) >= MAX_CANDIDATES:
                logger.warning("[CANON] rejected reason=candidate_limit")
                return Inspection(tuple(candidates), "candidate_limit")
            candidates.append(candidate)
            queue.append((text, depth + 1))
    logger.info("[CANON] candidate_count=%d", len(candidates))
    return Inspection(tuple(candidates))
