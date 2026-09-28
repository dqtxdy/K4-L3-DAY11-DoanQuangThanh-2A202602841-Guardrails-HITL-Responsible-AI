"""Shared deterministic text normalization and protected-data scanning."""
from __future__ import annotations

import json
import base64
import re
import unicodedata
from pathlib import Path


def canonicalize(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("security text must be a string")
    value = unicodedata.normalize("NFKC", text).casefold()
    value = "".join(ch for ch in unicodedata.normalize("NFD", value) if unicodedata.category(ch) != "Mn")
    value = "".join(ch for ch in value if unicodedata.category(ch) not in {"Cf", "Cc", "Cs"} or ch in "\n\t ")
    value = re.sub(r"(?<=[a-z])[^\w\s]{1,3}(?=[a-z])", " ", value)
    value = re.sub(r"[\s\u00a0]+", " ", value)
    return value.strip()


def secret_values() -> list[str]:
    path = Path(__file__).resolve().parents[2] / "data/protected/vinbank_secrets.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        values = list((data.get("secrets") or {}).values())
        values += [x for t in data.get("leak_targets", []) for x in [t.get("value", ""), *(t.get("match_substrings", []))]]
        return [str(x) for x in values if x]
    except (OSError, ValueError):
        return []


def sensitive_matches(text: str) -> list[str]:
    normalized = canonicalize(text)
    found: list[str] = []
    patterns = {
        "phone": r"(?<!\d)(?:\+?84|0)(?:[ .()-]*\d){9,10}(?!\d)",
        "email": r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-z]{2,}(?!\w)",
        "identity_number": r"(?<!\d)\d{9}(?:\d{3})?(?!\d)",
        "api_key": r"\b(?:sk-[a-z0-9_-]{4,}|(?:api[_ -]?key|token)\s*(?:[:=]|starts|begins|is)\s*[^\s,;]+)",
        "password": r"\b(?:admin\s+)?(?:password|passwd|passcode)\b.{0,24}\b(?:[:=]|is|starts|begins|equals)\b",
        "database_host": r"\b[a-z0-9.-]+\.internal(?::\d{2,5})?\b|\b(?:host|server|database)\s*[:=]\s*[^\s,;]+",
    }
    for category, pattern in patterns.items():
        if re.search(pattern, normalized, re.I) or (category == "email" and re.search(pattern, text, re.I)):
            found.append(category)
    for value in secret_values():
        needle = canonicalize(value)
        compact = re.sub(r"[^a-z0-9]", "", needle)
        compact_text = re.sub(r"[^a-z0-9]", "", normalized)
        encoded_match = False
        if len(compact) >= 6:
            try:
                secret_bytes = value.encode("utf-8", errors="strict")
                b64 = base64.b64encode(secret_bytes).decode("ascii")
                hex_value = secret_bytes.hex()
                encoded_match = b64 in text or hex_value in text.casefold()
            except UnicodeEncodeError:
                pass
        if needle in normalized or (len(compact) >= 6 and compact in compact_text) or encoded_match:
            category = "api_key" if "sk-" in value.lower() else "database_host" if ".internal" in value.lower() else "password"
            if category not in found:
                found.append(category)
    return found
