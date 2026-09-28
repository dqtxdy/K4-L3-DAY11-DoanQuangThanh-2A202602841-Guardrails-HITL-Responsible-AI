"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        from core.security import sensitive_matches
        request_id = request_id or f"{user_id}-{len(self.logs)+1}"
        self._open[request_id] = __import__('time').monotonic()
        preview = text[:240]
        if sensitive_matches(preview):
            from guardrails.output_guardrails import content_filter
            preview = content_filter(preview)["redacted"]
        self._current = getattr(self, "_current", {})
        self._current[request_id] = {"request_id": request_id, "user_id": user_id, "timestamp": utc_now_iso(), "input_preview": preview}
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        from guardrails.output_guardrails import content_filter
        request_id = request_id or next(iter(self._open), f"{user_id}-{len(self.logs)+1}")
        clean = content_filter(text)["redacted"]
        row = getattr(self, "_current", {}).pop(request_id, {"request_id": request_id, "user_id": user_id, "timestamp": utc_now_iso()})
        row.update({"decision": "BLOCK" if blocked else "ALLOW", "blocked": blocked, "layer": layer, "latency_ms": round((__import__('time').monotonic() - self._open.pop(request_id, __import__('time').monotonic())) * 1000, 2), "output_preview": clean[:240]})
        self.logs.append(row)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
