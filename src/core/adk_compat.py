"""Small import-time fallback for offline deterministic guardrail use.

Real ADK types are used whenever google-adk is installed; the fallback is not
an agent runtime and only supports tests/callback decisions without a model.
"""
from __future__ import annotations

try:
    from google.genai import types as types
    from google.adk.plugins import base_plugin as base_plugin
except ImportError:
    from dataclasses import dataclass, field
    from types import SimpleNamespace

    @dataclass
    class Part:
        text: str = ""
        @classmethod
        def from_text(cls, text: str):
            return cls(text=text)

    @dataclass
    class Content:
        role: str = "user"
        parts: list = field(default_factory=list)

    class BasePlugin:
        def __init__(self, name: str = "plugin"):
            self.name = name

    types = SimpleNamespace(Content=Content, Part=Part)
    base_plugin = SimpleNamespace(BasePlugin=BasePlugin)
