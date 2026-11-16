"""Settings from a .env file and the environment. Imports nothing from the project.

This is the single place where LLM defaults live; `.env.example` documents the same names.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """LLM settings. The key is hidden from repr so it never leaks into logs."""
    api_key: str | None = field(repr=False)
    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    timeout: float = 60.0         # seconds per LLM request
    temperature: float = 0.0      # 0 = most repeatable answers
    max_transactions: int = 200   # how many HTTP transactions are sent to the model
    base_url: str | None = None   # server URL for provider "openai" (OpenAI-compatible API)
    json_mode: bool = False       # ask the server for JSON output (only some models support it)


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse NAME=value lines; skip blanks, # comments and `export `; drop trailing ` # note`."""
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().removeprefix("export ")
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            value = value.strip()
            values[name.strip()] = value.strip("\"'") if value[:1] in "\"'" else value.split(" #")[0].strip()
    return values


def _number(values: Mapping[str, str], name: str, default):
    """Read a numeric setting (int or float, following the default's type)."""
    raw = values.get(name)
    if not raw:
        return default
    try:
        return type(default)(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got '{raw}'") from None


def load_settings(env_file: Path = Path(".env"), environ: Mapping[str, str] | None = None) -> Settings:
    """Read the LLM_* settings. Real environment variables beat the file. Bad numbers raise ValueError."""
    values = {**_read_env_file(Path(env_file)), **(os.environ if environ is None else environ)}
    return Settings(
        api_key=values.get("LLM_API_KEY") or None,
        provider=values.get("LLM_PROVIDER") or Settings.provider,
        model=values.get("LLM_MODEL") or Settings.model,
        timeout=_number(values, "LLM_TIMEOUT", Settings.timeout),
        temperature=_number(values, "LLM_TEMPERATURE", Settings.temperature),
        max_transactions=_number(values, "LLM_MAX_TRANSACTIONS", Settings.max_transactions),
        base_url=values.get("LLM_BASE_URL") or None,
        json_mode=values.get("LLM_JSON_MODE", "").lower() in ("1", "true", "yes"),
    )
