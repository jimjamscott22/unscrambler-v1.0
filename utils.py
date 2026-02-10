"""Utility helpers for normalization, parsing, config, and exports."""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from models import SolveOptions, SolveReport


def _choose_app_dir() -> Path:
    """
    Pick a writable app directory.

    Preferred location is user home, with local workspace fallback when blocked.
    """
    preferred = Path.home() / ".unscrambler_anagram_app"
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        return preferred
    except OSError:
        fallback = Path(".unscrambler_anagram_app")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


APP_DIR = _choose_app_dir()
CONFIG_PATH = APP_DIR / "config.json"
CACHE_DIR = APP_DIR / "cache"
LOG_PATH = APP_DIR / "app.log"

NON_ALNUM_PATTERN = re.compile(r"[^0-9A-Za-z]+")
WHITESPACE_PATTERN = re.compile(r"\S+")
COMMON_LABEL_LINE = re.compile(r"^\s*(list of scrambled words|scrambled words|input|words)\s*:\s*", re.IGNORECASE)


def ensure_app_dirs() -> None:
    """Create app directories if they do not already exist."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging() -> None:
    """Configure file logging once per app run."""
    ensure_app_dirs()
    logging.basicConfig(
        filename=str(LOG_PATH),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def load_config() -> dict[str, Any]:
    """Load config from the user home config file."""
    ensure_app_dirs()
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        logging.exception("Failed to load config from %s", CONFIG_PATH)
        return {}


def save_config(config: dict[str, Any]) -> None:
    """Persist config to disk."""
    ensure_app_dirs()
    try:
        CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except Exception:
        logging.exception("Failed to save config to %s", CONFIG_PATH)


def normalize_token(token: str, normalize_case: bool, strip_non_alphanumerics: bool) -> str:
    """
    Normalize a token using selected options.

    Steps:
    1) Trim leading/trailing whitespace.
    2) Optionally lowercase.
    3) Optionally strip non-alphanumerics.
    """
    out = token.strip()
    if normalize_case:
        out = out.lower()
    if strip_non_alphanumerics:
        out = NON_ALNUM_PATTERN.sub("", out)
    return out


def parse_scramble_tokens(raw_text: str, auto_detect_labels: bool) -> list[str]:
    """Parse whitespace-separated tokens from potentially labeled input text."""
    if not raw_text or not raw_text.strip():
        return []

    lines = raw_text.splitlines()
    cleaned_lines: list[str] = []
    for line in lines:
        if auto_detect_labels:
            line = COMMON_LABEL_LINE.sub("", line)
        cleaned_lines.append(line)

    cleaned = "\n".join(cleaned_lines).strip()
    return WHITESPACE_PATTERN.findall(cleaned)


def signature(token: str) -> str:
    """Canonical sorted-signature for an anagram token."""
    return "".join(sorted(token))


def cache_key(wordlist_path: Path, options: SolveOptions, file_size: int, mtime_ns: int) -> str:
    """Create a deterministic cache key from file identity and relevant options."""
    key_data = {
        "path": str(wordlist_path.resolve()),
        "size": file_size,
        "mtime_ns": mtime_ns,
        "normalize_case": options.normalize_case,
        "strip_non_alphanumerics": options.strip_non_alphanumerics,
    }
    digest = hashlib.sha256(json.dumps(key_data, sort_keys=True).encode("utf-8")).hexdigest()
    return digest


def export_report(json_path: Path, csv_path: Path, report: SolveReport, wordlist_path: str, options: SolveOptions) -> None:
    """Export solve report to both JSON and CSV."""
    payload = {
        "generated_at_utc": report.generated_at_utc,
        "wordlist_path": wordlist_path,
        "options": {
            "normalize_case": options.normalize_case,
            "strip_non_alphanumerics": options.strip_non_alphanumerics,
            "auto_detect_labels": options.auto_detect_labels,
            "use_speed_cache": options.use_speed_cache,
        },
        "answer_csv": report.answer_csv,
        "input_tokens": report.input_tokens,
        "results": [
            {
                "token": r.token,
                "normalized_token": r.normalized_token,
                "status": r.status,
                "chosen_match": r.chosen_match,
                "matches": r.matches,
            }
            for r in report.results
        ],
    }

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["token", "normalized_token", "status", "chosen_match", "alternative_matches"])
        for row in report.results:
            alternatives = [word for word in row.matches if word != row.chosen_match]
            writer.writerow([row.token, row.normalized_token, row.status, row.chosen_match, "|".join(alternatives)])
