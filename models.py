"""Data models for anagram solve results and indexing metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class SolveOptions:
    """Normalization and parsing options used for indexing and solving."""

    normalize_case: bool = True
    strip_non_alphanumerics: bool = False
    auto_detect_labels: bool = False
    use_speed_cache: bool = True


@dataclass(slots=True)
class TokenResult:
    """Result for a single input token."""

    token: str
    normalized_token: str
    status: str
    chosen_match: str
    matches: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SolveReport:
    """Aggregated solve output preserving input order."""

    input_tokens: list[str]
    results: list[TokenResult]
    answer_csv: str
    generated_at_utc: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass(slots=True)
class IndexBuildResult:
    """Summary returned after building or loading an index."""

    wordlist_path: str
    total_lines: int
    accepted_words: int
    unique_signatures: int
    loaded_from_cache: bool

