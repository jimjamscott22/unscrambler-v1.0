"""Anagram index builder and solve engine."""

from __future__ import annotations

import logging
import pickle
from collections import defaultdict
from pathlib import Path
from typing import Callable

from models import IndexBuildResult, SolveOptions, SolveReport, TokenResult
from utils import CACHE_DIR, cache_key, ensure_app_dirs, normalize_token, parse_scramble_tokens, signature

ProgressCallback = Callable[[float], None]


class AnagramSolver:
    """Build and query a signature index for fast anagram solving."""

    def __init__(self) -> None:
        self.index: dict[str, list[str]] = {}
        self.wordlist_path: str = ""
        self.index_options = SolveOptions()

    def build_index(
        self,
        wordlist_path: str,
        options: SolveOptions,
        progress_callback: ProgressCallback | None = None,
    ) -> IndexBuildResult:
        """
        Build or load an anagram index from a wordlist path.

        The index maps signature -> list of candidate words.
        """
        path = Path(wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

        ensure_app_dirs()
        file_stat = path.stat()
        cache_file = CACHE_DIR / f"{cache_key(path, options, file_stat.st_size, file_stat.st_mtime_ns)}.pkl"

        if options.use_speed_cache and cache_file.exists():
            with cache_file.open("rb") as handle:
                cached = pickle.load(handle)
            self.index = cached["index"]
            self.wordlist_path = str(path)
            self.index_options = SolveOptions(
                normalize_case=options.normalize_case,
                strip_non_alphanumerics=options.strip_non_alphanumerics,
                auto_detect_labels=options.auto_detect_labels,
                use_speed_cache=options.use_speed_cache,
            )
            if progress_callback:
                progress_callback(1.0)
            return IndexBuildResult(
                wordlist_path=str(path),
                total_lines=cached["total_lines"],
                accepted_words=cached["accepted_words"],
                unique_signatures=len(self.index),
                loaded_from_cache=True,
            )

        total_bytes = max(file_stat.st_size, 1)
        total_lines = 0
        accepted_words = 0
        index_map: dict[str, list[str]] = defaultdict(list)

        with path.open("rb") as handle:
            bytes_processed = 0
            for raw_line in handle:
                bytes_processed += len(raw_line)
                total_lines += 1

                candidate = raw_line.decode("utf-8", errors="ignore").strip()
                if not candidate:
                    continue

                normalized = normalize_token(
                    candidate,
                    normalize_case=options.normalize_case,
                    strip_non_alphanumerics=options.strip_non_alphanumerics,
                )
                if not normalized:
                    continue

                sig = signature(normalized)
                stored_word = normalized if (options.normalize_case or options.strip_non_alphanumerics) else candidate
                index_map[sig].append(stored_word)
                accepted_words += 1

                if progress_callback and total_lines % 5000 == 0:
                    progress_callback(min(bytes_processed / total_bytes, 1.0))

        self.index = dict(index_map)
        self.wordlist_path = str(path)
        self.index_options = SolveOptions(
            normalize_case=options.normalize_case,
            strip_non_alphanumerics=options.strip_non_alphanumerics,
            auto_detect_labels=options.auto_detect_labels,
            use_speed_cache=options.use_speed_cache,
        )

        if options.use_speed_cache:
            payload = {
                "index": self.index,
                "total_lines": total_lines,
                "accepted_words": accepted_words,
            }
            try:
                with cache_file.open("wb") as handle:
                    pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception:
                logging.exception("Failed writing cache file: %s", cache_file)

        if progress_callback:
            progress_callback(1.0)

        return IndexBuildResult(
            wordlist_path=str(path),
            total_lines=total_lines,
            accepted_words=accepted_words,
            unique_signatures=len(self.index),
            loaded_from_cache=False,
        )

    def solve(
        self,
        raw_input: str,
        options: SolveOptions,
        manual_choices: dict[int, str] | None = None,
    ) -> SolveReport:
        """Solve tokens in input order and return detailed per-token results."""
        tokens = parse_scramble_tokens(raw_input, auto_detect_labels=options.auto_detect_labels)
        results: list[TokenResult] = []
        choices = manual_choices or {}

        for idx, token in enumerate(tokens):
            normalized = normalize_token(
                token,
                normalize_case=options.normalize_case,
                strip_non_alphanumerics=options.strip_non_alphanumerics,
            )
            if not normalized:
                chosen = f"[NO MATCH: {token}]"
                results.append(
                    TokenResult(
                        token=token,
                        normalized_token=normalized,
                        status="not found",
                        chosen_match=chosen,
                        matches=[],
                    )
                )
                continue

            sig = signature(normalized)
            matches = self.index.get(sig, [])
            if matches:
                chosen = matches[0]
                if idx in choices and choices[idx] in matches:
                    chosen = choices[idx]
                results.append(
                    TokenResult(
                        token=token,
                        normalized_token=normalized,
                        status="found",
                        chosen_match=chosen,
                        matches=matches,
                    )
                )
            else:
                chosen = f"[NO MATCH: {token}]"
                results.append(
                    TokenResult(
                        token=token,
                        normalized_token=normalized,
                        status="not found",
                        chosen_match=chosen,
                        matches=[],
                    )
                )

        answer = ",".join(r.chosen_match for r in results)
        return SolveReport(input_tokens=tokens, results=results, answer_csv=answer)

