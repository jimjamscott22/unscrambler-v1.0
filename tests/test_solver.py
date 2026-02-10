from pathlib import Path

from models import SolveOptions
from solver import AnagramSolver
from utils import signature


def sample_wordlist_path() -> str:
    return str(Path("sample_data") / "wordlist_small.txt")


def test_build_index_groups_anagrams() -> None:
    solver = AnagramSolver()
    options = SolveOptions(normalize_case=True, strip_non_alphanumerics=False, use_speed_cache=False)
    result = solver.build_index(sample_wordlist_path(), options)

    sig = signature("listen")
    assert result.accepted_words == 12
    assert sig in solver.index
    assert solver.index[sig][:3] == ["listen", "silent", "enlist"]


def test_solve_preserves_order_and_no_match_placeholder() -> None:
    solver = AnagramSolver()
    options = SolveOptions(normalize_case=True, strip_non_alphanumerics=False, use_speed_cache=False)
    solver.build_index(sample_wordlist_path(), options)

    report = solver.solve("tinsel vile unknown", options)
    chosen = [row.chosen_match for row in report.results]
    assert chosen[0] == "listen"
    assert chosen[1] == "evil"
    assert chosen[2] == "[NO MATCH: unknown]"
    assert report.answer_csv == "listen,evil,[NO MATCH: unknown]"


def test_solve_with_strip_non_alphanumerics() -> None:
    solver = AnagramSolver()
    options = SolveOptions(normalize_case=True, strip_non_alphanumerics=True, use_speed_cache=False)
    solver.build_index(sample_wordlist_path(), options)

    report = solver.solve("v!i,l.e", options)
    assert len(report.results) == 1
    assert report.results[0].status == "found"
    assert report.results[0].chosen_match == "evil"

