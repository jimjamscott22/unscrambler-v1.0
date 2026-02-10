from utils import normalize_token, parse_scramble_tokens


def test_normalize_token_case_and_strip() -> None:
    token = "  HeL-lo!42  "
    normalized = normalize_token(token, normalize_case=True, strip_non_alphanumerics=True)
    assert normalized == "hello42"


def test_normalize_token_keeps_digits_and_punctuation_when_configured() -> None:
    token = "AbC-123!"
    normalized = normalize_token(token, normalize_case=False, strip_non_alphanumerics=False)
    assert normalized == "AbC-123!"


def test_parse_scramble_tokens_with_auto_detect_label() -> None:
    raw = "List of scrambled words: tinsel  vile\nonset"
    tokens = parse_scramble_tokens(raw, auto_detect_labels=True)
    assert tokens == ["tinsel", "vile", "onset"]

