# Unscrambler Anagram App

A fast Tkinter desktop app for solving scrambled-word (anagram) challenges using a provided wordlist.

## Features

- Paste scrambled words (space-separated or one per line).
- Load a `.txt` wordlist (one candidate word per line).
- Background-thread indexing with UI progress updates.
- Signature-based anagram matching: `signature = ''.join(sorted(word))`.
- Normalization options:
  - Normalize case (lowercase)
  - Strip non-alphanumerics (keeps digits)
- Optional auto-detect label cleanup (`List of scrambled words: ...`).
- Optional speed cache: saves index to disk for near-instant reload.
- Per-token result table:
  - token
  - found/not found
  - chosen match
  - alternative match count
- Alternative selection UI for collisions (choose preferred match).
- Primary output as a single comma-separated answer string (input order preserved).
- One-click clipboard copy.
- Export results to JSON + CSV.
- Persists last-used wordlist path in a small config file under the user app directory.
- Error dialogs for users plus file logging.

## Project Structure

```text
app.py
solver.py
models.py
utils.py
requirements.txt
sample_data/
  wordlist_small.txt
tests/
  test_utils.py
  test_solver.py
```

## Setup

1. Create/activate a Python 3.11+ environment.
2. Install test dependency:

```bash
pip install -r requirements.txt
```

## Run App

```bash
python app.py
```

## Run Tests

```bash
pytest -q
```

## Sample Challenge

Using `sample_data/wordlist_small.txt` and input:

```text
tinsel vile unknown
```

Expected answer output:

```text
listen,evil,[NO MATCH: unknown]
```

The app preserves token order and keeps placeholders for misses.

## Export Format

- JSON: full metadata and per-token details.
- CSV: `token, normalized_token, status, chosen_match, alternative_matches`.

## Config, Cache, and Logs

- Preferred app directory: `~/.unscrambler_anagram_app/`
- Files:
  - `config.json` (last wordlist path)
  - `cache/*.pkl` (optional speed cache)
  - `app.log` (error/info log)
- If home write access is blocked, app falls back to a local `.unscrambler_anagram_app/` directory.

## Build Executable (Optional)

Install PyInstaller and build:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed app.py
```

Executable output appears under `dist/`.

