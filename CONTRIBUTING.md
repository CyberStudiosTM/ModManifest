# Contributing

1. Fork, branch, and keep changes focused.
2. `pip install -e ".[dev]"`
3. `ruff check . && ruff format --check . && pytest` must pass.

Guidelines:

- Tests use synthetic fixtures built in code. Never commit real mod content.
- Every emitted diagnostic code must be registered in `src/modmanifest/codes.py` with a
  basis. Keep observed conventions separate from verified format rules.
- The tool is read-only: no extraction, execution, network access or file modification.
- Do not guess unknown formats or checksum algorithms; report `NOT CHECKED`.
