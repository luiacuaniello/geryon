"""Locating, loading and validating the attack corpus.

The corpus lives in a top-level ``attacks/`` directory rather than inside the
package, because it is data that people are meant to read and criticise, not an
implementation detail. That choice means the path has to be resolved rather than
hard-coded relative to the module: a fixed ``parents[2]`` works in an editable
install and silently resolves to somewhere in site-packages otherwise.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import yaml

ENV_VAR = "GERYON_CASES"


class CorpusNotFound(RuntimeError):
    """The attacks/ directory could not be located."""


class CaseInvalid(ValueError):
    """A case file does not satisfy attacks/schema.json."""


def find_cases_dir(start: Path | None = None) -> Path:
    """Resolve the corpus directory.

    Order: explicit environment variable, then the nearest ancestor of this file
    that contains ``attacks/schema.json``.
    """
    override = os.environ.get(ENV_VAR)
    if override:
        path = Path(override).expanduser().resolve()
        if not (path / "schema.json").is_file():
            raise CorpusNotFound(f"{ENV_VAR}={path} does not contain schema.json")
        return path

    here = (start or Path(__file__)).resolve()
    for parent in here.parents:
        candidate = parent / "attacks"
        if (candidate / "schema.json").is_file():
            return candidate
    raise CorpusNotFound(
        "could not locate attacks/schema.json above "
        f"{here}. Install the project in editable mode (pip install -e .) or set "
        f"{ENV_VAR} to the corpus directory."
    )


def load_schema(cases_dir: Path | None = None) -> dict:
    cases_dir = cases_dir or find_cases_dir()
    with open(cases_dir / "schema.json") as fh:
        return json.load(fh)


def validate_case(case: dict, schema: dict, source: str) -> None:
    """Validate one case, with a message that names the file."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise CaseInvalid("jsonschema is required to validate the corpus") from exc

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(case), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors)
        raise CaseInvalid(f"{source}: {detail}")


def load_cases(cases_dir: Path | None = None, validate: bool = True) -> dict[str, dict]:
    """Every case in the corpus, keyed by id, validated against the schema."""
    cases_dir = cases_dir or find_cases_dir()
    schema = load_schema(cases_dir) if validate else {}
    cases: dict[str, dict] = {}
    for path in sorted(cases_dir.glob("*/case.yaml")):
        with open(path) as fh:
            case = yaml.safe_load(fh)
        if not isinstance(case, dict):
            raise CaseInvalid(f"{path}: not a mapping")
        if validate:
            validate_case(case, schema, str(path))
        case_id = case["id"]
        if case_id in cases:
            raise CaseInvalid(f"{path}: duplicate case id {case_id!r}")
        if path.parent.name != case_id:
            raise CaseInvalid(f"{path}: directory {path.parent.name!r} does not match id {case_id!r}")
        case["_path"] = str(path)
        cases[case_id] = case
    return cases


def main() -> int:
    """CLI: validate the corpus. Used by CI so a bad case fails the build."""
    try:
        cases_dir = find_cases_dir()
        cases = load_cases(cases_dir)
    except (CorpusNotFound, CaseInvalid) as exc:
        print(f"corpus INVALID: {exc}")
        return 1
    if not cases:
        print(f"corpus INVALID: no cases found in {cases_dir}")
        return 1
    print(f"corpus OK: {len(cases)} case(s) in {cases_dir}")
    for case_id, case in cases.items():
        print(f"  {case_id:32s} family={case['family']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
