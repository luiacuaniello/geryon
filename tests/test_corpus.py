"""The corpus is data, so its integrity is a test rather than a convention."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from geryon.cases import CaseInvalid, find_cases_dir, load_cases, validate_case

REPO = Path(__file__).resolve().parents[1]
TAXONOMY = REPO / "protocol" / "attack-taxonomy.md"


def test_corpus_loads_and_validates():
    cases = load_cases()
    assert cases, "corpus is empty"


def test_schema_families_match_the_taxonomy_document():
    """A family that exists in code but not in the protocol is undocumented."""
    schema = json.loads((find_cases_dir() / "schema.json").read_text())
    schema_families = set(schema["properties"]["family"]["enum"])
    documented = set(re.findall(r"`family: ([a-z-]+)`", TAXONOMY.read_text()))
    assert schema_families == documented, (
        f"only in schema: {sorted(schema_families - documented)}; "
        f"only in taxonomy: {sorted(documented - schema_families)}"
    )


def test_every_case_declares_what_it_probes():
    for case_id, case in load_cases().items():
        assert case["probes"].strip(), f"{case_id} does not say what it probes"
        assert case["rationale"].strip(), f"{case_id} has no rationale"


def test_templates_carry_the_goal_placeholder():
    """A case that never substitutes {goal} cannot execute the injection task."""
    for case_id, case in load_cases().items():
        assert "{goal}" in case["template"], f"{case_id} template has no {{goal}} placeholder"


def test_directory_name_matches_case_id():
    for case_id, case in load_cases().items():
        assert Path(case["_path"]).parent.name == case_id


def test_invalid_case_is_rejected():
    schema = json.loads((find_cases_dir() / "schema.json").read_text())
    with pytest.raises(CaseInvalid):
        validate_case({"id": "nope", "family": "invented"}, schema, "<test>")
