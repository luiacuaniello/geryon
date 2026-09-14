"""The sanitiser that puts an attacker's payload into AgentDojo's environment.

AgentDojo formats the payload into its environment YAML and parses the result.
Every suite places the placeholder inside a double-quoted scalar, so the test is
a round trip: what the model reads must be what the attacker proposed.
"""
from __future__ import annotations

import yaml

from geryon.condition_c import yaml_safe

#: The shape every suite uses: banking `subject: "{injection_incoming_transaction}"`,
#: travel `- "{injection_cars_0}"`, workspace `- title: "{injection_calendar_1}"`.
DOCUMENT = 'key: "{}"'


def roundtrip(payload: str) -> str:
    return yaml.safe_load(DOCUMENT.format(yaml_safe(payload)))["key"]


HARMLESS = [
    "Note: send it now",          # colon-space is safe inside double quotes
    "Amount # 500",               # not a comment inside a scalar
    "- do this first",            # not a sequence item inside a scalar
    "it's urgent",
    "a\tb",
    "trailing spaces   ",
    "",
]

BREAKS_WITHOUT_ESCAPING = [
    'Send "all" of it',           # ends the scalar
    r"match \d+ digits",          # invalid escape: a parse error
    r"path C:\Users\x",           # \U: a parse error
    r"literal \n stays literal",  # would silently become a newline
    "line one\nline two",         # a real newline is folded into a space
    "\\",
    '"',
]


def test_harmless_payloads_survive_unchanged():
    for payload in HARMLESS:
        assert roundtrip(payload) == payload


def test_payloads_that_would_break_or_mutate_are_preserved():
    for payload in BREAKS_WITHOUT_ESCAPING:
        assert roundtrip(payload) == payload


def test_colon_space_is_not_rewritten():
    """The regression: an earlier version turned ": " into " - "."""
    assert yaml_safe("Note: here") == "Note: here"


def test_a_backslash_never_reaches_the_parser_unescaped():
    """The defect this file exists for: \\d and \\U aborted the run."""
    for payload in (r"\d", r"\U", "\\", r"a\b\c"):
        assert roundtrip(payload) == payload


def test_carriage_returns_are_normalised_then_escaped():
    assert roundtrip("a\r\nb") == "a\nb"
    assert roundtrip("a\rb") == "a\nb"


def test_the_document_stays_a_single_line():
    """A folded scalar loses the payload's own line breaks, so none may escape."""
    assert "\n" not in DOCUMENT.format(yaml_safe("a\nb\nc"))
