"""The fair test's analysis refuses runs that are not what their directory says, and compares the rest."""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from geryon.generic_policy import progent_rules

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("analyse_fair_test", ROOT / "scripts" / "analyse_fair_test.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)

#: Two pairs within policy and two outside, none on injection tasks 0, 1 or 3, whose
#: re-scoring would need the per-pair message logs.
PAIRS = [
    ("user_task_0", "injection_task_2", True),
    ("user_task_1", "injection_task_2", True),
    ("user_task_0", "injection_task_4", False),
    ("user_task_1", "injection_task_4", False),
]
WITHIN = {"user_task_0|injection_task_2", "user_task_1|injection_task_2"}


def write_configuration(root: Path, name: str, successes: set[str], rules_held: bool = True) -> None:
    condition, approver, generic = analysis.CONFIGURATIONS[name]
    directory = root / name
    directory.mkdir(parents=True)
    for repeat in (1, 2, 3):
        provenance = {
            "condition": condition, "suite": "banking", "repeat": repeat, "benchmark_version": "v1.2",
            "agent_model": "agent", "policy_model": "policy" if condition == "B" else None,
            "approver": approver, "generic_policy": generic, "defence_active": condition == "B",
            "benchmark_repo_commit": "b02783b" + "0" * 33,
        }
        security = {f"{u}|{i}": f"{u}|{i}" in successes for u, i, _ in PAIRS}
        run = {"provenance": provenance, "security": security, "utility": dict.fromkeys(security, True)}
        stem = directory / f"banking-{condition}-r{repeat}"
        stem.with_suffix(".json").write_text(json.dumps(run))
        if name == "generic":
            rules = {tool: list(r) for tool, r in progent_rules().items()} if rules_held else {}
            with gzip.open(stem.with_suffix(".log.gz"), "wt") as handle:
                handle.write(f"security policy updated: {rules!r}\n")


def write_pairs(path: Path) -> Path:
    entries = [{"suite": "banking", "user_task": u, "injection_task": i, "within_policy": w}
               for u, i, w in PAIRS]
    path.write_text(json.dumps(entries))
    return path


@pytest.fixture
def fair_test(tmp_path):
    root = tmp_path / "runs"
    write_configuration(root, "A", WITHIN | {"user_task_0|injection_task_4"})
    write_configuration(root, "auto-approve", WITHIN)
    write_configuration(root, "generic", set())
    write_configuration(root, "auto-deny", {"user_task_0|injection_task_2"})
    return root, analysis.pair_sets(write_pairs(tmp_path / "pairs.json"))


def test_comparable_runs_are_compared_pair_by_pair(fair_test):
    root, sets = fair_test
    configurations = analysis.load(root)
    assert analysis.problems(configurations, sets["all pairs"]) == []
    outcomes = {name: analysis.collapse(analysis.scored(runs, "intended"), "security")
                for name, runs in configurations.items()}
    within = sets["within policy"]
    assert analysis.compare(outcomes["generic"], outcomes["auto-approve"], within) == (2, 0, 0.5)
    assert analysis.compare(outcomes["auto-deny"], outcomes["auto-approve"], within) == (1, 0, 1.0)


def test_a_run_that_is_not_what_its_directory_says_is_refused(fair_test):
    root, sets = fair_test
    run = root / "generic" / "banking-B-r2.json"
    data = json.loads(run.read_text())
    data["provenance"]["generic_policy"] = False
    run.write_text(json.dumps(data))
    found = analysis.problems(analysis.load(root), sets["all pairs"])
    assert any("banking-B-r2.json: records ('B', 'auto-approve', False)" in problem for problem in found)


def test_a_generic_run_whose_rules_did_not_hold_is_refused(tmp_path):
    root = tmp_path / "runs"
    for name in analysis.CONFIGURATIONS:
        write_configuration(root, name, set(), rules_held=False)
    sets = analysis.pair_sets(write_pairs(tmp_path / "pairs.json"))
    found = analysis.problems(analysis.load(root), sets["all pairs"])
    assert sum("--check-log" in problem for problem in found) == 3


def test_another_progent_commit_or_pair_set_is_refused(fair_test):
    root, sets = fair_test
    run = root / "A" / "banking-A-r1.json"
    data = json.loads(run.read_text())
    data["provenance"]["benchmark_repo_commit"] = "8a8eb894b9d568a32b4e58252fea85b47f789c77"
    del data["security"]["user_task_1|injection_task_4"]
    run.write_text(json.dumps(data))
    found = analysis.problems(analysis.load(root), sets["all pairs"])
    assert any("Progent commit 8a8eb89" in problem for problem in found)
    assert any("not the 4 banking pairs" in problem for problem in found)


def test_a_missing_repeat_is_refused(fair_test):
    root, sets = fair_test
    (root / "auto-deny" / "banking-B-r3.json").unlink()
    found = analysis.problems(analysis.load(root), sets["all pairs"])
    assert "auto-deny: 2 repeats, the protocol fixes 3" in found


def test_main_prints_the_primary_comparison(fair_test, monkeypatch, capsys):
    root, _ = fair_test
    monkeypatch.setattr(analysis, "EARLIER", root / "absent")
    monkeypatch.setattr(sys, "argv", ["analyse_fair_test.py", "--root", str(root),
                                      "--pairs", str(root.parent / "pairs.json")])
    assert analysis.main() == 0
    out = capsys.readouterr().out
    assert "PRIMARY   generic against auto-approve, within policy: 2 attacks stopped only by generic" in out
    assert "every recorded success under the generic policy, run by run" in out


def test_refused_user_tasks_match_the_preanalysis():
    pytest.importorskip("agentdojo", reason="AgentDojo is needed for the reference solutions")
    from geryon.generic_policy import preanalysis

    assert list(analysis.REFUSED_USER_TASKS) == preanalysis("v1.2").refused_user
