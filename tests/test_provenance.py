"""The provenance helpers in the runner.

These exist because the first campaign recorded `"geryon_commit": "HEAD"` in 36
files: `git rev-parse HEAD` exits 128 in a repository with no commits and still
prints "HEAD" on stdout, and the old helper trusted stdout alone.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _runner():
    spec = importlib.util.spec_from_file_location(
        "run_condition", ROOT / "scripts" / "run_condition.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_condition = _runner()


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    return tmp_path


@pytest.fixture
def repo(empty_repo: Path) -> Path:
    _git(empty_repo, "config", "user.email", "t@example.invalid")
    _git(empty_repo, "config", "user.name", "T")
    (empty_repo / "a.txt").write_text("one\n")
    _git(empty_repo, "add", "a.txt")
    _git(empty_repo, "commit", "-qm", "first")
    return empty_repo


def test_commit_is_none_before_the_first_commit(empty_repo: Path) -> None:
    """The regression: git prints "HEAD" here and exits non-zero."""
    assert run_condition.git_commit(empty_repo) is None


def test_commit_is_a_full_hash(repo: Path) -> None:
    sha = run_condition.git_commit(repo)
    assert sha is not None
    assert run_condition._SHA1.match(sha)


def test_commit_is_none_outside_a_repository(tmp_path: Path) -> None:
    assert run_condition.git_commit(tmp_path) is None


def test_dirty_tracks_uncommitted_changes(repo: Path) -> None:
    assert run_condition.git_dirty(repo) is False
    (repo / "a.txt").write_text("two\n")
    assert run_condition.git_dirty(repo) is True


def test_dirty_is_none_outside_a_repository(tmp_path: Path) -> None:
    assert run_condition.git_dirty(tmp_path) is None


def test_root_is_the_repository_not_a_parent_guess(repo: Path) -> None:
    nested = repo / "deep" / "deeper"
    nested.mkdir(parents=True)
    assert Path(run_condition.git_root(nested)).resolve() == repo.resolve()
    assert run_condition.git_root(Path(repo.parent)) != str(repo)
