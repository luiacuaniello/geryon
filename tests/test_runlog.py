"""The run logger, because two runs were already lost to buffering."""

from __future__ import annotations

import gzip
import sys

from geryon import runlog


def test_output_reaches_both_the_console_and_the_file(tmp_path, capsys):
    path = tmp_path / "run.log"
    handle = runlog.start(path, header="# header line")
    try:
        print("first line")
        print("second line")
    finally:
        archived = runlog.finish(handle, path, compress=False)

    written = archived.read_text()
    assert "# header line" in written
    assert "first line" in written
    assert "second line" in written
    assert "first line" in capsys.readouterr().out


def test_every_line_is_flushed_immediately(tmp_path):
    """The whole point: a running job must be readable while it runs."""
    path = tmp_path / "run.log"
    handle = runlog.start(path)
    try:
        print("visible right away")
        # read the file while the run is still "in progress"
        assert "visible right away" in path.read_text()
    finally:
        runlog.finish(handle, path, compress=False)


def test_stderr_is_captured_too(tmp_path):
    path = tmp_path / "run.log"
    handle = runlog.start(path)
    try:
        print("to stderr", file=sys.stderr)
    finally:
        runlog.finish(handle, path, compress=False)
    assert "to stderr" in path.read_text()


def test_start_composes_with_an_existing_redirection(tmp_path):
    """Tee onto the current stream, not the original, or a caller's capture is lost."""
    import io

    outer = io.StringIO()
    saved = sys.stdout
    sys.stdout = outer
    path = tmp_path / "run.log"
    handle = runlog.start(path)
    try:
        print("through both")
    finally:
        runlog.finish(handle, path, compress=False)
        restored = sys.stdout
        sys.stdout = saved

    assert restored is outer, "finish must put back what start found"
    assert "through both" in outer.getvalue()
    assert "through both" in path.read_text()


def test_streams_are_restored_and_the_log_is_compressed(tmp_path):
    path = tmp_path / "run.log"
    handle = runlog.start(path)
    print("content")
    archived = runlog.finish(handle, path)

    assert not isinstance(sys.stdout, runlog.Tee), "a run must not leave the streams hijacked"
    assert not isinstance(sys.stderr, runlog.Tee)
    assert archived.suffix == ".gz"
    assert not path.exists(), "the uncompressed log is replaced, not duplicated"
    with gzip.open(archived, "rt") as fh:
        assert "content" in fh.read()


def test_isatty_is_false_so_progress_bars_do_not_pollute_the_log(tmp_path):
    path = tmp_path / "run.log"
    handle = runlog.start(path)
    try:
        assert sys.stdout.isatty() is False
    finally:
        runlog.finish(handle, path, compress=False)


def test_capture_finalises_the_log_even_when_the_run_dies(tmp_path):
    """A crash is when the log matters most.

    The first real run with logging enabled had its API key expire mid-flight.
    The traceback was already flushed to the file, but the log was never closed
    or compressed because the exception skipped the cleanup.
    """
    import gzip

    path = tmp_path / "run.log"
    try:
        with runlog.capture(path, header="# header"):
            print("some progress")
            raise RuntimeError("the key expired")
    except RuntimeError:
        pass

    archived = path.with_suffix(".log.gz")
    assert archived.exists(), "the log must be finalised on the way out"
    assert not path.exists()
    with gzip.open(archived, "rt") as fh:
        body = fh.read()
    assert "# header" in body
    assert "some progress" in body
    assert not isinstance(sys.stdout, runlog.Tee), "streams restored despite the exception"


def test_a_failing_run_records_its_traceback_in_the_log(tmp_path):
    """The log's whole purpose is explaining a run that died.

    An exception escaping the capture has its traceback printed after the streams
    are restored, so it goes wherever the shell was pointing — /dev/null for a
    background run. The runner therefore prints it inside the context; this test
    pins that the log can carry a traceback at all.
    """
    import gzip
    import traceback

    path = tmp_path / "run.log"
    try:
        with runlog.capture(path):
            try:
                raise RuntimeError("the benchmark exploded")
            except RuntimeError:
                traceback.print_exc()
                raise
    except RuntimeError:
        pass

    with gzip.open(path.with_suffix(".log.gz"), "rt") as fh:
        body = fh.read()
    assert "the benchmark exploded" in body
    assert "Traceback" in body
