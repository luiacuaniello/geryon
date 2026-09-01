"""Capture a run's entire output to a file, line by line, without a shell pipe.

Two runs were lost to buffering before this existed: once Python block-buffered
its stdout into a pipe, once `grep` did the same one stage further along. Both
times the run was working and looked dead, and once the evidence for the most
interesting finding survived only because the temporary file had not been cleaned
up yet.

The fix is to stop routing the log through the shell. The process writes its own
log, flushing every line, and everything printed by anything in the process —
including the defence under test, which prints its policy updates — lands in it.

`isatty()` returns False deliberately: AgentDojo renders progress with rich, and
a log file full of animation escape codes is not greppable.
"""

from __future__ import annotations

import gzip
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path


class Tee:
    """Writes to the original stream and to a file, flushing both every time."""

    def __init__(self, stream, handle):
        self._stream = stream
        self._handle = handle

    def write(self, data: str) -> int:
        self._stream.write(data)
        self._stream.flush()
        self._handle.write(data)
        self._handle.flush()
        return len(data)

    def flush(self) -> None:
        self._stream.flush()
        self._handle.flush()

    def isatty(self) -> bool:
        return False

    def fileno(self):
        return self._stream.fileno()


def start(path: Path, header: str = "") -> object:
    """Redirect stdout and stderr into `path` as well as the current console.

    Tees onto whatever streams are installed rather than onto `sys.__stdout__`,
    and remembers them so `finish` puts back what it found. Reaching for the
    original streams would silently discard any redirection the caller had set up.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "w", buffering=1, encoding="utf-8", errors="replace")
    if header:
        handle.write(header.rstrip() + "\n\n")
        handle.flush()
    previous = (sys.stdout, sys.stderr)
    sys.stdout = Tee(sys.stdout, handle)
    sys.stderr = Tee(sys.stderr, handle)
    handle._geryon_previous = previous  # noqa: SLF001 - carried with the handle
    return handle


def finish(handle, path: Path, compress: bool = True) -> Path:
    """Restore the streams and gzip the log, which is mostly repetitive text."""
    previous = getattr(handle, "_geryon_previous", (sys.__stdout__, sys.__stderr__))
    sys.stdout, sys.stderr = previous
    try:
        handle.close()
    except Exception:  # noqa: BLE001 - never fail a completed run over its log
        pass
    if not compress or not path.exists():
        return path
    target = path.with_suffix(path.suffix + ".gz")
    with open(path, "rb") as src, gzip.open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
    path.unlink()
    return target


@contextmanager
def capture(path: Path, header: str = "", compress: bool = True):
    """Capture a run's output, finalising the log even when the run dies.

    A crash is when the log matters most: the run that first exercised this had
    its API key expire mid-flight, and the only account of it was the traceback
    the log had already flushed. Use this rather than start/finish by hand.
    """
    handle = start(path, header)
    try:
        yield handle
    finally:
        finish(handle, path, compress=compress)
