import fcntl
import json
import os
import time
from typing import Optional, TextIO
from typing import Protocol, runtime_checkable, cast

import yaml

_lock_file_handle: Optional[TextIO] = None
STALE_LOCK_SECONDS = 300  # 5 minutes


def _is_lock_stale(lock_path: str, stale_seconds: int = STALE_LOCK_SECONDS) -> bool:
    """
    Decide if the lock file looks stale based on its modification time.
    We assume mtime is updated when a process successfully acquires the lock.
    """
    if not os.path.exists(lock_path):
        return False

    try:
        mtime = os.path.getmtime(lock_path)
    except OSError:
        return False

    age = time.time() - mtime

    return age > stale_seconds


def acquire_singleton_lock(lock_path: str):
    """
    Acquire an exclusive non-blocking lock.

    If the lock is already held:
      - If the lock file is older than STALE_LOCK_SECONDS, we treat it as stale:
        remove the file and create a new lock file, then try again.
      - Otherwise, exit with a message that another instance is running.

    The lock file content is a simple timestamp (seconds since epoch) of when
    the lock was acquired successfully.
    """
    global _lock_file_handle

    # Check staleness BEFORE touching the file, so mtime reflects the previous holder.
    stale_before_open = _is_lock_stale(lock_path)

    # Do not use "w" here to avoid truncating and changing mtime before we decide.
    _lock_file_handle = open(lock_path, "a+")

    try:
        fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        # Another process holds the lock
        if stale_before_open:
            # Try to break a stale lock: remove the old file (old inode) and re-create.
            # noinspection PyBroadException
            try:
                _lock_file_handle.close()
            except Exception:
                pass

            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                pass

            # Reopen a fresh file and lock it
            _lock_file_handle = open(lock_path, "a+")
            try:
                fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # If we still cannot get the lock, something is really wrong.
                exit(
                    "Another instance is already running and the lock looks stale, "
                    "but it cannot be taken over. Exiting."
                )
        else:
            exit("Another instance is already running. Exiting.")

    # We have the lock now (either initially or after taking over a stale lock).
    # Store the acquisition timestamp in the file so future runs can detect staleness.
    # noinspection PyBroadException
    try:
        _lock_file_handle.seek(0)
        _lock_file_handle.truncate()
        _lock_file_handle.write(str(int(time.time())))
        _lock_file_handle.flush()
        os.fsync(_lock_file_handle.fileno())
    except Exception:
        # Lock itself is held even if we fail to update the timestamp.
        pass

    return _lock_file_handle


def release_singleton_lock():
    global _lock_file_handle

    if _lock_file_handle is not None:
        try:
            fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_UN)
        finally:
            _lock_file_handle.close()
            _lock_file_handle = None


def load_yaml_or_exit(file_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)

    if not os.path.isfile(path):
        exit(f"{path} not found")

    with open(path, 'r') as file:
        return yaml.safe_load(file)


@runtime_checkable
class Writer(Protocol):
    def write(self, __s: str) -> int: ...


def load_cache(path: str):
    if not os.path.isfile(path):
        return {}

    # noinspection PyBroadException
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(path: str, cache: dict) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        writer = cast(Writer, f)
        json.dump(cache, writer, indent=2)
