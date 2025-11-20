#!/usr/bin/env python3
"""
Small diagnostic tool to check whether the monitoring lock file is currently held.

It works like this:
  - If the lock file does not exist -> reports "no lock".
  - If the lock file exists:
      * Tries to acquire an exclusive non-blocking flock().
      * If it succeeds -> lock is NOT held by another process (we immediately release it).
      * If it fails with BlockingIOError -> lock IS held by another process.

This script does not change the lock file contents and does not deliberately touch mtime.
"""

import fcntl
import os
import sys

from run import LOCK_PATH


def check_lock(lock_path: str) -> int:
    """
    Check whether a lock on `lock_path` is currently held by another process.

    Return codes:
      0 -> lock is NOT held (or file does not exist)
      1 -> lock IS held by another process
      2 -> some error occurred while checking
    """
    print(f"[LOCK CHECK] Using lock file: {lock_path}")

    if not os.path.exists(lock_path):
        print("[LOCK CHECK] Lock file does not exist. Lock is NOT held.")

        return 0

    try:
        # Open read-only, to avoid modifying the file or its mtime.
        f = open(lock_path, "r")
    except OSError as e:
        print(f"[LOCK CHECK] Failed to open lock file: {e!r}")

        return 2

    try:
        print("[LOCK CHECK] Trying flock(LOCK_EX | LOCK_NB)...")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("[LOCK CHECK] flock() succeeded.")
        print("[LOCK CHECK] This means no other process currently holds the lock.")
        # Immediately release it back
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        print("[LOCK CHECK] Lock released again by this diagnostic script.")

        return 0
    except BlockingIOError as e:
        print("[LOCK CHECK] flock() raised BlockingIOError.")
        print("[LOCK CHECK] This means another process currently holds the lock.")
        print(f"[LOCK CHECK] Details: {e!r}")

        return 1
    except OSError as e:
        print(f"[LOCK CHECK] Unexpected error during flock(): {e!r}")

        return 2
    finally:
        # noinspection PyBroadException
        try:
            f.close()
        except Exception:
            pass


def main() -> None:
    exit_code = check_lock(LOCK_PATH)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
