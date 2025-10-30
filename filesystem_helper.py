import fcntl
import json
import os
from typing import Optional, TextIO
from typing import Protocol, runtime_checkable, cast

import yaml

_lock_file_handle: Optional[TextIO] = None


def acquire_singleton_lock(lock_path: str):
    global _lock_file_handle
    _lock_file_handle = open(lock_path, "w")

    try:
        fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        exit("Another instance is already running. Exiting.")

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

    with open(path, 'r') as f:
        return json.load(f)


def save_cache(path: str, cache: dict) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        writer = cast(Writer, f)
        json.dump(cache, writer, indent=2)
