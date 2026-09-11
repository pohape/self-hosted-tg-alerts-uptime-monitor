import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import run


class CacheWriteCheckPreservesStateTest(unittest.TestCase):
    """`check_writing_to_cache` proves the cache is writable. It must not empty it.

    It used to write `{}`. That reset every check's `failed_attempts` and its
    "already notified" flag, so running `--check-config`, `--test-notifications`
    or `--id-bot-mode` quietly degraded monitoring: an outage in progress
    restarted its countdown to `notify_after_attempt`, and an outage already
    reported could be reported a second time. Nothing looked broken afterwards,
    which is exactly why it went unnoticed.
    """

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        self._original = run.CACHE_PATH
        run.CACHE_PATH = self.path

    def tearDown(self):
        run.CACHE_PATH = self._original
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _run(self):
        with redirect_stdout(io.StringIO()):
            return run.check_writing_to_cache()

    def test_existing_state_survives_the_check(self):
        state = {
            'some_site': {
                'last_checked_at': 1789000000,
                'last_error': {'msg': 'timeout'},
                'notified_down': 1789000001,
                'notified_restore': None,
                'failed_attempts': 4,
            }
        }
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(state, f)

        self.assertTrue(self._run())

        with open(self.path, encoding='utf-8') as f:
            self.assertEqual(state, json.load(f))

    def test_missing_file_is_created_and_check_passes(self):
        os.unlink(self.path)

        self.assertTrue(self._run())

        self.assertTrue(os.path.exists(self.path))
        with open(self.path, encoding='utf-8') as f:
            self.assertEqual({}, json.load(f))

    def test_unwritable_path_is_reported_as_failure(self):
        run.CACHE_PATH = os.path.join(self.path, 'not-a-directory', 'cache.json')

        self.assertFalse(self._run())


if __name__ == '__main__':
    unittest.main()
