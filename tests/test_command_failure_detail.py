import unittest

import run


class CommandFailureDetailTest(unittest.TestCase):
    """A failing command's alert must say what failed.

    Health checks print their verdict (``DOWN 1/2: …``) to stdout and exit 1; the
    alert used to carry only stderr, i.e. nothing but the exit code.
    """

    def test_stdout_is_reported_when_stderr_is_empty(self):
        error = run.perform_command('echo "DOWN 1/2: bot=inactive"; exit 1', 5, 'OK', None, None)

        self.assertEqual('Command exited with code 1: DOWN 1/2: bot=inactive', error)

    def test_stderr_wins_when_present(self):
        error = run.perform_command('echo out; echo boom >&2; exit 2', 5, 'OK', None, None)

        self.assertEqual('Command exited with code 2: boom', error)

    def test_success_is_unchanged(self):
        self.assertIsNone(run.perform_command('echo OK all', 5, 'OK', None, None))


if __name__ == '__main__':
    unittest.main()
