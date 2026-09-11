import io
import unittest
from contextlib import redirect_stdout

import run


class MisconfiguredCheckIsReportedTest(unittest.TestCase):
    """A check with an incomplete config used to be skipped with a line on stdout.

    Under cron nobody reads stdout, so the check simply never ran and nothing said so.
    It must be recorded as a failure instead, like any other broken check.
    """

    def test_command_without_chats_is_recorded_as_failure(self):
        cache = {}

        with redirect_stdout(io.StringIO()):
            run.process_command({'command': 'echo hi'}, 'cmd_without_chats', cache)

        self.assertIn('cmd_without_chats', cache)
        entry = cache['cmd_without_chats']
        self.assertEqual(1, entry['failed_attempts'])
        self.assertIn('tg_chats_to_notify', entry['last_error']['msg'])

    def test_command_without_command_field_is_recorded_as_failure(self):
        cache = {}

        with redirect_stdout(io.StringIO()):
            run.process_command({'tg_chats_to_notify': [1]}, 'cmd_without_command', cache)

        self.assertIn('cmd_without_command', cache)
        self.assertIn("'command'", cache['cmd_without_command']['last_error']['msg'])

    def test_site_without_url_is_recorded_as_failure(self):
        cache = {}

        with redirect_stdout(io.StringIO()):
            run.process_site({'tg_chats_to_notify': [1]}, 'site_without_url', cache)

        self.assertIn('site_without_url', cache)
        self.assertIn("'url'", cache['site_without_url']['last_error']['msg'])

    def test_valid_command_is_not_reported_as_misconfigured(self):
        cache = {}

        with redirect_stdout(io.StringIO()):
            run.process_command(
                {'command': 'echo hi', 'tg_chats_to_notify': [1], 'search_string': 'hi'},
                'good_cmd',
                cache,
            )

        self.assertEqual(0, cache['good_cmd']['failed_attempts'])


class ResolveChatIdsTest(unittest.TestCase):
    CONFIG = {
        'sites': {'a': {'url': 'https://example.com', 'tg_chats_to_notify': [111]}},
        'commands': {'b': {'command': 'true', 'tg_chats_to_notify': [222, 333]}},
    }

    def test_own_list_wins(self):
        self.assertEqual({'999'}, run.resolve_chat_ids({'tg_chats_to_notify': [999]}, self.CONFIG))

    def test_falls_back_to_every_chat_in_config(self):
        # The alert about a missing 'tg_chats_to_notify' would otherwise have nowhere to go
        self.assertEqual({'111', '222', '333'}, run.resolve_chat_ids({}, self.CONFIG))

    def test_collect_ignores_checks_without_the_field(self):
        config = {'commands': {'x': {'command': 'true'}, 'y': {'command': 'true', 'tg_chats_to_notify': [7]}}}
        self.assertEqual({'7'}, run.collect_all_chat_ids(config))


if __name__ == '__main__':
    unittest.main()
