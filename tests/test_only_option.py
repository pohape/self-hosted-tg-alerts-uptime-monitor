"""--only NAME runs just the named checks, right now, through the normal run path.

Everything else must be skipped, and the cache entries of the skipped checks must stay
exactly as they were, so a manual run never disturbs what cron is tracking.
"""
import copy
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

import run

CONFIG = {
    'telegram_bot_token': 'x',
    'summary_schedule': '* * * * *',
    'sites': {
        'site_a': {'url': 'https://a.example', 'tg_chats_to_notify': ['1'], 'schedule': '0 0 1 1 *'},
        'site_b': {'url': 'https://b.example', 'tg_chats_to_notify': ['1']},
    },
    'commands': {
        'cmd_a': {'command': 'true', 'tg_chats_to_notify': ['1'], 'schedule': '0 0 1 1 *'},
        'cmd_b': {'command': 'true', 'tg_chats_to_notify': ['1']},
    },
    'domains': {
        'dom_a': {'domain': 'a.example', 'tg_chats_to_notify': ['1']},
        'dom_b': {'domain': 'b.example', 'tg_chats_to_notify': ['1']},
    },
}

ARGS = SimpleNamespace(debug=False)


def _down_entry(attempts=3, checked_ago=60):
    return {
        'last_checked_at': int(time.time()) - checked_ago,
        'last_error': {'msg': 'boom', 'site_name': 'x', 'url': 'https://x.example'},
        'notified_down': None,
        'notified_restore': None,
        'failed_attempts': attempts,
    }


class ParseOnlyNamesTest(unittest.TestCase):
    def test_repeated_and_comma_separated(self):
        self.assertEqual(['a', 'b', 'c'], run.parse_only_names(['a', 'b, c', 'a', ' ,']))

    def test_unknown_names_are_reported_in_order(self):
        self.assertEqual(['nope', 'zzz'], run.find_unknown_check_names(['site_a', 'nope', 'dom_b', 'zzz'], CONFIG))
        self.assertEqual([], run.find_unknown_check_names(['site_a', 'cmd_b', 'dom_a'], CONFIG))


class ShouldRunTest(unittest.TestCase):
    def test_only_overrides_schedule_and_skips_others(self):
        self.assertEqual('only', run._should_run_check('site_a', '0 0 1 1 *', {}, False, only=['site_a']))
        self.assertIsNone(run._should_run_check('site_b', '* * * * *', {}, False, only=['site_a']))

    def test_other_failing_check_is_not_retried(self):
        cache = {'site_b': _down_entry()}
        self.assertIsNone(run._should_run_check('site_b', '* * * * *', cache, False, only=['site_a']))

    def test_only_bypasses_domain_retry_interval(self):
        cache = {'dom_a': _down_entry(checked_ago=10)}
        self.assertIsNone(run._should_run_check('dom_a', '0 9 * * *', cache, False,
                                                retry_interval=run.DOMAIN_RETRY_SECONDS))
        self.assertEqual('only', run._should_run_check('dom_a', '0 9 * * *', cache, False,
                                                       retry_interval=run.DOMAIN_RETRY_SECONDS, only=['dom_a']))


class ProcessEachSiteOnlyTest(unittest.TestCase):
    def _run(self, only, cache):
        calls = []

        def fake(kind):
            return lambda cfg, name, c: calls.append((kind, name)) or run._update_cache(name, c, None, None)

        with redirect_stdout(io.StringIO()), \
                patch.object(run, 'process_site', side_effect=fake('site')), \
                patch.object(run, 'process_command', side_effect=fake('command')), \
                patch.object(run, 'process_domain', side_effect=fake('domain')):
            count = run.process_each_site(ARGS, CONFIG, cache, only=only)

        return calls, count

    def test_selects_across_all_three_types(self):
        for name, kind in (('site_a', 'site'), ('cmd_a', 'command'), ('dom_a', 'domain')):
            with self.subTest(name=name):
                calls, count = self._run([name], {})
                self.assertEqual([(kind, name)], calls)
                self.assertEqual(1, count)

    def test_multiple_names(self):
        calls, count = self._run(['dom_b', 'site_a', 'cmd_b'], {})
        self.assertEqual([('site', 'site_a'), ('command', 'cmd_b'), ('domain', 'dom_b')], calls)
        self.assertEqual(3, count)

    def test_other_cache_entries_untouched(self):
        cache = {name: _down_entry() for name in ('site_a', 'site_b', 'cmd_b', 'dom_b')}
        before = copy.deepcopy(cache)

        calls, _ = self._run(['site_a'], cache)

        self.assertEqual([('site', 'site_a')], calls)
        self.assertIsNone(cache['site_a']['last_error'])
        for name in ('site_b', 'cmd_b', 'dom_b'):
            self.assertEqual(before[name], cache[name])


class MainOnlyTest(unittest.TestCase):
    """End to end through main(): same lock, same cache file, same alerting."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.tmp.name, 'cache.json')
        real_load = run.load_yaml_or_exit
        self.patches = [
            patch.object(run, 'CACHE_PATH', self.cache_path),
            patch.object(run, 'LOCK_PATH', os.path.join(self.tmp.name, 'lock')),
            patch.object(run, 'load_yaml_or_exit',
                         side_effect=lambda f: CONFIG if f == run.CONFIG_PATH else real_load(f)),
            patch.object(run, 'get_server_info', return_value='SERVER'),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _main(self, *argv):
        with patch.object(sys, 'argv', ['run.py', *argv]), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            run.main()
        return out.getvalue() + err.getvalue()

    def test_unknown_name_exits_nonzero_and_runs_nothing(self):
        with patch.object(run, 'process_site') as site, patch.object(run, 'process_command') as cmd, \
                patch.object(run, 'process_domain') as dom, \
                self.assertRaises(SystemExit) as ctx:
            self._main('--only', 'site_a,no_such_check')

        self.assertNotEqual(0, ctx.exception.code)
        site.assert_not_called()
        cmd.assert_not_called()
        dom.assert_not_called()
        self.assertFalse(os.path.exists(self.cache_path))

    def test_only_with_force_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self._main('--only', 'site_a', '--force')
        self.assertNotEqual(0, ctx.exception.code)

    def test_failing_check_counts_and_alerts_others_untouched(self):
        other = _down_entry(attempts=5)
        with open(self.cache_path, 'w') as f:
            json.dump({'site_b': other}, f)

        sent = []
        with patch.object(run, 'perform_request', return_value='Site is down'), \
                patch.object(run.telegram_helper, 'send_message',
                             side_effect=lambda c, chat, m: sent.append((chat, m))):
            self._main('--only', 'site_a')

        with open(self.cache_path) as f:
            cache = json.load(f)

        self.assertEqual(1, cache['site_a']['failed_attempts'])
        self.assertIsNotNone(cache['site_a']['notified_down'])
        # Only the DOWN alert for site_a: site_b's pending alert and the summary are not sent
        self.assertEqual(1, len(sent))
        self.assertIn('https://a.example', sent[0][1])
        self.assertEqual(other, cache['site_b'])
        self.assertEqual({'site_a', 'site_b'}, set(cache))


if __name__ == '__main__':
    unittest.main()
