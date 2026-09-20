"""Bot API calls must survive the loss of one mirror.

The monitor's reason to exist is telling you that something died. When it
watches the very machine that hosts its Bot API mirror, a single configured
host makes the most important outage the one it cannot report: the mirror goes
down together with the machine, and the alert has nowhere to go.

So `telegram_api_host` accepts a list, and a call walks it until one host
answers. These tests pin what counts as "does not answer" — the distinction is
the whole design:

  * transport error, 5xx, non-JSON body  -> that mirror is broken, try the next
  * 4xx with a JSON body                 -> Telegram ANSWERED; repeating the
                                            question elsewhere repeats the answer
"""
import unittest
from unittest.mock import patch

import requests

import telegram_helper as th

CONFIG_ONE = {'telegram_bot_token': 'T', 'telegram_api_host': 'first.example'}
CONFIG_TWO = {'telegram_bot_token': 'T',
              'telegram_api_host': ['first.example', 'second.example']}


class _Response:
    def __init__(self, status_code=200, payload=None, body_is_json=True):
        self.status_code = status_code
        self._payload = payload if payload is not None else {'ok': True}
        self._body_is_json = body_is_json

    def json(self):
        if not self._body_is_json:
            raise ValueError('Expecting value: line 1 column 1 (char 0)')

        return self._payload


class HostListTest(unittest.TestCase):
    def test_single_host_stays_a_single_host(self):
        """The old string form must keep working: it is what every existing
        config out there has."""
        self.assertEqual(['first.example'], th.get_api_hosts(CONFIG_ONE))

    def test_list_is_kept_in_order(self):
        """Order IS the preference — the first host is the primary one."""
        self.assertEqual(['first.example', 'second.example'], th.get_api_hosts(CONFIG_TWO))

    def test_missing_key_means_the_official_host(self):
        self.assertEqual(['api.telegram.org'], th.get_api_hosts({}))

    def test_schemes_blanks_and_duplicates_are_cleaned(self):
        """A config written by hand carries scheme, slash and repetition."""
        hosts = th.get_api_hosts({'telegram_api_host':
                                  ['  ', None, 'https://x.example/', 'x.example', 'http://y.example']})

        self.assertEqual(['x.example', 'y.example'], hosts)

    def test_empty_list_falls_back_to_the_official_host(self):
        """An unreachable configuration is worse than the default."""
        self.assertEqual(['api.telegram.org'], th.get_api_hosts({'telegram_api_host': []}))

    def test_base_url_is_the_primary_host(self):
        self.assertEqual('https://first.example', th.get_api_base(CONFIG_TWO))


class FailoverTest(unittest.TestCase):
    def _run(self, side_effect, config=None):
        with patch.object(th.requests, 'request', side_effect=side_effect) as call:
            return th.api_request(config or CONFIG_TWO, 'GET', '/getMe'), call

    def test_transport_error_moves_to_the_next_host(self):
        """The case this was built for: the machine hosting mirror #1 is gone."""
        payload, call = self._run([requests.ConnectionError('down'), _Response()])

        self.assertEqual({'ok': True}, payload)
        self.assertEqual(2, call.call_count)
        self.assertIn('second.example', call.call_args_list[1][0][1])

    def test_5xx_moves_to_the_next_host(self):
        """Our own reverse proxy answers 502 exactly while its backend dies."""
        payload, call = self._run([_Response(status_code=502), _Response()])

        self.assertEqual({'ok': True}, payload)
        self.assertEqual(2, call.call_count)

    def test_non_json_body_moves_to_the_next_host(self):
        """A proxy error page is HTML, and HTML is not an answer."""
        payload, call = self._run([_Response(body_is_json=False), _Response()])

        self.assertEqual({'ok': True}, payload)
        self.assertEqual(2, call.call_count)

    def test_4xx_with_json_is_an_answer_not_a_failure(self):
        """Telegram says 'wrong token' with 401 — asking a second mirror would
        only get the same 401, and would hide the real reason behind a
        'all hosts failed' error."""
        error = {'ok': False, 'error_code': 401, 'description': 'Unauthorized'}
        payload, call = self._run([_Response(status_code=401, payload=error)])

        self.assertEqual(error, payload)
        self.assertEqual(1, call.call_count)

    def test_every_host_failing_raises_the_last_error(self):
        """Silence about a broken notification channel defeats the tool."""
        with self.assertRaises(requests.RequestException):
            self._run([requests.ConnectionError('one'), requests.ConnectionError('two')])

    def test_single_host_config_does_not_retry(self):
        """One host means one attempt — no hidden second call."""
        with self.assertRaises(requests.RequestException):
            self._run([requests.ConnectionError('down')], config=CONFIG_ONE)

    def test_every_call_carries_a_timeout(self):
        """Without a deadline a hung mirror blocks forever and the backup host
        never gets its turn: failover without a timeout is failover on paper."""
        _, call = self._run([_Response()])

        self.assertEqual(th.API_TIMEOUT_SEC, call.call_args_list[0][1]['timeout'])

    def test_long_poll_keeps_its_own_deadline(self):
        """getUpdates waits for up to 100 s BY DESIGN; the HTTP deadline must
        outlive it, or normal waiting would look like a dead host."""
        with patch.object(th.requests, 'request', return_value=_Response()) as call:
            th.get_updates(CONFIG_TWO)

        self.assertEqual(th.LONG_POLL_TIMEOUT_SEC, call.call_args_list[0][1]['timeout'])
        self.assertGreater(th.LONG_POLL_TIMEOUT_SEC, 100)


if __name__ == '__main__':
    unittest.main()


class TokenIsNeverPrintedTest(unittest.TestCase):
    """The token lives in the URL path of every call, so whatever quotes a
    failed request quotes the credential with it — and failover messages quote
    failed requests by definition. Caught on a live run: the first warning
    printed the full URL, token included, straight into cron mail.
    """

    def test_failover_warning_masks_the_token(self):
        import io
        from contextlib import redirect_stdout

        # Токен правдоподобной формы, а не односимвольный `T` из общего стенда:
        # с одной буквой маскировка съела бы каждую `T` в тексте, и тест мерил
        # бы собственную выдумку вместо поведения.
        token = '8531861837:AAHFAKEfakeFAKEfakeFAKEfakeFAKEfake'
        config = dict(CONFIG_TWO, telegram_bot_token=token)
        # Настоящий requests кладёт в текст ошибки полный URL — воспроизводим
        # это дословно, иначе тест мерил бы удобную выдумку.
        blown = requests.ConnectionError(
            f"HTTPSConnectionPool(host='first.example', port=443): "
            f"Max retries exceeded with url: /bot{token}/getMe")
        out = io.StringIO()

        with redirect_stdout(out), patch.object(th.requests, 'request',
                                                side_effect=[blown, _Response()]):
            th.api_request(config, 'GET', '/getMe')

        self.assertNotIn(token, out.getvalue())
        self.assertIn('<token>', out.getvalue())

    def test_masking_survives_a_missing_token(self):
        self.assertEqual('boom', th.hide_token('boom', ''))
