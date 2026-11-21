"""Domain registration expiry checks.

A domain expired and nobody noticed for five days: the sites on it went down,
but "site is down" does not say "pay the registrar", and by the time anyone
looked, the free-date was getting close. These tests pin the parsing of every
data source the monitor uses (with answers captured from the real servers),
the alert thresholds and the config validation. Nothing here touches the network.
"""
import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from unittest.mock import patch

import domain_helper as dh
import run
from console_helper import Color

NOW = datetime(2026, 11, 21, 13, 0, tzinfo=timezone.utc)

# whois.tcinet.ru, 2026-11-21 (klinika-zhigalovyh.rf, five days after it expired)
TCI_EXPIRED = """% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf (in Russian)
% https://tcinet.ru/documents/whois_su.pdf (in Russian)

domain:        XN----7SBBIDRLADOCJJTY7IRE.XN--P1AI
nserver:       dnsproxy1.fm.nic.ru.
nserver:       dnsproxy2.fm.nic.ru.
state:         REGISTERED, DELEGATED, UNVERIFIED
person:        Private Person
registrar:     RUCENTER-RF
admin-contact: https://www.nic.ru/whois
created:       2020-11-16T10:15:25Z
paid-till:     2026-11-16T10:15:25Z
free-date:     2026-12-17
source:        TCI

Last updated on 2026-11-21T13:18:01Z
"""

TCI_NOT_FOUND = """% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf (in Russian)

No entries found for the selected source(s).

Last updated on 2026-11-21T13:18:01Z
"""

# whois.flexireg.net — the registry of regional third-level domains (spb.ru, msk.ru, com.ru, ...)
FLEXIREG = """Domain Name: zagrebskiy.spb.ru
Registry Domain ID: 20230429201342210134_78740ba5fbf3d760abb527e425747ecd_domain-FIR
Registrar WHOIS Server: whois.reg.ru
Registrar URL: https://www.reg.ru
Updated Date: 2026-04-14T21:03:45Z
Creation Date: 2023-04-29T20:13:41Z
Registry Expiry Date: 2027-04-29T20:13:41Z
Registrar: LLC Reg.ru
Registrar IANA ID: 1606
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Country: RU
Name Server: curt.ns.cloudflare.com
Name Server: zelda.ns.cloudflare.com
DNSSEC: unsignedDelegation
>>> Last update of WHOIS database: 2026-11-21T13:21:08Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

% By submitting a query to Whois Service
% you agree to abide by the following terms of use:
% http://flexireg.net/whois-terms_of_use.html (in Russian)
"""

FLEXIREG_NOT_FOUND = """  Domain not found.

>>> Last update of WHOIS database: 2026-11-21T13:21:09Z <<<
"""

# A registrar's whois (whois.reg.ru) gives a bare date.
REGISTRAR_DATE_ONLY = """domain:       ZAGREBSKIY.SPB.RU
state:        REGISTERED, DELEGATED
created:      2023-04-29
paid-till:    2027-04-29
source:       REGRU-RU
"""

# rdap.verisign.com, trimmed
RDAP_COM = {
    "objectClassName": "domain",
    "ldhName": "CAPTCHACODES.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2018-05-30T11:40:54Z"},
        {"eventAction": "expiration", "eventDate": "2027-05-30T11:40:54Z"},
        {"eventAction": "last changed", "eventDate": "2026-05-12T09:42:07Z"},
        {"eventAction": "last update of RDAP database", "eventDate": "2026-11-21T13:20:27Z"},
    ],
}

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
        [["example"], ["http://insecure.example/rdap/", "https://secure.example/rdap/"]],
    ]
}


def info(**overrides):
    base = {'domain': 'example.com', 'source': 'RDAP test', 'registered': True,
            'expires': datetime(2027, 5, 30, tzinfo=timezone.utc), 'delegated': None, 'state': None,
            'statuses': [], 'free_date': None, 'error': None}
    base.update(overrides)

    return base


class IdnTest(unittest.TestCase):
    def test_cyrillic_domain_becomes_punycode(self):
        self.assertEqual('xn----7sbbidrladocjjty7ire.xn--p1ai', dh.to_ascii('клиника-жигаловых.рф'))

    def test_case_and_trailing_dot_are_normalised(self):
        self.assertEqual('example.com', dh.to_ascii(' Example.COM. '))
        self.assertEqual('xn----7sbbidrladocjjty7ire.xn--p1ai', dh.to_ascii('КЛИНИКА-ЖИГАЛОВЫХ.РФ'))

    def test_punycode_round_trip(self):
        self.assertEqual('клиника-жигаловых.рф', dh.to_unicode('xn----7sbbidrladocjjty7ire.xn--p1ai'))

    def test_invalid_names_are_rejected(self):
        for bad in ('', 'localhost', 'https://example.com/', 'exa mple.com', '-bad.com', 'bad-.com',
                    '1.2.3.4', 'a..com', None, 42):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dh.to_ascii(bad)


class DataSourceTest(unittest.TestCase):
    def test_russian_second_level_goes_to_tci(self):
        for name in ('kgdrent.ru', 'xn----7sbbidrladocjjty7ire.xn--p1ai', 'example.su'):
            self.assertEqual('whois.tcinet.ru', dh.pick_whois_server(name), name)

    def test_regional_third_level_goes_to_flexireg(self):
        for name in ('zagrebskiy.spb.ru', 'mos.msk.ru', 'test.com.ru'):
            self.assertEqual('whois.flexireg.net', dh.pick_whois_server(name), name)

    def test_mskix_third_level_zones(self):
        for name in ('test.org.ru', 'mail.net.ru', 'test.pp.ru'):
            self.assertEqual('whois.nic.net.ru', dh.pick_whois_server(name), name)

    def test_other_tlds_use_rdap(self):
        self.assertIsNone(dh.pick_whois_server('captchacodes.com'))
        self.assertIn('RDAP', dh.describe_source('captchacodes.com'))

    def test_explicit_whois_server_wins(self):
        self.assertEqual('whois whois.reg.ru', dh.describe_source('zagrebskiy.spb.ru', 'whois.reg.ru'))

    def test_bootstrap_lookup_prefers_https_and_longest_match(self):
        self.assertEqual('https://rdap.verisign.com/com/v1/', dh.find_rdap_base(BOOTSTRAP, 'antcpt.com'))
        self.assertEqual('https://secure.example/rdap/', dh.find_rdap_base(BOOTSTRAP, 'a.b.example'))
        self.assertIsNone(dh.find_rdap_base(BOOTSTRAP, 'example.de'))
        # "com" must not match "notcom"
        self.assertIsNone(dh.find_rdap_base(BOOTSTRAP, 'example.notcom'))


class ParseDatetimeTest(unittest.TestCase):
    def test_formats(self):
        utc = timezone.utc
        self.assertEqual(datetime(2026, 11, 16, 10, 15, 25, tzinfo=utc), dh.parse_datetime('2026-11-16T10:15:25Z'))
        self.assertEqual(datetime(2027, 4, 29, tzinfo=utc), dh.parse_datetime('2027-04-29'))
        self.assertEqual(datetime(2027, 1, 1, 9, 0, tzinfo=utc), dh.parse_datetime('2027-01-01T12:00:00+03:00'))
        self.assertEqual(datetime(2027, 1, 1, 0, 0, 1, tzinfo=utc), dh.parse_datetime('2027-01-01T00:00:01.123Z'))
        self.assertIsNone(dh.parse_datetime('soon'))
        self.assertIsNone(dh.parse_datetime('2027-13-45'))


class ParseWhoisTest(unittest.TestCase):
    def test_tci_answer(self):
        result = dh.parse_whois(TCI_EXPIRED, 'xn----7sbbidrladocjjty7ire.xn--p1ai', 'whois whois.tcinet.ru')
        self.assertTrue(result['registered'])
        self.assertTrue(result['delegated'])
        self.assertEqual(datetime(2026, 11, 16, 10, 15, 25, tzinfo=timezone.utc), result['expires'])
        self.assertEqual('2026-12-17', result['free_date'])
        self.assertEqual('REGISTERED, DELEGATED, UNVERIFIED', result['state'])
        self.assertIsNone(result['error'])

    def test_tci_not_delegated(self):
        text = TCI_EXPIRED.replace('REGISTERED, DELEGATED, UNVERIFIED', 'REGISTERED, NOT DELEGATED, VERIFIED')
        self.assertFalse(dh.parse_whois(text, 'x.ru', 's')['delegated'])

    def test_tci_not_found(self):
        result = dh.parse_whois(TCI_NOT_FOUND, 'nope.ru', 's')
        self.assertFalse(result['registered'])
        self.assertIsNone(result['error'])

    def test_flexireg_answer(self):
        result = dh.parse_whois(FLEXIREG, 'zagrebskiy.spb.ru', 'whois whois.flexireg.net')
        self.assertTrue(result['registered'])
        self.assertIsNone(result['delegated'])
        self.assertEqual(datetime(2027, 4, 29, 20, 13, 41, tzinfo=timezone.utc), result['expires'])
        self.assertEqual(1, len(result['statuses']))

    def test_flexireg_not_found(self):
        self.assertFalse(dh.parse_whois(FLEXIREG_NOT_FOUND, 'nope.spb.ru', 's')['registered'])

    def test_registrar_date_only(self):
        result = dh.parse_whois(REGISTRAR_DATE_ONLY, 'zagrebskiy.spb.ru', 's')
        self.assertEqual(datetime(2027, 4, 29, tzinfo=timezone.utc), result['expires'])

    def test_garbage_is_a_lookup_error_not_a_verdict(self):
        result = dh.parse_whois('%% rate limit\nYou have exceeded allowed connection rate.\n', 'x.ru', 's')
        self.assertIsNone(result['registered'])
        self.assertIn('exceeded', result['error'])
        self.assertIn('empty', dh.parse_whois('', 'x.ru', 's')['error'])


class ParseRdapTest(unittest.TestCase):
    def test_expiration_event(self):
        result = dh.parse_rdap(RDAP_COM, 'captchacodes.com', 'RDAP x')
        self.assertTrue(result['registered'])
        self.assertEqual(datetime(2027, 5, 30, 11, 40, 54, tzinfo=timezone.utc), result['expires'])
        self.assertEqual(['client transfer prohibited'], result['statuses'])

    def test_missing_expiration_is_an_error(self):
        data = dict(RDAP_COM, events=[{"eventAction": "registration", "eventDate": "2018-05-30T11:40:54Z"}])
        self.assertIn('no expiration', dh.parse_rdap(data, 'x.com', 's')['error'])

    def test_error_object_404(self):
        self.assertFalse(dh.parse_rdap({'errorCode': 404}, 'x.com', 's')['registered'])

    def test_rdap_http_404_means_not_registered(self):
        class Resp:
            status_code = 404

        with patch.object(dh, 'load_rdap_bootstrap', return_value=BOOTSTRAP), \
                patch.object(dh.requests, 'get', return_value=Resp()) as get:
            result = dh.lookup_rdap('nope-nope.com', 5)

        self.assertFalse(result['registered'])
        self.assertEqual('https://rdap.verisign.com/com/v1/domain/nope-nope.com', get.call_args[0][0])

    def test_tld_without_rdap_asks_for_whois_server(self):
        with patch.object(dh, 'load_rdap_bootstrap', return_value=BOOTSTRAP):
            self.assertIn('whois_server', dh.lookup_rdap('example.de', 5)['error'])


class BootstrapCacheTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp()
        os.close(fd)

        with open(self.path, 'w') as f:
            json.dump(BOOTSTRAP, f)

    def tearDown(self):
        os.unlink(self.path)

    def test_fresh_cache_is_used_without_a_request(self):
        with patch.object(dh.requests, 'get') as get:
            self.assertEqual(BOOTSTRAP, dh.load_rdap_bootstrap(5, self.path))

        get.assert_not_called()

    def test_stale_cache_survives_a_failed_refresh(self):
        old = time.time() - dh.RDAP_BOOTSTRAP_MAX_AGE - 10
        os.utime(self.path, (old, old))

        with patch.object(dh.requests, 'get', side_effect=dh.requests.exceptions.ConnectionError('down')):
            self.assertEqual(BOOTSTRAP, dh.load_rdap_bootstrap(5, self.path))


class EvaluateTest(unittest.TestCase):
    def test_healthy_domain(self):
        self.assertIsNone(dh.evaluate(info(), 30, NOW))

    def test_expires_within_warn_days(self):
        message = dh.evaluate(info(expires=datetime(2026, 12, 11, 13, 0, tzinfo=timezone.utc)), 30, NOW)
        self.assertIn('expires in 20 days', message)
        self.assertIn('2026-12-11', message)

    def test_exactly_warn_days_left_is_fine(self):
        self.assertIsNone(dh.evaluate(info(expires=datetime(2026, 12, 21, 13, 0, tzinfo=timezone.utc)), 30, NOW))

    def test_expired_domain(self):
        result = dh.parse_whois(TCI_EXPIRED, 'xn----7sbbidrladocjjty7ire.xn--p1ai', 'whois whois.tcinet.ru')
        message = dh.evaluate(result, 30, NOW)
        self.assertIn('EXPIRED on 2026-11-16 (5 days ago)', message)
        self.assertIn('клиника-жигаловых.рф', message)
        self.assertIn('2026-12-17', message)

    def test_not_registered(self):
        self.assertIn('not registered', dh.evaluate(info(registered=False, expires=None), 30, NOW))

    def test_not_delegated(self):
        message = dh.evaluate(info(delegated=False, state='REGISTERED, NOT DELEGATED'), 30, NOW)
        self.assertIn('not delegated', message)

    def test_hold_status(self):
        message = dh.evaluate(info(statuses=['clientHold https://icann.org/epp#clientHold']), 30, NOW)
        self.assertIn('clientHold', message)

    def test_lookup_failure(self):
        self.assertIn('lookup failed', dh.evaluate(info(registered=None, expires=None, error='timed out'), 30, NOW))


class DomainConfigValidationTest(unittest.TestCase):
    def report_for(self, config):
        report = {}
        run.check_domains_config(config, report)

        return report

    def test_valid_entry(self):
        report = self.report_for({'domains': {'klinika': {
            'domain': 'клиника-жигаловых.рф', 'warn_days': 30, 'schedule': '0 9 * * *',
            'notify_after_attempt': 2, 'tg_chats_to_notify': [123]}}})
        self.assertEqual({}, report['klinika'][Color.ERROR])
        self.assertIn('xn----7sbbidrladocjjty7ire.xn--p1ai', report['klinika'][Color.SUCCESS]['domain'])
        self.assertIn('whois.tcinet.ru', report['klinika'][Color.SUCCESS]['domain'])

    def test_errors(self):
        report = self.report_for({
            'sites': {'shared': {}},
            'commands': {'cmd': {}},
            'domains': {
                'shared': {'domain': 'example.com', 'tg_chats_to_notify': [1]},
                'cmd': {'domain': 'example.com', 'tg_chats_to_notify': [1]},
                'bad': {'domain': 'https://example.com/', 'warn_days': 0, 'schedule': '61 * * * *',
                        'notify_after_attempt': 'two', 'tg_chats_to_notify': ['abc'], 'typo': 1},
                'empty': {},
            }})
        self.assertIn('site', report['shared'][Color.ERROR]['name'])
        self.assertIn('command', report['cmd'][Color.ERROR]['name'])
        errors = report['bad'][Color.ERROR]
        self.assertEqual({'domain', 'warn_days', 'schedule', 'notify_after_attempt', 'tg_chats_to_notify'},
                         set(errors))
        self.assertIn('typo', report['bad'][Color.WARNING])
        self.assertEqual({'domain', 'tg_chats_to_notify'}, set(report['empty'][Color.ERROR]))

    def test_no_domains_section_changes_nothing(self):
        self.assertEqual({}, self.report_for({'sites': {}}))
        self.assertEqual({}, self.report_for({'domains': None}))

    def test_full_check_config_runs_without_sites(self):
        with redirect_stdout(io.StringIO()) as out:
            run.check_config({'domains': {'d': {'domain': 'example.com', 'tg_chats_to_notify': [1]}}})

        self.assertIn('=== d ===', out.getvalue())


class DomainRunTest(unittest.TestCase):
    CONFIG = {'domains': {'klinika': {'domain': 'клиника-жигаловых.рф', 'notify_after_attempt': 1,
                                      'tg_chats_to_notify': [42]}}}

    def test_expired_domain_is_recorded_and_alerted(self):
        cache = {}
        result = dh.parse_whois(TCI_EXPIRED, 'xn----7sbbidrladocjjty7ire.xn--p1ai', 'whois whois.tcinet.ru')

        with redirect_stdout(io.StringIO()), patch.object(dh, 'get_domain_expiry', return_value=result) as lookup:
            run.process_domain(self.CONFIG['domains']['klinika'], 'klinika', cache)

        lookup.assert_called_once_with('xn----7sbbidrladocjjty7ire.xn--p1ai', 10.0, None)
        self.assertEqual(1, cache['klinika']['failed_attempts'])
        self.assertIn('EXPIRED', cache['klinika']['last_error']['msg'])
        self.assertEqual('2026-11-16T10:15:25+00:00', cache['klinika']['domain_expires_at'])

        sent = []
        messages = run.load_yaml_or_exit(run.MESSAGES_PATH)

        with redirect_stdout(io.StringIO()), \
                patch.object(run.telegram_helper, 'send_message', side_effect=lambda c, chat, m: sent.append((chat, m))), \
                patch.object(run, 'get_server_info', return_value='SERVER'):
            run.process_cache(cache, self.CONFIG, messages)

        self.assertEqual(1, len(sent))
        self.assertEqual('42', sent[0][0])
        self.assertIn('клиника\\-жигаловых\\.рф', sent[0][1])
        self.assertIn('whois whois\\.tcinet\\.ru', sent[0][1])
        self.assertTrue(cache['klinika']['notified_down'])

        with patch.object(run, 'get_server_info', return_value='SERVER'):
            summary = run.generate_summary_msg(messages, cache, self.CONFIG)

        self.assertIn('klinika', summary)

    def test_missing_domain_field_is_a_failure(self):
        cache = {}

        with redirect_stdout(io.StringIO()):
            run.process_domain({'tg_chats_to_notify': [1]}, 'nodomain', cache)

        self.assertIn("'domain'", cache['nodomain']['last_error']['msg'])

    def test_failing_domain_is_retried_hourly_not_every_minute(self):
        now = int(time.time())
        cache = {'d': {'last_error': {'msg': 'x'}, 'last_checked_at': now - 600, 'failed_attempts': 1}}
        never = '0 0 1 1 *' if datetime.now().strftime('%m%d') != '0101' else '0 0 2 2 *'

        self.assertIsNone(run._should_run_check('d', never, cache, False, retry_interval=3600))
        cache['d']['last_checked_at'] = now - 3700
        self.assertEqual('down', run._should_run_check('d', never, cache, False, retry_interval=3600))
        # sites and commands keep their every-minute retry
        cache['d']['last_checked_at'] = now - 60
        self.assertEqual('down', run._should_run_check('d', never, cache, False))
        self.assertEqual('force', run._should_run_check('d', never, cache, True, retry_interval=3600))

    def test_absent_domains_section_runs_nothing_new(self):
        class Args:
            debug = False

        with redirect_stdout(io.StringIO()), patch.object(run, 'process_domain') as process:
            run.process_each_site(Args(), {'sites': {}, 'commands': {}}, {}, force=True)

        process.assert_not_called()

    def test_all_chat_ids_include_domains(self):
        self.assertEqual({'42'}, run.collect_all_chat_ids(self.CONFIG))


if __name__ == '__main__':
    unittest.main()
