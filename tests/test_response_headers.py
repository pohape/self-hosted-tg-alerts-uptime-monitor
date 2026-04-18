import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import run
from run import RequestMethod


class FakeResponse:
    def __init__(self, status_code=200, text='', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class ResponseHeadersValidationTest(unittest.TestCase):
    def test_validate_response_header_rules_accepts_contains_and_absent(self):
        rules = [
            {'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'},
            {'name': 'Server', 'absent': 'nginx/1.18.0'},
        ]

        self.assertIsNone(run.validate_response_header_rules(rules))

    def test_validate_response_header_rules_requires_name(self):
        rules = [{'contains': 'Basic realm="Admin"'}]

        self.assertEqual(
            "rule #1 must have a non-empty string 'name'",
            run.validate_response_header_rules(rules),
        )

    def test_validate_response_header_rules_requires_exactly_one_matcher(self):
        rules = [{'name': 'WWW-Authenticate', 'contains': 'Basic', 'absent': 'Digest'}]

        self.assertEqual(
            'rule #1 must define exactly one of: contains, absent',
            run.validate_response_header_rules(rules),
        )

    def test_validate_response_header_rules_rejects_wrong_type(self):
        self.assertEqual(
            'must be a list of header rules',
            run.validate_response_header_rules({'name': 'WWW-Authenticate', 'contains': 'Basic'}),
        )

    def test_validate_response_headers_passes_when_contains_matches(self):
        rules = [{'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'}]
        headers = {'www-authenticate': 'Basic realm="Admin"'}

        self.assertIsNone(run.validate_response_headers(headers, rules))

    def test_validate_response_headers_fails_when_expected_header_missing(self):
        rules = [{'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'}]

        self.assertEqual(
            "Expected header 'WWW-Authenticate' containing 'Basic realm=\"Admin\"', but header was missing.",
            run.validate_response_headers({}, rules),
        )

    def test_validate_response_headers_absent_passes_when_header_missing(self):
        rules = [{'name': 'Server', 'absent': 'nginx'}]

        self.assertIsNone(run.validate_response_headers({}, rules))

    def test_validate_response_headers_absent_fails_when_substring_present(self):
        rules = [{'name': 'Server', 'absent': 'nginx'}]

        self.assertEqual(
            "Forbidden 'nginx' found in header 'Server': 'nginx/1.18.0'.",
            run.validate_response_headers({'Server': 'nginx/1.18.0'}, rules),
        )


class ResponseHeadersRequestFlowTest(unittest.TestCase):
    @patch('run.get_certificate_expiry_with_cache', return_value={'error': None, 'is_valid': True, 'time_taken': 0})
    @patch('run.requests.head')
    def test_perform_request_validates_headers_for_head_requests(self, mock_head, _mock_tls):
        mock_head.return_value = FakeResponse(
            status_code=401,
            headers={'www-authenticate': 'Basic realm="Admin"'},
        )

        error = run.perform_request(
            url='https://example.com/',
            follow_redirects=False,
            method=RequestMethod.HEAD,
            status_codes=[401],
            search='',
            absent='',
            response_header_rules=[{'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'}],
            timeout=5,
            post_data=None,
            headers={},
        )

        self.assertIsNone(error)

    @patch('run.get_certificate_expiry_with_cache', return_value={'error': None, 'is_valid': True, 'time_taken': 0})
    @patch('run.requests.get')
    def test_perform_request_keeps_body_validation_when_response_headers_are_present(self, mock_get, _mock_tls):
        mock_get.return_value = FakeResponse(
            status_code=200,
            text='Welcome to the admin page',
            headers={'WWW-Authenticate': 'Basic realm="Admin"'},
        )

        error = run.perform_request(
            url='https://example.com/',
            follow_redirects=False,
            method=RequestMethod.GET,
            status_codes=[200],
            search='Welcome',
            absent='Forbidden',
            response_header_rules=[{'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'}],
            timeout=5,
            post_data=None,
            headers={},
        )

        self.assertIsNone(error)


class CheckConfigResponseHeadersTest(unittest.TestCase):
    def test_check_config_reports_response_headers_successfully(self):
        config = {
            'telegram_bot_token': 'token',
            'sites': {
                'admin_login': {
                    'url': 'https://example.com/',
                    'method': 'HEAD',
                    'status_code': 401,
                    'response_headers': [
                        {'name': 'WWW-Authenticate', 'contains': 'Basic realm="Admin"'},
                    ],
                    'tg_chats_to_notify': ['123'],
                }
            },
            'commands': {},
        }

        stdout = io.StringIO()

        with redirect_stdout(stdout):
            run.check_config(config)

        self.assertIn("response_headers: WWW-Authenticate contains 'Basic realm=\"Admin\"'", stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
