import unittest

import run


class CurlHidesCredentialsTest(unittest.TestCase):
    """The cURL command of an alert goes to Telegram: credential headers keep their name, lose their value."""

    def test_authorization_value_is_hidden(self):
        curl = run.generate_curl_command('https://example.com/api/ping', False, 'GET', 10,
                                         headers={'Authorization': 'Basic c2VjcmV0OnNlY3JldA=='})

        self.assertNotIn('c2VjcmV0OnNlY3JldA==', curl)
        self.assertIn("-H 'Authorization: <hidden>'", curl)

    def test_header_name_case_does_not_matter(self):
        curl = run.generate_curl_command('https://example.com/', False, 'GET', 5,
                                         headers={'x-API-key': 'k-123', 'Cookie': 'sid=1'})

        self.assertNotIn('k-123', curl)
        self.assertNotIn('sid=1', curl)

    def test_other_headers_are_shown(self):
        curl = run.generate_curl_command('https://example.com/', False, 'GET', 5,
                                         headers={'Content-Type': 'application/json'})

        self.assertIn("-H 'Content-Type: application/json'", curl)


if __name__ == '__main__':
    unittest.main()
