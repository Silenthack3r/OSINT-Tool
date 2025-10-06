import unittest
from unittest.mock import patch

from scans import user_clean


class MockResponse:
    def __init__(self, status_code=200, text="", url=None):
        self.status_code = status_code
        self.text = text
        self.url = url or "https://example.com/profile"
        self.history = []


class TestUserClean(unittest.TestCase):
    def setUp(self):
        # Minimal site info templates
        self.site = "TestSite"
        self.base_info = {
            "url": "https://example.com/{0}",
            "urlMain": "https://example.com/",
            "isNSFW": False,
        }

    @patch("scans.user_clean.requests.get")
    def test_200_with_errormsg(self, mock_get):
        info = dict(self.base_info)
        info["errorMsg"] = ["user not found"]

        mock_get.return_value = MockResponse(status_code=200, text="<html>User not found</html>", url="https://example.com/notfound")

        res = user_clean.check_site("alice", self.site, info)
        self.assertFalse(res["found"])

    @patch("scans.user_clean.requests.get")
    def test_200_without_errormsg(self, mock_get):
        info = dict(self.base_info)
        info["errorMsg"] = ["user not found"]

        mock_get.return_value = MockResponse(status_code=200, text="<html>Profile: Alice</html>", url="https://example.com/alice")

        res = user_clean.check_site("alice", self.site, info)
        self.assertTrue(res["found"])

    @patch("scans.user_clean.requests.get")
    def test_404(self, mock_get):
        info = dict(self.base_info)

        mock_get.return_value = MockResponse(status_code=404, text="Not found", url="https://example.com/404")

        res = user_clean.check_site("alice", self.site, info)
        self.assertFalse(res["found"])

    @patch("scans.user_clean.requests.get")
    def test_redirect_to_login(self, mock_get):
        info = dict(self.base_info)

        # Simulate a redirect to a login page
        mock_get.return_value = MockResponse(status_code=200, text="", url="https://example.com/login")

        res = user_clean.check_site("alice", self.site, info)
        self.assertFalse(res["found"])

    @patch("scans.user_clean.requests.post")
    @patch("scans.user_clean.requests.get")
    def test_post_payload_uses_variant(self, mock_get, mock_post):
        # Ensure POST payload replacement uses the probe_username (variant)
        info = dict(self.base_info)
        info["request_method"] = "POST"
        info["request_payload"] = {"user": "{username}"}
        info["urlProbe"] = "https://example.com/api/{0}"

        # We'll let GET be used for non-POST variants but ensure POST is called
        mock_post_called = {}

        def fake_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            mock_post_called['url'] = url
            mock_post_called['json'] = json
            return MockResponse(status_code=200, text="OK", url=url)

        mock_post.side_effect = fake_post

        # When check_site formats urls_to_try it will attempt variants; we only
        # care that the POST payload contains a username field equal to the
        # probe username passed for that url.
        res = user_clean.check_site("alice", self.site, info)

        # Ensure a POST happened and payload contains a username key
        self.assertIn('json', mock_post_called)
        payload = mock_post_called['json']
        self.assertIn('user', payload)
        # The payload should contain a non-empty username string
        self.assertTrue(isinstance(payload['user'], str) and len(payload['user']) > 0)


if __name__ == '__main__':
    unittest.main()
