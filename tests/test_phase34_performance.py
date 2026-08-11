import unittest
from unittest.mock import patch, MagicMock
import requests
from api.scanner.transport import get_http_session, safe_request

class TestPhase34Performance(unittest.TestCase):
    @patch('api.scanner.transport.is_public_hostname', return_value=True)
    def test_http_session_caching(self, mock_is_public):
        session = get_http_session()
        self.assertTrue(hasattr(session, '_request_cache'))
        self.assertTrue(hasattr(session, '_dns_cache'))

        # Mock the session.request to track calls
        original_request = session.request
        call_count = 0

        def mocked_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = requests.Response()
            resp.status_code = 200
            resp.url = url
            resp._content = b'test content'
            return resp

        session.request = mocked_request

        # First request should miss cache
        resp1 = safe_request("GET", "http://example.com/test", session=session)
        self.assertIsNotNone(resp1)
        self.assertEqual(call_count, 1)

        # Second identical request should hit cache
        resp2 = safe_request("GET", "http://example.com/test", session=session)
        self.assertIsNotNone(resp2)
        self.assertEqual(call_count, 1)  # Call count remains 1
        self.assertIs(resp1, resp2)  # Should return exactly the same object

        # Different method shouldn't hit cache
        resp3 = safe_request("POST", "http://example.com/test", session=session)
        self.assertIsNotNone(resp3)
        self.assertEqual(call_count, 2)

        # stream=True shouldn't hit or write to cache
        resp4 = safe_request("GET", "http://example.com/stream", session=session, stream=True)
        self.assertIsNotNone(resp4)
        self.assertEqual(call_count, 3)

        # And calling it again should cause another request
        resp5 = safe_request("GET", "http://example.com/stream", session=session, stream=True)
        self.assertIsNotNone(resp5)
        self.assertEqual(call_count, 4)

    @patch('api.scanner.transport.is_public_hostname', return_value=True)
    def test_http_caching_exceptions(self, mock_is_public):
        session = get_http_session()

        call_count = 0
        def mocked_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            raise requests.exceptions.ReadTimeout("Timeout error")

        session.request = mocked_request

        with self.assertRaises(requests.exceptions.ReadTimeout):
            safe_request("GET", "http://example.com/timeout", session=session)
        self.assertEqual(call_count, 2)

        # Second request should immediately raise exception from cache, without hitting request
        with self.assertRaises(requests.exceptions.ReadTimeout):
            safe_request("GET", "http://example.com/timeout", session=session)
        self.assertEqual(call_count, 2)

if __name__ == '__main__':
    unittest.main()
