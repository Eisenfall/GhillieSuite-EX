import sys
import types
import unittest
from unittest.mock import patch

from ghilliesuite_ex.waf_engine import verify_bypass


class _RedirectResponse:
    status_code = 302
    headers = {"Location": "https://outside.example/"}
    text = ""


class _FakeClient:
    def __init__(self, **kwargs):
        self.request_kwargs = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def get(self, *_args, **kwargs):
        self.request_kwargs = kwargs
        return _RedirectResponse()


class TestWafRedirect(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_is_not_followed_or_confirmed_as_bypass(self):
        client = _FakeClient()
        with patch.dict(sys.modules, {"curl_cffi": None}), patch(
            "httpx.Client", return_value=client
        ), patch("asyncio.sleep", return_value=None):
            result = await verify_bypass(
                "https://example.com/api?item=1",
                "item",
                "probe",
                auth_headers={"Authorization": "Bearer secret"},
            )
        self.assertIsNotNone(client.request_kwargs, result.evidence)
        self.assertFalse(client.request_kwargs["follow_redirects"])
        self.assertEqual(client.request_kwargs["headers"]["Authorization"], "Bearer secret")
        self.assertFalse(result.success)

    async def test_curl_backend_does_not_follow_redirect(self):
        client = _FakeClient()
        fake_requests = types.SimpleNamespace(Session=lambda **_kwargs: client)
        with patch.dict(sys.modules, {"curl_cffi": types.SimpleNamespace(requests=fake_requests)}), patch(
            "asyncio.sleep", return_value=None
        ):
            result = await verify_bypass("https://example.com/api?item=1", "item", "probe")
        self.assertIsNotNone(client.request_kwargs, result.evidence)
        self.assertFalse(client.request_kwargs["allow_redirects"])
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
