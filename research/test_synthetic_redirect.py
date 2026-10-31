"""Purely synthetic localhost redirect/one-time callback tests."""

from __future__ import annotations

import http.client
import stat
import tempfile
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlencode

from synthetic_redirect import (
    CALLBACK,
    FAKE_CODE,
    LIFETIME_SECONDS,
    create_session,
    make_handler,
    receive_callback,
)


class SyntheticRedirectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name) / "demo"
        self.now = 1_800_000_000.0
        self.state = create_session(self.folder, now=self.now)
        self.url = CALLBACK + "?" + urlencode({"code": FAKE_CODE, "state": self.state})

    def tearDown(self):
        self.tmp.cleanup()

    def test_state_and_permissions(self):
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.folder / "pending.json").stat().st_mode), 0o600)
        self.assertGreaterEqual(len(self.state), 40)

    def test_exact_fake_callback_passes_once(self):
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + 1).startswith("PASS")
        )
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + 2).startswith("REJECT")
        )
        self.assertFalse((self.folder / "pending.json").exists())

    def test_wrong_state_does_not_consume_pending(self):
        invalid = CALLBACK + "?code=synthetic-code&state=wrong"
        self.assertTrue(
            receive_callback(self.folder, invalid, now=self.now + 1).startswith("REJECT")
        )
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + 2).startswith("PASS")
        )

    def test_real_looking_code_and_extra_params_rejected(self):
        for url in (
            CALLBACK + "?code=real-looking-code&state=" + self.state,
            self.url + "&other=1",
            CALLBACK + "?code=synthetic-code&code=synthetic-code&state=" + self.state,
            "haloapp://other?code=synthetic-code&state=" + self.state,
            self.url + "#fragment",
        ):
            with self.subTest(url_type=url.split("?")[0]):
                self.assertTrue(
                    receive_callback(self.folder, url, now=self.now + 1).startswith("REJECT")
                )
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + 2).startswith("PASS")
        )

    def test_expired_session_rejected(self):
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + LIFETIME_SECONDS + 1).startswith(
                "REJECT"
            )
        )

    def test_two_sessions_use_different_states(self):
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now + 1).startswith("PASS")
        )
        other = create_session(self.folder, now=self.now + 2)
        self.assertNotEqual(self.state, other)

    def test_http_302_redirect_is_local_and_does_not_contact_provider(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/")
            home = connection.getresponse()
            self.assertEqual(home.status, 200)
            self.assertIn(b"synthetic", home.read())
            connection.request("GET", "/redirect")
            response = connection.getresponse()
            self.assertEqual(response.status, 302)
            self.assertEqual(response.getheader("Location"), self.url)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            response.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_rejects_stale_or_backdated_callback(self):
        self.assertTrue(
            receive_callback(self.folder, self.url, now=self.now - 1).startswith("REJECT")
        )

    def test_result_does_not_write_callback_or_tokens(self):
        receive_callback(self.folder, self.url, now=self.now + 1)
        result = (self.folder / "status.txt").read_text(encoding="utf-8")
        self.assertNotIn(self.state, result)
        self.assertNotIn(FAKE_CODE, result)


if __name__ == "__main__":
    unittest.main()
