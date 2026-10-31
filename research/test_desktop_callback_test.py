"""Unit tests for the local, synthetic-only handler. No Halo requests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from desktop_callback_test import is_synthetic_callback, main, record_status


class DesktopCallbackTests(unittest.TestCase):
    def test_valid_synthetic_callback(self):
        self.assertTrue(
            is_synthetic_callback("haloapp://callback?code=synthetic-code&state=halo-research-demo")
        )
        self.assertTrue(
            is_synthetic_callback("haloapp://callback?state=halo-research-demo&code=synthetic-code")
        )

    def test_refuses_real_or_altered_codes(self):
        for uri in (
            "haloapp://callback?code=real-auth-code&state=halo-research-demo",
            "haloapp://callback?code=synthetic-code&state=unknown",
            "haloapp://callback?code=synthetic-code",
            "haloapp://callback?code=synthetic-code&state=halo-research-demo&error=invalid",
            "haloapp://callback?code=synthetic-code&state=halo-research-demo&code=another",
            "https://callback?code=synthetic-code&state=halo-research-demo",
            "haloapp://another?code=synthetic-code&state=halo-research-demo",
            "haloapp://callback/path?code=synthetic-code&state=halo-research-demo",
            "haloapp://callback?code=synthetic-code&state=halo-research-demo#fragment",
            "haloapp://callback?code=synthetic-code&state=halo-research-demo%ZZ",
            "a" * 513,
            "",
            None,
        ):
            with self.subTest(case=repr(uri)[:40]):
                self.assertFalse(is_synthetic_callback(uri))

    def test_fixed_output_never_contains_callback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "status"
            record_status(True, path=path)
            self.assertEqual(path.read_text(), "PASS: synthetic callback received\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            record_status(False, path=path)
            self.assertEqual(path.read_text(), "IGNORED: non-synthetic callback\n")

    def test_cli_reports_only_success_or_failure(self):
        with patch("desktop_callback_test.record_status") as record:
            self.assertEqual(
                main(["haloapp://callback?code=synthetic-code&state=halo-research-demo"]), 0
            )
            record.assert_called_once_with(True)
        with patch("desktop_callback_test.record_status") as record:
            self.assertEqual(
                main(["haloapp://callback?code=real-secret&state=halo-research-demo"]), 1
            )
            record.assert_called_once_with(False)


if __name__ == "__main__":
    unittest.main()
