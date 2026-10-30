"""Pure offline tests for synthetic callback stream framing."""

from __future__ import annotations

import unittest

from preflight_desktop_callback import FAKE_CALLBACK, _read_fake_uri


class FakeSocket:
    def __init__(self, pieces: list[bytes]) -> None:
        self.pieces = iter(pieces)

    def recv(self, _size: int) -> bytes:
        return next(self.pieces, b"")


class RehearsalFramingTests(unittest.TestCase):
    def test_fragmented_uri(self) -> None:
        encoded = FAKE_CALLBACK.encode("utf-8")
        self.assertEqual(
            _read_fake_uri(FakeSocket([encoded[:7], encoded[7:38], encoded[38:] + b"\n"])),
            FAKE_CALLBACK,
        )

    def test_unterminated_uri_rejected(self) -> None:
        self.assertIsNone(_read_fake_uri(FakeSocket([FAKE_CALLBACK.encode()])))

    def test_two_callbacks_rejected(self) -> None:
        self.assertIsNone(_read_fake_uri(FakeSocket([b"callback-one\ncallback-two\n"])))

    def test_invalid_utf8_rejected(self) -> None:
        self.assertIsNone(_read_fake_uri(FakeSocket([b"\xff\n"])))

    def test_oversized_callback_rejected(self) -> None:
        self.assertIsNone(_read_fake_uri(FakeSocket([b"x" * 8192, b"\n"])))


if __name__ == "__main__":
    unittest.main()
