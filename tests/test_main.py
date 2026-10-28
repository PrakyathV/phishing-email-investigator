import tempfile
import unittest
from pathlib import Path

from email import policy
from email.parser import BytesParser

from main import defang_url, domain_of, extract_urls, inspect_email


class TestPhishingInvestigator(unittest.TestCase):

    def test_domain_extraction(self):
        self.assertEqual(
            domain_of('"DBS/POSB." <noreply@example.com>'),
            "example.com",
        )

    def test_url_defanging(self):
        self.assertEqual(
            defang_url("https://example.com/login"),
            "hxxps://example[.]com/login",
        )

    def test_extract_urls_from_email(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"Subject: Test\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Please review https://example.com/login\r\n"
        )
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertIn(
            "https://example.com/login",
            extract_urls(message),
        )

    def test_brand_mismatch_is_flagged(self):
        raw = (
            b'From: "DBS/POSB." <noreply@substackss.firebaseapp.com>\r\n'
            b"Subject: Account Notice\r\n"
            b"Authentication-Results: mx.example; "
            b"spf=pass; dkim=pass; dmarc=permerror\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Please review your account.\r\n"
        )

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "message.eml"
            path.write_bytes(raw)
            result = inspect_email(path)

        self.assertEqual(result["score"], 40)
        self.assertEqual(result["rating"], "MEDIUM")
        self.assertTrue(
            any("Display name mentions DBS" in item
                for item in result["findings"])
        )

    def test_missing_authentication_is_not_called_failure(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"Subject: Ordinary message\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "message.eml"
            path.write_bytes(raw)
            result = inspect_email(path)

        self.assertEqual(result["score"], 0)
        self.assertTrue(
            any("authentication status is unknown" in item
                for item in result["findings"])
        )


if __name__ == "__main__":
    unittest.main()
