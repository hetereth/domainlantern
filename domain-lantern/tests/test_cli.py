import unittest

from domain_lantern.cli import json_safe, normalize_domain


class NormalizeDomainTests(unittest.TestCase):
    def test_accepts_plain_domain(self) -> None:
        self.assertEqual(normalize_domain("Example.COM"), "example.com")

    def test_accepts_url(self) -> None:
        self.assertEqual(normalize_domain("https://www.example.com/path"), "www.example.com")

    def test_rejects_bad_domain(self) -> None:
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")


class JsonSafeTests(unittest.TestCase):
    def test_converts_sets_to_sorted_lists(self) -> None:
        self.assertEqual(json_safe({"b", "a"}), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
