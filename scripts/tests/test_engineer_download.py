import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


spec = importlib.util.spec_from_file_location(
    "engineer_bridge", Path(__file__).resolve().parents[1] / "build_engineer_bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class DownloadTests(unittest.TestCase):
    def test_throttle_retries_official_mirror_and_validates_before_caching(self):
        payload = b"pinned archive"
        url = "https://repo.maven.apache.org/maven2/example.aar"
        error = urllib.error.HTTPError(url, 429, "rate limited", {"Retry-After": "0"}, None)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(bridge, "CACHE", Path(directory)), \
                patch.object(bridge.time, "sleep") as sleep, \
                patch.object(bridge.urllib.request, "urlopen", side_effect=[error, io.BytesIO(payload)]) as fetch:
            digest = hashlib.sha256(payload).hexdigest()
            self.assertEqual(bridge.download("archive", url, digest), payload)
            self.assertEqual(fetch.call_args_list[1].args[0].full_url,
                             "https://repo1.maven.org/maven2/example.aar")
            sleep.assert_called_once_with(0)
            self.assertEqual(bridge.download("archive", url, digest), payload)
            self.assertEqual(fetch.call_count, 2)

    def test_bad_hash_does_not_create_a_cache_entry(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(bridge, "CACHE", Path(directory)), \
                patch.object(bridge.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")) as fetch:
            with self.assertRaises(ValueError):
                bridge.download("archive", "https://example.test/a", hashlib.sha256(b"right").hexdigest())
            self.assertFalse((Path(directory) / "archive").exists())
            self.assertEqual(fetch.call_count, 1)

    def test_permanent_errors_and_long_cooldowns_do_not_retry(self):
        for code, headers in [(404, {}), (429, {"Retry-After": "120"})]:
            error = urllib.error.HTTPError("https://example.test/a", code, "error", headers, None)
            with patch.object(bridge.urllib.request, "urlopen", side_effect=error) as fetch, \
                    patch.object(bridge.time, "sleep") as sleep:
                with self.assertRaises(urllib.error.HTTPError):
                    bridge.fetch_dependency("https://example.test/a")
                self.assertEqual(fetch.call_count, 1)
                sleep.assert_not_called()

    def test_repeated_transient_errors_stop_after_four_attempts(self):
        errors = [urllib.error.HTTPError("https://example.test/a", 503, "busy", {}, None)
                  for _ in range(4)]
        with patch.object(bridge.urllib.request, "urlopen", side_effect=errors) as fetch, \
                patch.object(bridge.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                bridge.fetch_dependency("https://example.test/a")
            self.assertEqual(fetch.call_count, 4)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10, 20])


if __name__ == "__main__":
    unittest.main()
