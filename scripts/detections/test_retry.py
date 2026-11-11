"""Exercise download retries with fake commands; no network or waiting."""

from pathlib import Path
import subprocess
import tempfile
import unittest


class RetryTests(unittest.TestCase):
    def run_retry(self, diagnostic, failures):
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(
                ["bash", "-c", '''
set -euo pipefail
source "$1"
count=0
sleep() { echo "BACKOFF:$1" >&2; }
download() {
    count=$((count + 1))
    echo "ATTEMPT:$count" >&2
    if (( count <= $3 )); then
        echo "$2" >&2
        return 7
    fi
    echo "download verified"
}
retry_network download "$@"
''', "test-retry", str(Path(__file__).with_name("retry.sh").resolve()), diagnostic, str(failures)],
                env={"PATH": "/usr/bin:/bin", "TMPDIR": temp},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(list(Path(temp).iterdir()), [], "temporary log must be removed")
            return result

    def test_transient_download_recovers(self):
        for diagnostic in ["response status code 429: toomanyrequests", "response status code 503", "net/http: TLS handshake timeout"]:
            with self.subTest(diagnostic=diagnostic):
                result = self.run_retry(diagnostic, 2)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((result.stdout + result.stderr).count("ATTEMPT:"), 3)
                self.assertIn("BACKOFF:2", result.stderr)
                self.assertIn("BACKOFF:4", result.stderr)

    def test_retries_are_bounded(self):
        result = self.run_retry("response status code 429", 99)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stderr.count("ATTEMPT:"), 4)
        self.assertEqual(result.stderr.count("BACKOFF:"), 3)

    def test_permanent_errors_fail_immediately(self):
        for diagnostic in ["signature verification failed", "checksum mismatch", "response status code 404", "response status code 401", "invalid rule"]:
            with self.subTest(diagnostic=diagnostic):
                result = self.run_retry(diagnostic, 99)
                self.assertEqual(result.returncode, 7)
                self.assertEqual(result.stderr.count("ATTEMPT:"), 1)
                self.assertNotIn("BACKOFF:", result.stderr)


if __name__ == "__main__":
    unittest.main()
