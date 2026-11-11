"""Regression tests for the validation harness itself (no Docker required)."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validate import check_falco, flatten


class ValidatorTests(unittest.TestCase):
    def test_flatten_preserves_audit_paths(self):
        self.assertEqual(
            flatten({"objectRef": {"resource": "serviceaccounts", "subresource": "token"}, "user": {"username": "tester"}}),
            {"objectRef.resource": "serviceaccounts", "objectRef.subresource": "token", "user.username": "tester"},
        )

    def test_falco_checker_fails_on_diagnostics_and_bad_alerts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "falco").mkdir()
            (root / "falco/example.yaml").write_text("example")
            (root / "audit-expected.json").write_text(json.dumps({"positive": ["example"], "negative": []}))
            validation = root / "validation.json"
            alerts = root / "alerts.jsonl"
            clean = {"successful": True, "schema_valid": True, "warnings": [], "schema_warnings": [], "errors": []}
            validation.write_text(json.dumps({"falco_load_results": [clean, clean]}))
            good_alert = {"rule": "example", "output_fields": {"ka.auditid": "positive"}}
            alerts.write_text(json.dumps(good_alert) + "\n")
            with patch("builtins.print"):
                check_falco(root, alerts, validation)
            for bad_alerts in [[], [good_alert, good_alert],
                               [{"rule": "wrong", "output_fields": {"ka.auditid": "positive"}}],
                               [good_alert, {"rule": "example", "output_fields": {"ka.auditid": "negative"}}],
                               [{"rule": "example", "output_fields": {"ka.auditid": "unknown"}}]]:
                alerts.write_text("\n".join(json.dumps(alert) for alert in bad_alerts))
                with self.assertRaises(AssertionError):
                    check_falco(root, alerts, validation)
            alerts.write_text(json.dumps(good_alert) + "\n")
            for diagnostic in ["warnings", "schema_warnings", "errors"]:
                bad = {**clean, diagnostic: ["test diagnostic"]}
                validation.write_text(json.dumps({"falco_load_results": [clean, bad]}))
                with self.assertRaises(AssertionError):
                    check_falco(root, alerts, validation)


if __name__ == "__main__":
    unittest.main()
