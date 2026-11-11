#!/usr/bin/env python3
"""Compile real Sigma rules to SQLite and evaluate synthetic event fixtures.

No home-grown Sigma interpreter: pySigma handles conditions and modifiers, and
the SQLite backend's SQL is executed by SQLite. The same raw Kubernetes audit
fixtures are also prepared for replay through Falco's actual k8saudit plugin.
"""

import argparse
import json
from pathlib import Path
import sqlite3

from jsonschema import Draft202012Validator, FormatChecker
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
import yaml


def flatten(event, prefix=""):
    result = {}
    for key, value in event.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten(value, name))
        else:
            result[name] = value
    return result


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def validate_sigma(rule_dir, fixtures):
    schema = json.loads((rule_dir / "sigma-schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    paths = sorted((rule_dir / "sigma").glob("*.yaml"))
    if not paths or {p.stem for p in paths} != set(fixtures):
        raise AssertionError("fixture techniques must exactly match the exported catalog")
    total = 0
    seen_ids = set()
    for path in paths:
        text = path.read_text()
        document = yaml.safe_load(text)
        validator.validate(document)
        collection = SigmaCollection.from_yaml(text)
        if len(collection.rules) != 1:
            raise AssertionError(f"{path}: expected one Sigma rule")
        rule = collection.rules[0]
        if rule.id in seen_ids:
            raise AssertionError(f"{path}: duplicate rule ID {rule.id}")
        seen_ids.add(rule.id)
        if document["status"] != "experimental":
            raise AssertionError(f"{path}: synthetic fixtures do not justify promotion from experimental")
        queries = sqliteBackend().convert(collection)
        if len(queries) != 1:
            raise AssertionError(f"{path}: expected one single-event query")
        cases = fixtures[path.stem]
        if {case["match"] for case in cases} != {True, False}:
            raise AssertionError(f"{path}: positive and negative cases are required")
        if len({case["name"] for case in cases}) != len(cases):
            raise AssertionError(f"{path}: duplicate case names")
        # Give absent fields SQL NULL, preserving Sigma missing-field semantics.
        columns = {
            field.split("|")[0]
            for selector in document["detection"].values()
            if isinstance(selector, dict)
            for field in selector
        }
        events = [flatten(case["event"]) for case in cases]
        columns = sorted(columns | {key for event in events for key in event})
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE logs (" + ",".join(quote(c) for c in columns) + ")")
            insert = "INSERT INTO logs VALUES (" + ",".join("?" for _ in columns) + ")"
            for case, event in zip(cases, events):
                db.execute("DELETE FROM logs")
                db.execute(insert, [event.get(c) for c in columns])
                matched = bool(db.execute(queries[0]).fetchall())
                if matched != case["match"]:
                    raise AssertionError(f"{path.stem}/{case['name']}: matched={matched}, expected={case['match']}\n{queries[0]}")
                total += 1
        print(f"Sigma {path.stem}: schema-checked, parsed, converted, {len(cases)} fixtures passed")
    print(f"Sigma: {len(paths)} rules, {total} fixture assertions passed")


def prepare_audit(rule_dir, fixtures):
    expected = {}
    records = []
    for path in sorted((rule_dir / "falco").glob("*.yaml")):
        rule = yaml.safe_load(path.read_text())[0]
        if rule["source"] != "k8s_audit":
            continue
        for case in fixtures[path.stem]:
            audit_id = f"{path.stem}/{case['name']}"
            # The fixture's raw objectRef/user structure is intentionally retained.
            event = {
                "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
                "auditID": audit_id,
                "requestReceivedTimestamp": "2026-11-11T00:00:00.000000Z",
                "stageTimestamp": "2026-11-11T00:00:00.100000Z",
                "responseStatus": {"code": 200},
                **case["event"],
            }
            records.append(json.dumps(event))
            expected[audit_id] = [rule["rule"]] if case["match"] else []
    if not records:
        raise AssertionError("no Kubernetes audit fixtures prepared")
    (rule_dir / "audit-events.jsonl").write_text("\n".join(records) + "\n")
    (rule_dir / "audit-expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"Prepared {len(records)} Kubernetes audit events for real Falco replay")


def check_falco(rule_dir, alerts_path, validation_path):
    validation = json.loads(validation_path.read_text())
    results = validation["falco_load_results"]
    if len(results) != 2:
        raise AssertionError("both syscall and Kubernetes audit rules must be validated")
    for result in results:
        if not result["successful"] or not result.get("schema_valid"):
            raise AssertionError(f"Falco rule validation failed: {result}")
        if result.get("warnings") or result.get("schema_warnings") or result.get("errors"):
            raise AssertionError(f"Falco compiler/schema diagnostics: {result}")
    expected = json.loads((rule_dir / "audit-expected.json").read_text())
    observed = {audit_id: [] for audit_id in expected}
    for line in alerts_path.read_text().splitlines():
        alert = json.loads(line)
        audit_id = alert["output_fields"]["ka.auditid"]
        if audit_id not in observed:
            raise AssertionError(f"unexpected audit event alert: {audit_id}")
        observed[audit_id].append(alert["rule"])
    for audit_id, rules in expected.items():
        if sorted(observed[audit_id]) != sorted(rules):
            raise AssertionError(f"Falco {audit_id}: {observed[audit_id]}, expected {rules}")
    rule_count = len(list((rule_dir / "falco").glob("*.yaml")))
    print(f"Falco: {rule_count} rules compiled without warnings; {len(expected)} audit replay assertions passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, default=Path("pkg/detectgen/testdata/events.json"))
    parser.add_argument("--falco-alerts", type=Path)
    parser.add_argument("--falco-validation", type=Path)
    args = parser.parse_args()
    if args.falco_alerts or args.falco_validation:
        if not (args.falco_alerts and args.falco_validation):
            parser.error("supply both Falco result paths")
        check_falco(args.rules, args.falco_alerts, args.falco_validation)
    else:
        fixtures = json.loads(args.fixtures.read_text())
        validate_sigma(args.rules, fixtures)
        prepare_audit(args.rules, fixtures)


if __name__ == "__main__":
    main()
