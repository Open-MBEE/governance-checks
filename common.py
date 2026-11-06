"""Shared by sense.py, model.py and check.py: the GitHub reader, the pinned registry, and the applies_if evaluator."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fnmatch
import json
import os
import pathlib
import re
import subprocess
import sys

import yaml

SEMVER = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
SBOM_GLOBS = ("*.spdx.json", "*.spdx", "*.cdx.json", "*bom*.json")
ORDER = ["fail", "unreadable", "unattested", "unimplemented", "pass", "exception", "attested", "n/a"]
GOOD = {"pass", "exception", "attested", "n/a"}
# Transcribed from an attested check's statement when it binds a narrower kind than its policy
# (semantic-versioning: "For graduated tools: ..."). Drop an entry once the registry carries the rule.
CHECK_APPLIES = {"stable-release-policy": {"attr": "stage", "eq": "graduated"}}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


class GitHub:
    """Thin wrapper over `gh api`: returns (http_status, parsed_json_or_None)."""

    def __init__(self, env: dict | None = None):
        self.env = {**os.environ, **(env or {})}
        self.cache: dict[tuple, tuple[int, object]] = {}

    def api(self, path: str, *, paginate: bool = False, method: str | None = None):
        key = (path, paginate, method)
        if key in self.cache:
            return self.cache[key]
        cmd = ["gh", "api", path]
        if paginate:
            cmd += ["--paginate", "--slurp"]
        if method:
            cmd += ["--method", method]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        if proc.returncode == 0:
            body = proc.stdout.strip()
            data = json.loads(body) if body else None
            if paginate and isinstance(data, list) and data and isinstance(data[0], list):
                data = [item for page in data for item in page]
            status = 204 if body == "" else 200
            result = (status, data)
        else:
            m = re.search(r"\(HTTP (\d{3})\)", proc.stderr)
            status = int(m.group(1)) if m else 0
            data = None
            try:
                data = json.loads(proc.stdout) if proc.stdout.strip() else None
            except json.JSONDecodeError:
                pass
            result = (status, data if data is not None else {"message": proc.stderr.strip()})
        self.cache[key] = result
        return result

    def graphql(self, query: str, **variables):
        cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
        for k, v in variables.items():
            cmd += ["-f", f"{k}={v}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        if proc.returncode != 0:
            return (0, {"message": proc.stderr.strip()})
        return (200, json.loads(proc.stdout))


class Registry:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.policies = []
        for f in sorted((root / "data/policies").glob("*.yaml")):
            d = yaml.safe_load(f.read_text())
            if isinstance(d, dict) and d.get("id") and d.get("checks") is not None:
                self.policies.append(d)
        kinds = yaml.safe_load((root / "data/taxonomy/kinds.yaml").read_text())
        self.kinds = kinds["kinds"]
        self.type_topics = {v: k for k, v in kinds.get("type_topics", {}).items()}
        m = yaml.safe_load((root / "data/maintainers.yaml").read_text())
        self.maintainers = m.get("maintainers") or {}
        dev = yaml.safe_load((root / "data/deviations.yaml").read_text()) or {}
        self.deviations = {(str(d["repo_id"]), d["policy"]): d for d in dev.get("deviations") or []}
        lic = next(p for p in self.policies if p["id"] == "license-by-type")
        self.allowed_licenses = lic["allowed_licenses"]

    def tier(self, type_: str, stage: str) -> str:
        try:
            return self.kinds[type_][stage]["tier"]
        except KeyError as e:
            raise SystemExit(f"construction error: no kind {type_}/{stage} in kinds.yaml") from e


def applies(rule, attrs: dict) -> bool:
    if rule is None:
        return True
    if "all" in rule:
        return all(applies(r, attrs) for r in rule["all"])
    if "any" in rule:
        return any(applies(r, attrs) for r in rule["any"])
    if "not" in rule:
        return not applies(rule["not"], attrs)
    value = attrs.get(rule["attr"])
    if "eq" in rule:
        return value == rule["eq"]
    if "in" in rule:
        return value in rule["in"]
    raise SystemExit(f"construction error: unsupported applies_if clause {rule}")
