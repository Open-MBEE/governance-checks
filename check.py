#!/usr/bin/env python3
"""Measure Open-MBEE repositories against the repo-registry policies, with the verdicts decided in SysML v2.

Pipeline: model/governance.sysml (hand-written: one requirement def per registry check) is the source; model.py
derives model/repositories.sysml from repos.yaml (every registry check asserted of every repository); OpenSysML
evaluates each assertion's assumption to say which are in effect; sense.py observes the facts those read through
`gh api` (build/measurements.json); OpenSysML imports the facts into the model and evaluates every `satisfy`
assertion; this driver maps the verdicts to the table and compares them with baseline.json.

Statuses: pass, fail, exception (fails, but the registry records an accepted deviation), unreadable (a fact the
token could not read, so the assertion is unresolved), attested (repos.yaml gives evidence and it resolves),
unattested, n/a (the requirement's assumption
is false at the type/stage the entry is measured at). Compliance failures are reported, never raised; the exit code is
non-zero only for a regression against baseline.json or a construction error.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

import opensysml
import yaml

from common import GOOD, ORDER, GitHub, Registry
from model import MODEL, Applicability, Model, assertion, element, evidence_fact, generate, source
from sense import Repository

SUBJECT = re.compile(r"^Repositories::(?P<name>.+?): (?P<check>[a-z0-9-]+)$")
VERDICT = {"holds": "pass", "violated": "fail", "undecided": "unreadable"}


def connect(pin: str) -> opensysml.Connection:
    """A private sysml-grpc service of the pinned OpenSysML release. The installed client must be that release: it
    ships the release's digests, so the service it downloads is checked against them, and one named by
    $OPENSYSML_BINARY is refused unless it reports the pinned version."""
    if f"v{opensysml.__version__}" != pin:
        raise SystemExit(f"construction error: opensysml {opensysml.__version__} is installed but repos.yaml pins {pin}")
    try:
        return opensysml.connect(version=pin)
    except opensysml.errors.OpenSysMLError as e:
        raise SystemExit(f"construction error: no sysml-grpc {pin}: {e}")


def sense_all(gh: GitHub, registry: Registry, entries: list[dict], applicability: Applicability, model: Model):
    """Facts per element for -import, plus what each sensor said, per repository and check."""
    records, notes = [], {}
    for e in entries:
        repo = Repository(gh, registry, e, model)
        facts, said = {}, {}
        for policy, check, kind in applicability.in_effect(registry, e):
            if kind == "attested":
                s = said[check["id"]] = repo.sense_evidence(evidence_fact(check["id"]), check["id"])
                facts.update(s.facts)
                continue
            sensor = repo.sensor(check["id"])
            if sensor is None:
                raise SystemExit(f"construction error: no sensor for {policy['id']}/{check['id']}")
            s = sensor()
            for k, v in s.facts.items():
                if k in facts and facts[k] != v:
                    raise SystemExit(f"construction error: {e['name']}: sensors disagree on {k}: {facts[k]} vs {v}")
                facts[k] = v
            said[check["id"]] = s
        records.append({"element": element(e["name"]), **facts})
        notes[e["name"]] = {"said": said, "topic": repo.type_topic(), "id": repo.data.get("id")}
    return records, notes


def evaluate(conn: opensysml.Connection, model_dir: pathlib.Path, build: pathlib.Path, records: list[dict]) -> dict:
    """Verdict per (repository, check) from OpenSysML: holds / violated / undecided, with the condition or error."""
    build.mkdir(parents=True, exist_ok=True)
    measurements = json.dumps(records, indent=2) + "\n"
    (build / "measurements.json").write_text(measurements)
    text = source(model_dir)
    (build / "model.sysml").write_text(text)
    try:
        bound = conn.parse_sources([("model.sysml", text)], strict=True).import_data([("measurements.json", measurements)])
        (build / "bound.sysml").write_text(bound.content)
        answers = conn.parse_sources([("bound.sysml", bound.content)], strict=True).verify_satisfaction()
    except opensysml.errors.OpenSysMLError as e:
        raise SystemExit(f"construction error: OpenSysML could not evaluate the model: {e}")
    report, verdicts = [], {}
    for v in answers:
        record = {"subject": v.element, "status": v.status, "condition": v.condition, "error": v.error}
        report.append(record)
        m = SUBJECT.match(v.requirement_id)
        if m:
            verdicts[(m["name"], m["check"])] = record
    (build / "verdicts.json").write_text(json.dumps(report, indent=2) + "\n")
    return verdicts


def run_all(registry: Registry, entries: list[dict], verdicts: dict, notes: dict, applicability: Applicability):
    results = []
    for e in entries:
        said, topic, repo_id = notes[e["name"]]["said"], notes[e["name"]]["topic"], notes[e["name"]]["id"]
        effective = {(p["id"], c["id"]): kind for p, c, kind in applicability.in_effect(registry, e)}
        rows = []
        for p in (p for p in registry.policies if p.get("scope", "repository") == "repository"):
            deviation = registry.deviations.get((str(repo_id), p["id"]))
            for kind in ("automated", "attested"):
                for c in p["checks"].get(kind) or []:
                    if (p["id"], c["id"]) not in effective:
                        status, detail = "n/a", ""
                    else:
                        v = verdicts.get((e["name"], c["id"]))
                        if v is None:
                            raise SystemExit(f"construction error: no verdict for {assertion(e['name'], c['id'])}")
                        status = VERDICT.get(v["status"], "unreadable")
                        s = said[c["id"]]
                        detail = s.unreadable or s.detail
                        if kind == "attested":
                            status = "unreadable" if s.unreadable else "attested" if status == "pass" else "unattested"
                        else:
                            if s.unreadable:
                                status = "unreadable"  # a verdict over a fact nobody observed is not a verdict
                            elif status == "fail":
                                detail = f"{detail}; evaluated to false: {v['condition']}" if v.get("condition") else detail
                                if deviation:
                                    status, detail = "exception", f"{detail}; accepted exception: {deviation.get('reason')}"
                    rows.append({"policy": p["id"], "check": c["id"], "kind": kind, "status": status, "detail": detail})
        results.append({"name": e["name"], "type": e["type"], "stage": e["stage"],
                        "tier": applicability.tier(e), "checks": rows, "topic": topic})
    return results


def summarize(results):
    out = []
    for r in results:
        counts = {}
        for c in r["checks"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        head = ", ".join(f"{k} {counts[k]}" for k in ORDER if counts.get(k))
        out.append(f"### {r['name']} — {r['type']}/{r['stage']} ({r['tier']} tier): {head}\n")
        out.append("| policy | check | status | detail |\n|---|---|---|---|")
        for c in sorted(r["checks"], key=lambda c: (ORDER.index(c["status"]), c["policy"])):
            if c["status"] == "n/a":
                continue
            out.append(f"| {c['policy']} | {c['check']} | {c['status']} | {c['detail'].replace('|', '/')} |")
        na = sorted({c["policy"] for c in r["checks"] if c["status"] == "n/a"})
        if na:
            out.append(f"\nNot in effect at {r['type']}/{r['stage']}: {', '.join(na)}")
        if r.get("topic"):
            t = r["topic"]
            out.append(f"\nType topic `{t['expected']}`: {'declared' if t['declared'] else 'not declared'}")
        out.append("")
    return "\n".join(out)


def regressions(results, baseline):
    """A check that passed (or was attested) in the baseline and no longer does; a formerly passing check that
    became unreadable counts too, since the run has lost that coverage (usually a token losing a permission)."""
    out = []
    for r in results:
        base = {(c["check"]): c["status"] for c in (baseline.get(r["name"]) or {}).get("checks", [])}
        for c in r["checks"]:
            before = base.get(c["check"])
            if before in GOOD and c["status"] not in GOOD:
                out.append(f"{r['name']}: {c['policy']}/{c['check']} {before} -> {c['status']} ({c['detail']})")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="repos.yaml")
    ap.add_argument("--registry", required=True, help="path to a checkout of Open-MBEE/repo-registry at the pinned ref")
    ap.add_argument("--only", action="append", help="repository (owner/name) to measure; repeatable")
    ap.add_argument("--model", default="model", help="where repositories.sysml is written (governance.sysml is always model/governance.sysml)")
    ap.add_argument("--build", default="build", help="where measurements, the bound model and the verdicts go")
    ap.add_argument("--json", dest="json_out", help="write the results here")
    ap.add_argument("--summary", help="write the Markdown summary here (default: stdout)")
    ap.add_argument("--baseline", default="baseline.json", help="empty string: do not compare")
    ap.add_argument("--update-baseline", action="store_true")
    args = ap.parse_args(argv)

    config = yaml.safe_load(pathlib.Path(args.config).read_text())
    registry = Registry(pathlib.Path(args.registry))
    entries = config["repos"]
    if args.only:
        entries = [e for e in entries if e["name"] in args.only]

    generate(registry, config, pathlib.Path(args.model))
    with connect(config["opensysml"]) as conn:
        model = Model(conn, MODEL)
        facts = model.facts
        applicability = Applicability(conn, pathlib.Path(args.model), registry, entries)
        records, notes = sense_all(GitHub(), registry, entries, applicability, model)
        unknown = sorted({k for r in records for k in r if k != "element" and k not in facts})
        if unknown:
            raise SystemExit(f"construction error: sensors produced facts the model does not declare: {', '.join(unknown)}")
        verdicts = evaluate(conn, pathlib.Path(args.model), pathlib.Path(args.build), records)
    results = run_all(registry, entries, verdicts, notes, applicability)

    text = summarize(results)
    if args.summary:
        pathlib.Path(args.summary).write_text(text)
    else:
        print(text)
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(results, indent=2) + "\n")

    if not args.baseline:
        return 0
    base_path = pathlib.Path(args.baseline)
    snapshot = {r["name"]: {"checks": [{"check": c["check"], "status": c["status"]} for c in r["checks"]]} for r in results}
    if args.update_baseline:
        existing = json.loads(base_path.read_text()) if base_path.exists() else {}
        existing.update(snapshot)
        base_path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
        return 0
    if base_path.exists():
        regs = regressions(results, json.loads(base_path.read_text()))
        if regs:
            print("\nREGRESSIONS against baseline.json:\n- " + "\n- ".join(regs), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
