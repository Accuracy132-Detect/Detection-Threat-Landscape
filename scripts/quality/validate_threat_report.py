#!/usr/bin/env python3
"""Check the recorded threat-research contract, not semantic research quality.

Run for each newly authored package in addition to validate_repository.py.
Historical packages are deliberately not opted into this contract implicitly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


DIMENSIONS = (
    "mechanism", "timeline", "root_cause", "execution_flow", "impact",
    "evidence", "lab_plan",
)
SECTIONS = (
    "Scope and technical context",
    "Technical mechanism and root cause",
    "Timeline and execution flow",
    "Impact and scope",
    "Evidence and uncertainty",
    "Detection coverage and blind spots",
    "Laboratory plan",
    "Analyst assessment and sources",
)
PDF_PAGES = {
    "mechanism": {3}, "timeline": {2, 3}, "root_cause": {3},
    "execution_flow": {3}, "impact": {2, 8}, "evidence": {4, 8},
    "lab_plan": {7},
}
PLACEHOLDER = re.compile(r"(?im)^\s*(?:#+\s*)?(?:TODO|TBD|FIXME)\s*:|\{\{[^}]+\}\}")


def meaningful_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not PLACEHOLDER.search(value)


def integer_list(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, list) and bool(value)
        and all(type(item) is int and minimum <= item <= maximum for item in value)
        and len(value) == len(set(value))
    )


def read_object(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"{path.name}: cannot read JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path.name}: expected a JSON object")
        return {}
    return value


def validate_threat_report(package: Path) -> tuple[list[str], int]:
    errors: list[str] = []
    report = read_object(package / "report.json", errors)
    review = read_object(package / "threat-review.json", errors)
    evidence = read_object(package / "evidence.json", errors)
    references = read_object(package / "references.json", errors)
    try:
        manuscript = (package / "threat-report.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"threat-report.md: cannot read manuscript: {exc}")
        manuscript = ""

    if report.get("threat_research_contract") != "1.0":
        errors.append('report.json: threat_research_contract must be "1.0"')
    if review.get("schema_version") != "1.0":
        errors.append('threat-review.json: schema_version must be "1.0"')
    if review.get("decision") != "pass":
        errors.append("threat-review.json: editorial decision is not pass")
    if review.get("review_method") != "separate-editorial-pass":
        errors.append("threat-review.json: a separate editorial pass is required")
    if review.get("pdf_self_contained") is not True:
        errors.append("threat-review.json: PDF must be reviewed as self-contained")
    if review.get("blocking_issues") != []:
        errors.append("threat-review.json: blocking_issues must be an explicit empty list")
    if PLACEHOLDER.search(manuscript):
        errors.append("threat-report.md: unresolved template placeholder")

    headings = list(re.finditer(r"(?m)^## (\d+)\. (.+?)\s*$", manuscript))
    found_sections = set()
    for index, title in enumerate(SECTIONS, 1):
        matches = [
            (position, heading) for position, heading in enumerate(headings)
            if heading.group(1) == str(index) and heading.group(2) == title
        ]
        if len(matches) != 1:
            errors.append(f"threat-report.md: expected one section {index}. {title}")
            continue
        position, heading = matches[0]
        end = headings[position + 1].start() if position + 1 < len(headings) else len(manuscript)
        body = manuscript[heading.end():end].strip()
        if not meaningful_text(body):
            errors.append(f"threat-report.md: section {index} is empty or unfinished")
        else:
            found_sections.add(index)
    if [heading.group(1) for heading in headings] != [str(index) for index in range(1, 9)]:
        errors.append("threat-report.md: sections must appear once in order, 1-8")

    claims_list = evidence.get("claims", [])
    sources_list = references.get("sources", [])
    claims = {
        item["id"]: item for item in claims_list
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(claims_list, list) else {}
    sources = {
        item["id"]: item for item in sources_list
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(sources_list, list) else {}
    narrative_claims = set(re.findall(r"\bC\d{3}\b", manuscript))
    if not narrative_claims:
        errors.append("threat-report.md: no claim-level evidence references")
    for claim_id in sorted(narrative_claims - claims.keys()):
        errors.append(f"threat-report.md: unknown claim {claim_id}")
    for source_id in sorted(set(re.findall(r"\bS\d{3}\b", manuscript)) - sources.keys()):
        errors.append(f"threat-report.md: unknown source {source_id}")

    dimensions = review.get("dimensions", {})
    if not isinstance(dimensions, dict):
        dimensions = {}
    if set(dimensions) != set(DIMENSIONS):
        errors.append("threat-review.json: exactly seven analytical dimensions are required")
    total = 0
    used_claims = set(narrative_claims)
    for name in DIMENSIONS:
        dimension = dimensions.get(name)
        if not isinstance(dimension, dict):
            errors.append(f"{name}: missing dimension assessment")
            continue
        score = dimension.get("score")
        if type(score) is not int or not 0 <= score <= 4:
            errors.append(f"{name}: score must be an integer from 0 to 4")
        else:
            total += score
            if score < 3:
                errors.append(f"{name}: score below the 3/4 publication minimum")
        if not meaningful_text(dimension.get("rationale")):
            errors.append(f"{name}: specific score rationale is required")
        sections = dimension.get("report_sections")
        if not integer_list(sections, 1, 8):
            errors.append(f"{name}: report_sections must reference numbered manuscript sections")
        elif not set(sections) <= found_sections:
            errors.append(f"{name}: references an absent or empty manuscript section")
        pages = dimension.get("pdf_pages")
        if not integer_list(pages, 1, 8) or not set(pages) & PDF_PAGES[name]:
            errors.append(f"{name}: essential account must map to the appropriate canonical PDF page")
        claim_ids = dimension.get("claim_ids")
        if not isinstance(claim_ids, list) or not claim_ids or any(
            not isinstance(item, str) or item not in claims or item not in narrative_claims
            for item in claim_ids
        ):
            errors.append(f"{name}: supporting claims must exist in both evidence.json and the manuscript")
        else:
            used_claims.update(claim_ids)
    if total < 24:
        errors.append(f"threat-review.json: computed editorial score {total}/28 is below 24/28")

    needed_sources = set()
    for claim_id in used_claims & claims.keys():
        source_ids = claims[claim_id].get("source_ids", [])
        if not isinstance(source_ids, list) or any(not isinstance(item, str) for item in source_ids):
            errors.append(f"evidence.json: {claim_id} has invalid source_ids")
            continue
        needed_sources.update(source_ids)
    needed_sources.update(re.findall(r"\bS\d{3}\b", manuscript))
    checked_sources = set()
    checks = review.get("source_checks")
    if not isinstance(checks, list) or not checks:
        errors.append("threat-review.json: source_checks must record the opened sources")
        checks = []
    for check in checks:
        if not isinstance(check, dict):
            errors.append("source_checks: expected an object for each source")
            continue
        source_id = check.get("source_id")
        if not isinstance(source_id, str) or source_id not in sources:
            errors.append("source_checks: source_id must exist in references.json")
            continue
        if source_id in checked_sources:
            errors.append(f"source_checks: duplicate {source_id}")
        checked_sources.add(source_id)
        if check.get("opened") is not True or not meaningful_text(check.get("notes")):
            errors.append(f"source_checks: {source_id} needs an opened-source attestation and specific notes")
    for source_id in sorted(needed_sources - checked_sources):
        errors.append(f"source_checks: missing review of supporting source {source_id}")
    if not any(sources.get(item, {}).get("type") in {"primary", "original-research"} for item in needed_sources):
        errors.append("threat-report.md: supporting evidence needs a primary or original technical source")
    return errors, total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Newly authored package directories")
    args = parser.parse_args()
    failed = False
    for path in args.paths:
        errors, total = validate_threat_report(path.resolve())
        if errors:
            failed = True
            print(f"FAILED: {path}: {len(errors)} issue(s)", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
        else:
            print(f"PASS: {path}: recorded editorial contract {total}/28; source-based semantic review required")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
