#!/usr/bin/env python3
"""Validate v2 packages and the canonical PDF contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_REPORT_KEYS = {
    "schema_version", "id", "title", "short_title", "subtitle", "published",
    "report_type", "classification", "maturity", "confidence", "operational_value",
    "primary_platform", "mitre", "decision", "key_findings", "source_facts",
    "analyst_assessment", "assumptions", "unknowns", "technical_background",
    "attack_chain", "telemetry", "query", "triage", "false_positives",
    "validation", "conclusion", "artwork",
}
ALLOWED_EVIDENCE = {
    "documented", "analyst-inference", "static-observed", "dynamic-observed",
    "exploit-reproduced", "detection-validated",
}
LAB_EVIDENCE = {"static-observed", "dynamic-observed", "exploit-reproduced", "detection-validated"}
SOURCE_TYPES = {"primary", "original-research", "official-schema", "attck", "secondary", "poc"}
REPORT_TYPES = {"campaign", "cve", "malware", "behavior", "cloud-identity", "ot"}
MATURITY = {"concept", "validation", "hunting", "production-candidate", "lab-validated", "production-validated"}


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_pdf(path: Path, errors: list[str]) -> None:
    try:
        reader = PdfReader(str(path))
    except Exception as exc:
        errors.append(f"{path}: cannot open PDF: {exc}")
        return
    if len(reader.pages) != 8:
        errors.append(f"{path}: expected 8 pages, found {len(reader.pages)}")
    for index, page in enumerate(reader.pages, 1):
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)
        if abs(width - 595.276) > 1 or abs(height - 841.89) > 1:
            errors.append(f"{path}: page {index} is not A4 ({width:.2f}x{height:.2f})")
        if len((page.extract_text() or "").strip()) < 25:
            errors.append(f"{path}: page {index} appears blank")
    keywords = str((reader.metadata or {}).get("/Keywords", ""))
    if "canonical-layout-v2.0" not in keywords:
        errors.append(f"{path}: missing canonical layout metadata")

    try:
        result = subprocess.run(["pdffonts", str(path)], check=True, text=True, capture_output=True)
        output_lines = result.stdout.splitlines()
        font_rows = [line for line in output_lines[2:] if line.strip()]
        if not font_rows:
            errors.append(f"{path}: no fonts detected")
        emb_column = output_lines[0].find("emb") if output_lines else -1
        for row in font_rows:
            embedded = row[emb_column:emb_column + 3].strip().lower() if emb_column >= 0 else ""
            if embedded != "yes":
                errors.append(f"{path}: contains a non-embedded font: {row.split()[0]}")
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"{path}: pdffonts check failed: {exc}")


def validate_package(package: Path) -> list[str]:
    errors: list[str] = []
    required_files = ["report.json", "evidence.json", "references.json", "validation.md", "references.txt", "threat-analysis.pdf"]
    for name in required_files:
        if not (package / name).is_file():
            errors.append(f"{package}: missing {name}")
    if errors:
        return errors

    try:
        report = read_json(package / "report.json")
        evidence = read_json(package / "evidence.json")
        references = read_json(package / "references.json")
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{package}: invalid JSON: {exc}"]

    missing = REQUIRED_REPORT_KEYS - set(report)
    if missing:
        errors.append(f"{package}/report.json: missing keys {sorted(missing)}")
    if report.get("schema_version") != "2.0":
        errors.append(f"{package}/report.json: schema_version must be 2.0")
    if report.get("classification") not in {"Detection concept", "Validation query", "Hunting query", "Production candidate"}:
        errors.append(f"{package}/report.json: invalid classification")
    if report.get("report_type") not in REPORT_TYPES:
        errors.append(f"{package}/report.json: invalid report_type")
    if report.get("maturity") not in MATURITY:
        errors.append(f"{package}/report.json: invalid maturity")
    if report.get("confidence") not in {"Low", "Medium", "High"}:
        errors.append(f"{package}/report.json: invalid confidence")
    if not 1 <= int(report.get("operational_value", 0)) <= 10:
        errors.append(f"{package}/report.json: operational_value must be 1-10")
    if len(report.get("key_findings", [])) < 3:
        errors.append(f"{package}/report.json: at least three key findings are required")
    for key, minimum, maximum in (
        ("source_facts", 1, 4), ("analyst_assessment", 1, 4), ("assumptions", 1, 4),
        ("unknowns", 1, 4), ("attack_chain", 3, 6), ("telemetry", 3, 9),
        ("triage", 4, 6), ("false_positives", 1, 5),
    ):
        length = len(report.get(key, []))
        if not minimum <= length <= maximum:
            errors.append(f"{package}/report.json: {key} must contain {minimum}-{maximum} items")

    query_file = package / report.get("query", {}).get("file", "")
    if not query_file.is_file():
        errors.append(f"{package}: query file not found: {query_file.name}")
    else:
        query_text = query_file.read_text(encoding="utf-8", errors="replace")
        if "MITRE ATT&CK" not in query_text[:2500]:
            errors.append(f"{query_file}: missing MITRE ATT&CK header")
        for technique in report.get("mitre", []):
            if technique != "NO-MITRE-MAPPING" and technique not in query_text[:2500]:
                errors.append(f"{query_file}: header does not include {technique}")
        if report.get("query", {}).get("status", "") not in query_text[:2500]:
            errors.append(f"{query_file}: query status differs from report.json")
        if "does not prove" not in query_text[:3000].lower():
            errors.append(f"{query_file}: missing explicit non-claim boundary")

        migration = report.get("migration")
        if migration:
            if migration.get("provenance_status") != "legacy-review-required":
                errors.append(f"{package}/report.json: invalid migration provenance_status")
            if migration.get("query_conditions_changed") is not False:
                errors.append(f"{package}/report.json: migrated query must declare query_conditions_changed=false")
            marker = "#" if query_file.suffix.lower() == ".spl" else "//"
            lines = query_text.splitlines()
            claim_line = next((idx for idx, line in enumerate(lines[:40]) if "Evidence claims:" in line), None)
            if claim_line is None:
                errors.append(f"{query_file}: cannot isolate managed v2 header")
            else:
                cut = claim_line + 1
                if cut < len(lines) and lines[cut].strip() == marker:
                    cut += 1
                original_body = "\n".join(lines[cut:]).lstrip("\n") + "\n"
                body_hash = hashlib.sha256(original_body.encode("utf-8")).hexdigest()
                if body_hash != migration.get("legacy_query_sha256"):
                    errors.append(f"{query_file}: query body differs from the recorded pre-migration SHA-256")

    sources = references.get("sources", [])
    claims = evidence.get("claims", [])
    source_ids = {source.get("id") for source in sources}
    claim_ids = {claim.get("id") for claim in claims}
    if len(source_ids) != len(sources) or None in source_ids:
        errors.append(f"{package}/references.json: source IDs must be present and unique")
    if len(claim_ids) != len(claims) or None in claim_ids:
        errors.append(f"{package}/evidence.json: claim IDs must be present and unique")

    for source in sources:
        for key in ("title", "organization", "published", "accessed", "type", "url", "supports"):
            if key not in source or source[key] in (None, "", []):
                errors.append(f"{package}/references.json: {source.get('id')} missing {key}")
        if not str(source.get("url", "")).startswith("https://"):
            errors.append(f"{package}/references.json: {source.get('id')} must use an https URL")
        if source.get("type") not in SOURCE_TYPES:
            errors.append(f"{package}/references.json: {source.get('id')} has invalid source type")
        for claim_id in source.get("supports", []):
            if claim_id not in claim_ids:
                errors.append(f"{package}/references.json: {source.get('id')} references unknown {claim_id}")

    validation_text = (package / "validation.md").read_text(encoding="utf-8", errors="replace")
    for claim in claims:
        evidence_type = claim.get("evidence_type")
        if evidence_type not in ALLOWED_EVIDENCE:
            errors.append(f"{package}/evidence.json: {claim.get('id')} has invalid evidence_type")
        if evidence_type == "documented" and not claim.get("source_ids"):
            errors.append(f"{package}/evidence.json: documented claim {claim.get('id')} has no source")
        if evidence_type == "analyst-inference" and not claim.get("confirm_or_refute"):
            errors.append(f"{package}/evidence.json: inference {claim.get('id')} lacks confirm_or_refute")
        if claim.get("confidence") not in {"Low", "Medium", "High"}:
            errors.append(f"{package}/evidence.json: {claim.get('id')} has invalid confidence")
        for source_id in claim.get("source_ids", []):
            if source_id not in source_ids:
                errors.append(f"{package}/evidence.json: {claim.get('id')} references unknown {source_id}")
        if evidence_type in LAB_EVIDENCE and "Status\n\n`validated`" not in validation_text:
            errors.append(f"{package}/evidence.json: {claim.get('id')} claims lab evidence without validated record")

    referenced_claims = set(re.findall(r"\bC\d{3}\b", json.dumps(report)))
    for claim_id in referenced_claims:
        if claim_id not in claim_ids:
            errors.append(f"{package}/report.json: references unknown claim {claim_id}")

    folder = package.parent.name
    for technique in report.get("mitre", []):
        if technique != "NO-MITRE-MAPPING" and technique not in folder:
            errors.append(f"{package}: folder name does not include {technique}")

    validate_pdf(package / "threat-analysis.pdf", errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path, help="Package directories; defaults to every v2 package")
    parser.add_argument("--strict-all", action="store_true", help="Require every legacy package to be migrated")
    args = parser.parse_args()

    packages = [path.resolve() for path in args.paths]
    if not packages:
        packages = sorted(path.parent for path in ROOT.glob("**/report.json") if "templates" not in path.parts)
    all_detection_dirs = sorted(path.parent for path in ROOT.glob("**/threat-analysis.pdf") if "tmp" not in path.parts)
    if args.strict_all:
        missing = [path for path in all_detection_dirs if not (path / "report.json").is_file()]
        if missing:
            print(f"ERROR: {len(missing)} packages are not v2-complete", file=sys.stderr)
            for path in missing[:20]:
                print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
            return 1

    errors: list[str] = []
    for package in packages:
        errors.extend(validate_package(package))
    if errors:
        print(f"FAILED: {len(errors)} issue(s) across {len(packages)} v2 package(s)", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"PASS: {len(packages)} v2 package(s) validated; {len(all_detection_dirs)} total PDF package(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
