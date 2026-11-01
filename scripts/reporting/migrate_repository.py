#!/usr/bin/env python3
"""Migrate legacy detection packages to the v2 contract without inventing validation.

The migration preserves every query condition and references.txt, records hashes of
the legacy PDF/query, adds an explicit query contract, creates conservative evidence
and source ledgers, and rebuilds the PDF with the canonical layout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from pypdf import PdfReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_report import build  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
TODAY = "2026-11-01"
QUERY_SUFFIXES = {".kql", ".spl", ".sql"}
ACRONYMS = {
    "ad": "AD", "adcs": "AD CS", "ai": "AI", "api": "API", "appdata": "AppData",
    "aws": "AWS", "c2": "C2", "cef": "CEF", "ci": "CI", "cli": "CLI",
    "cmd": "CMD", "cve": "CVE", "dc": "DC", "dll": "DLL", "dns": "DNS",
    "dtls": "DTLS", "fmc": "FMC", "gpo": "GPO", "http": "HTTP",
    "https": "HTTPS", "iis": "IIS", "ime": "IME", "ip": "IP", "ldap": "LDAP",
    "lsa": "LSA", "macos": "macOS", "mfa": "MFA", "microsoft": "Microsoft",
    "msbuild": "MSBuild", "msp": "MSP", "msp360": "MSP360", "npm": "npm",
    "ntlm": "NTLM", "ot": "OT", "pdf": "PDF", "php": "PHP", "pid1": "PID 1",
    "poc": "PoC", "rdp": "RDP", "rmm": "RMM", "rce": "RCE", "rat": "RAT",
    "rid": "RID", "sap": "SAP", "smb": "SMB", "ssh": "SSH", "ssp": "SSP",
    "tcp": "TCP", "udp": "UDP", "uac": "UAC", "url": "URL", "vbs": "VBS",
    "vscode": "VS Code", "webdav": "WebDAV", "weblogic": "WebLogic",
    "wmic": "WMIC", "xdr": "XDR", "xml": "XML",
}
MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11,
    "december": 12,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact(value: str) -> str:
    value = value.replace("ﬁ", "fi").replace("ﬂ", "fl").replace("–", "-").replace("—", "-")
    value = value.replace("T unnel", "Tunnel").replace("N central", "N-central")
    return re.sub(r"\s+", " ", value).strip(" \t\r\n-·")


def truncate(value: str, limit: int) -> str:
    value = compact(value)
    if len(value) <= limit:
        return value
    shortened = value[: limit - 3].rsplit(" ", 1)[0]
    return (shortened or value[: limit - 3]).rstrip(" ,;:-") + "..."


def humanize(slug: str) -> str:
    protected: dict[str, str] = {}

    def protect(pattern: str, formatter) -> None:
        nonlocal slug
        def replacement(match: re.Match) -> str:
            key = f"zzprotected{len(protected)}zz"
            protected[key] = formatter(match.group(0))
            return key
        slug = re.sub(pattern, replacement, slug, flags=re.I)

    protect(r"\bn-central\b", lambda value: "N-central")
    protect(r"\bcl-unk-\d+\b", lambda value: value.upper())
    protect(r"\b(?:cve|uat|storm|gtg|stac|ref)-\d+(?:-\d+)?\b", lambda value: value.upper())
    words = re.split(r"[-_]+", slug.strip("-_/"))
    rendered: list[str] = []
    for word in words:
        lower = word.lower()
        if lower in protected:
            rendered.append(protected[lower])
        elif lower in ACRONYMS:
            rendered.append(ACRONYMS[lower])
        elif re.fullmatch(r"t\d{4}(?:\.\d{3})?", lower):
            rendered.append(lower.upper())
        elif re.fullmatch(r"\d+", word):
            rendered.append(word)
        elif re.fullmatch(r"[a-z]+\d+[a-z0-9]*", lower):
            rendered.append(word.upper())
        elif lower in {"a", "an", "and", "for", "from", "in", "of", "on", "or", "the", "to", "with"} and rendered:
            rendered.append(lower)
        else:
            rendered.append(word.capitalize())
    return " ".join(rendered)


def date_and_slug(package: Path) -> tuple[str, str]:
    date_dir = next((part for part in package.parents if re.match(r"^\d{2}-\d{2}-\d{4} - ", part.name)), None)
    if date_dir is None:
        raise ValueError(f"cannot locate dated package root for {package}")
    raw_date, slug = date_dir.name.split(" - ", 1)
    published = datetime.strptime(raw_date, "%d-%m-%Y").date().isoformat()
    return published, slug


def techniques_from_folder(package: Path) -> list[str]:
    name = package.parent.name
    techniques = re.findall(r"T\d{4}(?:\.\d{3})?", name)
    return techniques or ["NO-MITRE-MAPPING"]


def detection_slug(package: Path) -> str:
    name = package.parent.name
    name = re.sub(r"^(?:T\d{4}(?:\.\d{3})?-)+", "", name)
    name = re.sub(r"^NO-MITRE-MAPPING-", "", name)
    return name


def classification_for(package: Path) -> tuple[str, str]:
    if package.name == "production-candidates":
        return "Production candidate", "production-candidate"
    if package.name == "validation":
        return "Validation query", "validation"
    return "Hunting query", "hunting"


def query_file(package: Path) -> Path:
    candidates = sorted(path for path in package.iterdir() if path.suffix.lower() in QUERY_SUFFIXES)
    if len(candidates) != 1:
        raise ValueError(f"expected one primary query in {package}, found {len(candidates)}")
    return candidates[0]


def comment_text(query: str) -> str:
    lines: list[str] = []
    for line in query.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            lines.append(stripped[2:].strip())
        elif stripped.startswith("#"):
            lines.append(stripped[1:].strip())
    return compact(" ".join(lines))


def header_value(query: str, labels: tuple[str, ...]) -> str | None:
    for label in labels:
        match = re.search(rf"(?im)^\s*(?://|#)\s*{re.escape(label)}\s*:\s*(.+)$", query)
        if match:
            return compact(match.group(1))
    return None


def sentence_with(text: str, needles: tuple[str, ...]) -> str | None:
    normalized = compact(text)
    for sentence in re.split(r"(?<=[.!?])\s+", normalized):
        if any(needle in sentence.lower() for needle in needles) and len(sentence) >= 24:
            return truncate(sentence, 360)
    return None


def section_after(text: str, heading: str, stops: tuple[str, ...]) -> str | None:
    lower = text.lower()
    start = lower.find(heading.lower())
    if start < 0:
        return None
    start += len(heading)
    end = len(text)
    for stop in stops:
        found = lower.find(stop.lower(), start)
        if found >= 0:
            end = min(end, found)
    value = compact(text[start:end])
    return truncate(value, 420) if len(value) >= 18 else None


def query_tables(query: str) -> list[str]:
    body = re.sub(r"(?m)^\s*(?://|#).*$", "", query)
    known = re.findall(r"(?m)^\s*(?:\(\s*)?([A-Z][A-Za-z0-9_]{3,})\s*\n\s*\|", body)
    table_shape = re.compile(
        r"^(?:Device(?:Process|File|Network|Registry|ImageLoad|Logon|Events|Tvm)[A-Za-z0-9_]*|"
        r"Email[A-Za-z0-9_]*|Identity[A-Za-z0-9_]*Events|SecurityEvent|WindowsEvent|CommonSecurityLog|"
        r"Syslog|AuditLogs|SigninLogs|CloudAppEvents|MicrosoftGraphActivityLogs|AzureActivity|OfficeActivity|"
        r"AlertInfo|AlertEvidence|BehaviorAnalytics|UrlClickEvents|NetScalerLogs|Event)$",
        re.I,
    )
    known = [item for item in known if table_shape.search(item)]
    for token in re.findall(r"\b[A-Z][A-Za-z0-9_]{4,}\b", body):
        if table_shape.search(token):
            known.append(token)
    excluded = {"AND", "CASE", "FROM", "SELECT", "WHERE", "UNION"}
    result: list[str] = []
    for item in known:
        if item.upper() not in excluded and item not in result:
            result.append(item)
    prerequisite = header_value(query, ("Required telemetry", "Telemetry prerequisite", "Required table"))
    if prerequisite:
        for item in re.findall(r"\b[A-Z][A-Za-z0-9_]{4,}\b", prerequisite):
            if table_shape.search(item) and item not in result:
                result.append(item)
    return result[:5]


def infer_platform(query: str, suffix: str, tables: list[str]) -> str:
    explicit = header_value(query, ("Primary platform", "Platform"))
    if explicit:
        explicit = re.sub(r"\s+Advanced Hunting.*$", "", explicit, flags=re.I)
        return truncate(explicit, 80)
    if suffix == ".spl":
        return "Splunk"
    joined = " ".join(tables)
    if any(name in joined for name in ("AuditLogs", "SigninLogs", "SecurityEvent", "CommonSecurityLog", "Syslog", "AzureActivity")):
        return "Microsoft Sentinel"
    return "Microsoft Defender XDR"


def extract_cover_subtitle(pdf: Path) -> str | None:
    page = PdfReader(str(pdf)).pages[0]
    items: list[tuple[float, float, float, str]] = []

    def visitor(text, cm, tm, font_dict, font_size):
        value = compact(text)
        if value:
            items.append((float(font_size), float(tm[5]), float(tm[4]), value))

    page.extract_text(visitor_text=visitor)
    lines = [item for item in items if 13.0 <= item[0] <= 18.5 and item[2] < 120 and 300 <= item[1] <= 520]
    lines.sort(key=lambda item: item[1])
    text = compact(" ".join(item[3] for item in lines))
    blocked = ("CONFIDENCE", "PRODUCTION CANDIDATE")
    if len(text) >= 20 and not any(token in text.upper() for token in blocked):
        return truncate(text, 180)
    return None


def pdf_text(pdf: Path) -> list[str]:
    return [compact(page.extract_text() or "") for page in PdfReader(str(pdf)).pages]


def infer_confidence(query: str, pages: list[str]) -> str:
    value = header_value(query, ("Confidence", "Detection confidence"))
    haystack = value or " ".join(pages[:2])
    match = re.search(r"\b(High|Medium|Low)\b", haystack, flags=re.I)
    return match.group(1).capitalize() if match else "Medium"


def infer_value(pages: list[str], maturity: str) -> int:
    haystack = " ".join(pages[:2])
    match = re.search(r"(\d(?:\.\d)?)\s*/\s*10", haystack)
    if match:
        return min(10, max(1, round(float(match.group(1)))))
    return {"validation": 8, "hunting": 9, "production-candidate": 9}[maturity]


def extract_query_meaning(query: str, pages: list[str], detection: str, tables: list[str]) -> tuple[str, str, str]:
    comments = comment_text(query)
    proves = sentence_with(comments, ("a result shows", "a match proves", "a result is", "a match means"))
    does_not = sentence_with(comments, ("does not prove", "does not establish", "does not identify", "cannot establish", "not proof"))
    page_five = pages[4] if len(pages) > 4 else ""
    if not proves:
        proves = section_after(page_five, "what a match means", ("what a match does not prove", "maturity", "detection threat landscape"))
    if not proves:
        proves = sentence_with(page_five, ("a result shows", "a match is", "a result is"))
    if not does_not:
        does_not = section_after(page_five, "what a match does not prove", ("maturity", "detection threat landscape"))
    if not does_not:
        does_not = sentence_with(page_five, ("does not prove", "does not establish", "does not identify", "cannot establish"))
    table_text = ", ".join(tables) if tables else "the named telemetry"
    logic = f"Evaluate {table_text} for {humanize(detection).lower()} using the existing source-derived conditions while preserving projected investigation context."
    if proves and any(token in proves.lower() for token in ("let ", "| where", "| project", "deviceevents |")):
        proves = None
    proves = proves or f"A result proves that the published query conditions matched in {table_text}; it is an investigative event, not a malicious verdict."
    if does_not and (len(does_not) > 320 or any(token in does_not.lower() for token in ("evidence claims", "expected false positives", "coverage limits"))):
        does_not = None
    does_not = does_not or "successful exploitation, malicious ownership, downstream impact, campaign attribution or complete compromise without corroborating evidence."
    proves = re.sub(r"^(?:a match proves\s*:\s*|interpretation\s*:\s*)+", "", proves, flags=re.I)
    does_not = re.sub(r"^(?:(?:what )?a match does not prove\s*:?\s*|(?:it|a result) does not prove\s+)+", "", does_not, flags=re.I)
    return truncate(logic, 480), truncate(proves, 420), truncate(does_not, 420)


def url_entries(reference_file: Path) -> list[dict]:
    text = reference_file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    raw_urls = re.findall(r"(?:hxxps?|https?)://[^\s<>]+", text, flags=re.I)
    seen: set[str] = set()
    entries: list[dict] = []
    for raw in raw_urls:
        url = raw.rstrip(".,);]")
        url = re.sub(r"^hxxp", "http", url, flags=re.I)
        url = url.replace("[.]", ".").replace("[:]", ":")
        if url.startswith("http://"):
            url = "https://" + url[len("http://"):]
        if not url.startswith("https://") or url in seen:
            continue
        seen.add(url)
        line_index = next((idx for idx, line in enumerate(lines) if raw[:24] in line), 0)
        context = [compact(line) for line in lines[max(0, line_index - 6):line_index] if compact(line)]
        title = None
        organization = None
        published = "undated"
        for candidate in reversed(context):
            if candidate.lower().startswith("organization:"):
                organization = compact(candidate.split(":", 1)[1])
            if re.search(r"(?:publication|published|updated|date|accessed)\s*:", candidate, re.I):
                continue
            if candidate.isupper() and len(candidate) < 70:
                continue
            if not title and len(candidate) >= 5:
                title = candidate.strip('"')
        nearby = " ".join(context)
        iso = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", nearby)
        human = re.search(r"\b(\d{1,2})\s+([A-Za-z]+)\s+(20\d{2})\b", nearby)
        if iso:
            published = iso.group(1)
        elif human and human.group(2).lower() in MONTHS:
            published = f"{human.group(3)}-{MONTHS[human.group(2).lower()]:02d}-{int(human.group(1)):02d}"
        host = (urlparse(url).hostname or "source").removeprefix("www.")
        domain_org = {
            "attack.mitre.org": "MITRE ATT&CK", "learn.microsoft.com": "Microsoft Learn",
            "microsoft.com": "Microsoft", "github.com": "GitHub", "huntress.com": "Huntress",
            "unit42.paloaltonetworks.com": "Unit 42", "cloud.google.com": "Google Cloud",
        }
        if not organization:
            organization = next((org for domain, org in domain_org.items() if host == domain or host.endswith("." + domain)), host)
        if not title:
            title = f"Technical reference from {organization}"
        lower_url = url.lower()
        if "attack.mitre.org" in lower_url:
            source_type = "attck"
        elif "learn.microsoft.com" in lower_url or "/docs/" in lower_url or "documentation" in lower_url:
            source_type = "official-schema"
        elif "github.com" in lower_url and any(token in nearby.lower() for token in ("poc", "proof-of-concept", "exploit")):
            source_type = "poc"
        elif any(token in lower_url for token in ("/blog/", "research", "threat")):
            source_type = "original-research"
        else:
            source_type = "primary"
        entries.append({
            "id": f"S{len(entries) + 1:03d}",
            "title": truncate(title, 240),
            "organization": truncate(organization, 100),
            "author": None,
            "published": published,
            "event_date": None,
            "accessed": TODAY,
            "type": source_type,
            "url": url,
            "supports": ["C001", "C002", "C003"],
        })
    return entries


def infer_artwork(title: str, techniques: list[str]) -> str:
    lower = f"{title} {' '.join(techniques)}".lower()
    categories = [
        (("email", "phish", "qr"), "phishing-mail"),
        (("identity", "account", "role", "domain admin", "mfa", "passkey", "credential", "certificate", "ad cs"), "identity-access"),
        (("registry", "run key", "service", "scheduled", "launchagent", "systemd", "persistence"), "persistence"),
        (("azure", "cloud", "sharepoint", "m365", "graph"), "cloud-control"),
        (("dll", "sideload", "image load", "library"), "library-load"),
        (("powershell", "cmd", "bash", "shell", "wscript", "node", "python"), "command-chain"),
        (("proxy", "c2", "tunnel", "ssh", "network", "udp", "rdp"), "network-path"),
        (("cve", "exploit", "weblogic", "netscaler", "zimbra"), "exploit-boundary"),
        (("supply", "npm", "crate", "extension", "terraform"), "supply-chain"),
        (("ransom", "encrypt", "shadowcopy", "impact"), "impact"),
        (("exfil", "upload", "backblaze", "b2", "collection"), "data-transfer"),
    ]
    return next((kind for needles, kind in categories if any(needle in lower for needle in needles)), "endpoint-process")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepend_query_header(path: Path, report: dict, tables: list[str]) -> None:
    original = path.read_text(encoding="utf-8", errors="replace")
    marker = "#" if path.suffix.lower() == ".spl" else "//"
    original = strip_managed_header(original, marker)
    mitre = ", ".join(report["mitre"])
    table_text = ", ".join(tables) if tables else "See query body and local connector contract"
    lines = [
        f"{marker} Rule: [{mitre.replace(', ', '][')}] {report['title']}",
        f"{marker} MITRE ATT&CK: {mitre}",
        f"{marker} Classification: {report['classification']}",
        f"{marker} Status: {report['query']['status']}",
        f"{marker} Primary platform: {report['primary_platform']}",
        f"{marker} Required telemetry: {table_text}",
        f"{marker} Purpose: {report['subtitle']}",
        f"{marker} Logic: {report['query']['logic']}",
        f"{marker} A match proves: {report['query']['match_proves']}",
        f"{marker} A match does not prove: {report['query']['match_does_not_prove']}",
        f"{marker} Expected false positives: authorized administration, approved software, testing, or benign artifact collisions.",
        f"{marker} Coverage limits: local schema, field population, retention, collection scope, and attacker variation require validation.",
        f"{marker} Evidence claims: C001, C002, C003",
        marker,
    ]
    path.write_text("\n".join(lines) + "\n" + original, encoding="utf-8")


def strip_managed_header(text: str, marker: str) -> str:
    if "Evidence claims:" not in text[:3000] or "MITRE ATT&CK:" not in text[:3000]:
        return text
    lines = text.splitlines()
    claim_line = next((idx for idx, line in enumerate(lines[:40]) if "Evidence claims:" in line), None)
    if claim_line is None:
        return text
    cut = claim_line + 1
    if cut < len(lines) and lines[cut].strip() == marker:
        cut += 1
    return "\n".join(lines[cut:]).lstrip("\n") + "\n"


def validation_record(report: dict) -> str:
    return f"""# Validation record

## Status

`planned`

## Migration note

This package was migrated from the legacy eight-page dossier into schema 2.0. The query conditions were preserved. Claim-level provenance must be reviewed against `references.txt` before any evidence type is promoted beyond `analyst-inference`.

## Hypothesis

{report['query']['match_proves']}

## Environment and authorization

- Execute only in an authorized tenant, endpoint fleet, appliance lab, or log workspace.
- Preserve the raw matching event and connector/parser version.
- Do not contact source-published malicious infrastructure during testing.

## Positive controls

1. Generate a controlled equivalent of the principal observable without using live malicious infrastructure.
2. Confirm every required projected field is populated and retains its documented semantics.
3. Retain the raw event, query version, timestamp, test owner and expected result.

## Negative controls

- Approved administrative or software activity that overlaps the query conditions.
- A near-match that omits the most specific condition.
- An event outside the intended asset, identity or telemetry scope.

## Results

Not performed during repository migration. The package remains `{report['query']['status']}`.

## Promotion decision

Do not promote until controlled positives, representative negatives, benign prevalence, field semantics and operational ownership satisfy the promotion gate in `report.json`.
"""


def migrate(package: Path, force: bool = False, no_build: bool = False) -> str:
    report_path = package / "report.json"
    if report_path.exists() and not force:
        return "skipped"
    pdf = package / "threat-analysis.pdf"
    refs_file = package / "references.txt"
    query_path = query_file(package)
    existing_report = {}
    if report_path.exists():
        try:
            existing_report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing_report = {}
    prior_migration = existing_report.get("migration", {})
    old_pdf_hash = prior_migration.get("legacy_pdf_sha256") or sha256(pdf)
    old_query_hash = prior_migration.get("legacy_query_sha256") or sha256(query_path)
    pages = pdf_text(pdf)
    query_raw = query_path.read_text(encoding="utf-8", errors="replace")
    query = strip_managed_header(query_raw, "#" if query_path.suffix.lower() == ".spl" else "//")
    published, threat_slug = date_and_slug(package)
    detection = detection_slug(package)
    techniques = techniques_from_folder(package)
    classification, maturity = classification_for(package)
    threat_name = humanize(threat_slug)
    detection_name = humanize(detection)
    title = truncate(f"{threat_name} - {detection_name}", 140)
    cover_subtitle = existing_report.get("subtitle") if prior_migration else extract_cover_subtitle(pdf)
    subtitle = cover_subtitle or f"{classification} for {detection_name.lower()}, with evidence boundaries and target-environment validation requirements"
    tables = query_tables(query)
    platform = infer_platform(query, query_path.suffix.lower(), tables)
    logic, proves, does_not = extract_query_meaning(query, pages, detection, tables)
    confidence = infer_confidence(query, pages)
    value = infer_value(pages, maturity)
    sources = url_entries(refs_file)
    source_ids = [source["id"] for source in sources]
    status = header_value(query, ("Status",)) or "Untested implementation sketch"
    status = "Untested implementation sketch" if "untested" in status.lower() else status
    source_count = len(sources)
    source_summary = (
        f"The retained legacy source ledger contains {source_count} normalized reference{'s' if source_count != 1 else ''}; "
        "claim-to-source mapping remains review-required after mechanical migration. [C001]"
    )
    telemetry_items = [
        {"field": table, "status": "Required", "purpose": "Primary event source selected by the unchanged query logic."}
        for table in tables[:4]
    ]
    if not telemetry_items:
        telemetry_items.append({"field": "Primary event source", "status": "Required", "purpose": "Resolve the query source against the local connector and parser."})
    telemetry_items.extend([
        {"field": "Event time and entity identifiers", "status": "Required", "purpose": "Chronology, deduplication, scoping and investigation pivots."},
        {"field": "Raw projected context", "status": "Required", "purpose": "Preserve the fields emitted by the query before normalization or tuning."},
        {"field": "Asset, identity and change inventory", "status": "Enrichment", "purpose": "Separate authorized activity and define operational ownership."},
    ])
    report = {
        "schema_version": "2.0",
        "id": f"{published}-{threat_slug}-{detection}"[:180],
        "title": title,
        "short_title": truncate(threat_name, 60),
        "subtitle": truncate(subtitle, 180),
        "published": published,
        "report_type": "cve" if "cve" in title.lower() else ("cloud-identity" if any(x in title.lower() for x in ("entra", "azure", "cloud", "m365", "identity", "passkey")) else "campaign"),
        "classification": classification,
        "maturity": maturity,
        "confidence": confidence,
        "operational_value": value,
        "primary_platform": platform,
        "mitre": techniques,
        "decision": truncate(f"Retain this package as a {classification.lower()} and migrate it to the canonical visual and evidence contract without changing query conditions. Treat every result as an investigative lead until local schema, field population, benign overlap and the legacy claim provenance are reviewed.", 700),
        "key_findings": [
            truncate(f"The original query conditions and source ledger were preserved during layout migration; legacy PDF SHA-256 {old_pdf_hash[:16]}... is recorded for traceability. [C001]", 360),
            truncate(f"The principal observable is {logic} [C002]", 360),
            truncate(f"The evidence boundary remains explicit: a match does not prove {does_not} [C003]", 360),
        ],
        "source_facts": [source_summary],
        "analyst_assessment": [
            truncate(f"The existing logic is retained at {maturity} maturity; repository migration is not execution evidence and does not increase validation status. [C002]", 500),
            truncate(f"The folder and query header map the package to {' / '.join(techniques)}; operational relevance still depends on local telemetry and ownership context. [C003]", 500),
        ],
        "assumptions": [
            "The named telemetry is collected across the intended asset or identity scope with adequate retention. [C002]",
            "Projected fields preserve their expected semantics in the target connector and parser. [C002]",
            "Approved activity, owners and change records are available to analysts during disposition. [C003]",
        ],
        "unknowns": [
            f"A matching result does not prove {does_not}",
            "Target-environment field population, benign prevalence, parser behavior and operational ownership have not been validated by this repository migration.",
        ],
        "technical_background": truncate(f"The retained dossier links {threat_name} to the detection opportunity described as {detection_name.lower()}. The v2 migration preserves the query exactly and exposes its match boundary, but does not reinterpret legacy source claims as laboratory evidence. {logic} [C001][C002]", 1200),
        "attack_chain": [
            {"phase": "Threat context", "behavior": truncate(subtitle, 300), "observable": "Context retained from the legacy dossier and source ledger.", "claim_ids": ["C001"]},
            {"phase": "Observable candidate", "behavior": logic, "observable": f"Events from {', '.join(tables) if tables else 'the primary query source'} and projected fields.", "claim_ids": ["C002"]},
            {"phase": "Contextual enrichment", "behavior": "Resolve asset, identity, process, ownership and change context before disposition.", "observable": "Raw event, surrounding timeline, inventory and authorized-change evidence.", "claim_ids": ["C002", "C003"]},
            {"phase": "Decision gate", "behavior": "Escalate only when corroborating evidence closes the documented non-claim boundary.", "observable": "Controlled validation, explainable negatives and analyst-readable evidence.", "claim_ids": ["C003"]},
        ],
        "telemetry": telemetry_items[:8],
        "query": {
            "file": query_path.name,
            "language": "SPL" if query_path.suffix.lower() == ".spl" else "KQL",
            "status": status,
            "logic": logic,
            "match_proves": proves,
            "match_does_not_prove": does_not,
        },
        "triage": [
            "Preserve the complete raw matching event, query version, timestamp, connector or sensor version and stable entity identifiers.",
            f"Confirm the event originated from the intended {platform} data source and verify the semantics of every condition used by the query.",
            "Resolve asset, identity, process, software and destination ownership against authoritative inventories and approved change records.",
            "Build the surrounding endpoint, identity, network or appliance timeline and seek an independent evidence layer before escalation.",
            "Classify benign overlap explicitly; tune only with durable ownership or provenance controls, never by suppressing the core behavior globally.",
            "Escalate only when corroborating evidence establishes malicious or unauthorized activity beyond the documented match boundary.",
        ],
        "false_positives": [
            {"source": "Authorized administration or software", "control": "Require owner, purpose, approved change and expected execution or configuration provenance."},
            {"source": "Benign artifact or command collision", "control": "Require the full condition set plus an independent evidence layer or stable provenance."},
            {"source": "Parser, inventory or retention ambiguity", "control": "Reproduce a controlled event and reconcile raw fields, collection scope and authoritative inventory."},
        ],
        "validation": {
            "steps": [
                "Generate an authorized controlled equivalent of the primary observable without using live malicious infrastructure.",
                "Verify each query condition and projected field against retained raw telemetry.",
                "Run representative approved and near-match negative controls.",
                "Measure historical prevalence and classify every returned owner or workflow.",
                "Record parser, connector, retention and asset-scope dependencies with the test evidence.",
            ],
            "success": "The controlled positive produces a complete, explainable row and representative negatives are separable through durable context.",
            "rejection": "Reject promotion when field semantics, collection scope, benign ownership or the core behavior cannot be established reproducibly.",
            "visibility_gaps": ["Unvalidated local schema", "Missing projected fields", "Incomplete retention or asset scope", "Mutable attacker behavior", "Legacy claim provenance review pending"],
            "promotion_gate": "Require claim-level source review, a retained controlled positive, representative negatives, measured prevalence and an accountable operational owner.",
        },
        "conclusion": truncate(f"This package now uses the canonical v2 layout and evidence contract while preserving the original {query_path.name} conditions. It remains a {classification.lower()} at {confidence.lower()} confidence. The visual migration is complete; claim-level provenance and target-environment execution remain explicit promotion gates.", 900),
        "artwork": {"kind": infer_artwork(title, techniques), "label": f"{techniques[0]} · {maturity} · observability"},
        "migration": {
            "provenance_status": "legacy-review-required",
            "migrated_on": TODAY,
            "legacy_pdf_sha256": old_pdf_hash,
            "legacy_query_sha256": old_query_hash,
            "query_conditions_changed": False,
        },
    }
    claims = {
        "schema_version": "2.0",
        "claims": [
            {"id": "C001", "statement": "The package retains a legacy source ledger and the pre-migration PDF hash for review; individual narrative claims have not yet been remapped mechanically.", "evidence_type": "analyst-inference", "source_ids": source_ids, "confidence": "Medium", "confirm_or_refute": "Review each material legacy statement against the normalized source set and split it into atomic documented or inferred claims."},
            {"id": "C002", "statement": f"The unchanged query selects {logic}", "evidence_type": "analyst-inference", "source_ids": source_ids, "confidence": confidence, "confirm_or_refute": "Execute authorized positive and negative controls, verify every field and condition, and retain the raw results."},
            {"id": "C003", "statement": f"A matching result does not prove {does_not}", "evidence_type": "analyst-inference", "source_ids": source_ids, "confidence": "High", "confirm_or_refute": "Require an independent evidence layer before making any excluded conclusion."},
        ],
    }
    references = {"schema_version": "2.0", "sources": sources}
    write_json(report_path, report)
    write_json(package / "evidence.json", claims)
    write_json(package / "references.json", references)
    (package / "validation.md").write_text(validation_record(report), encoding="utf-8")
    prepend_query_header(query_path, report, tables)
    if not no_build:
        build(package)
    return "migrated"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path, help="Package directories; defaults to all PDF packages")
    parser.add_argument("--force", action="store_true", help="Replace existing v2 JSON and PDFs")
    parser.add_argument("--no-build", action="store_true", help="Write v2 source files without rebuilding PDFs")
    args = parser.parse_args()
    packages = [path.resolve() for path in args.paths]
    if not packages:
        packages = sorted(path.parent for path in ROOT.glob("**/threat-analysis.pdf") if "tmp" not in path.parts)
    counts = {"migrated": 0, "skipped": 0}
    for package in packages:
        result = migrate(package, force=args.force, no_build=args.no_build)
        counts[result] += 1
        print(f"{result:8} {package.relative_to(ROOT)}")
    print(f"migrated={counts['migrated']} skipped={counts['skipped']} total={len(packages)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
